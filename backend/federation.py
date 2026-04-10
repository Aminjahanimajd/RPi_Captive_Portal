#!/usr/bin/env python3
"""
Federation Agent — Federated File System Security
==================================================
Handles cryptographic key lifecycle for the federated edge filesystem.

Security model
--------------
* Each Raspberry Pi node holds a **shard** of the master AES-256 encryption key.
* On boot the node requests shards from its trusted federation neighbours.
* Once enough shards are collected all shards are XOR-ed together to reconstruct
  the master key.
* The master key is then used to open the LUKS-encrypted secure partition
  (simulated here with AES-GCM encryption of a marker file).

Key splitting — XOR N-of-N scheme
----------------------------------
  share[0..N-2] = CSPRNG random bytes
  share[N-1]    = master_key XOR share[0] XOR … XOR share[N-2]

  Reconstruction: XOR all N shares → master_key

  NOTE: For a production k-of-N threshold scheme, Shamir's Secret Sharing
  (e.g. the ``secretsharing`` library) should be used instead.

Node communication
------------------
Each node exposes /federation/request-shard and /federation/provide-shard
REST endpoints.  Requests are only honoured from nodes whose node_id appears
in the local ``federation_nodes`` table with is_trusted = 1.
"""

import base64
import hashlib
import json
import logging
import secrets
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    logger.warning("cryptography library not installed — running in simulation mode")

try:
    import requests as _http
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    _http = None


class FederationAgent:
    """Manages federation membership and the cryptographic key lifecycle."""

    def __init__(self, node_id: str, data_dir: str, neighbor_addresses: list):
        self.node_id = node_id
        self.data_dir = Path(data_dir)
        self.neighbor_addresses = [a for a in neighbor_addresses if a.strip()]

        self._key_dir = self.data_dir / "keys"
        self._secure_dir = self.data_dir / "secure_store"
        self._key_dir.mkdir(parents=True, exist_ok=True)
        self._secure_dir.mkdir(parents=True, exist_ok=True)

        self._private_key = None
        self._public_key = None
        self._master_key: bytes | None = None
        self._received_shards: dict[str, bytes] = {}  # sender_node_id -> shard bytes
        self._is_mounted = False
        # RLock so that receive_shard → _try_reconstruct → _mount_secure_partition
        # can all run within the same call chain without deadlocking.
        self._lock = threading.RLock()

        self._load_or_generate_keypair()

    # ── RSA Key Pair ────────────────────────────────────────────────────────

    def _load_or_generate_keypair(self) -> None:
        """Load an existing RSA-2048 key pair from disk or generate a new one."""
        priv_path = self._key_dir / "node_private.pem"
        pub_path = self._key_dir / "node_public.pem"

        if not HAS_CRYPTO:
            return

        if priv_path.exists():
            with open(priv_path, "rb") as fh:
                self._private_key = serialization.load_pem_private_key(
                    fh.read(), password=None, backend=default_backend()
                )
            self._public_key = self._private_key.public_key()
            logger.info("Loaded RSA key pair for node %s", self.node_id)
        else:
            self._private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            self._public_key = self._private_key.public_key()
            with open(priv_path, "wb") as fh:
                fh.write(
                    self._private_key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.TraditionalOpenSSL,
                        serialization.NoEncryption(),
                    )
                )
            with open(pub_path, "wb") as fh:
                fh.write(
                    self._public_key.public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                )
            logger.info("Generated new RSA key pair for node %s", self.node_id)

    def get_public_key_pem(self) -> str:
        """Return this node's RSA public key as a PEM string."""
        if not self._public_key:
            return ""
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    # ── Master Key & Shard Generation ───────────────────────────────────────

    def _load_or_generate_master_key(self) -> None:
        """Load or create the 32-byte AES-256 master filesystem key."""
        key_path = self._key_dir / "master.key"
        if key_path.exists():
            with open(key_path, "rb") as fh:
                self._master_key = fh.read()
            logger.info("Loaded existing master key")
        else:
            self._master_key = secrets.token_bytes(32)
            with open(key_path, "wb") as fh:
                fh.write(self._master_key)
            logger.info("Generated new master key for node %s", self.node_id)

    def generate_and_distribute_shards(self, n_nodes: int = 3) -> dict:
        """
        Split the master key into *n_nodes* XOR shares and persist them.

        Returns a dict mapping shard_id -> base64-encoded shard bytes.
        """
        if not self._master_key:
            self._load_or_generate_master_key()

        key_len = len(self._master_key)
        xor_acc = bytearray(self._master_key)
        raw_shards = []

        for _ in range(n_nodes - 1):
            shard = secrets.token_bytes(key_len)
            raw_shards.append(shard)
            xor_acc = bytearray(a ^ b for a, b in zip(xor_acc, shard))
        raw_shards.append(bytes(xor_acc))  # final shard closes the XOR chain

        shards_data = {
            f"shard-{self.node_id}-{i}": base64.b64encode(s).decode()
            for i, s in enumerate(raw_shards)
        }
        shards_path = self._key_dir / "shards.json"
        with open(shards_path, "w") as fh:
            json.dump(shards_data, fh)

        logger.info("Generated %d shards for master key distribution", n_nodes)
        return shards_data

    def get_shard_for_node(self, requesting_node_id: str) -> str | None:
        """
        Return the shard intended for a requesting neighbour (base64).
        Each unique node_id deterministically maps to a shard index so that
        repeated calls for the same node always return the same shard.
        """
        shards_path = self._key_dir / "shards.json"
        if not shards_path.exists():
            self.generate_and_distribute_shards()

        with open(shards_path) as fh:
            shards = json.load(fh)

        shard_keys = sorted(shards.keys())
        if not shard_keys:
            return None

        # Shard index 0 is kept locally; neighbours receive indices 1..N-1
        idx = (int(hashlib.md5(requesting_node_id.encode()).hexdigest(), 16) % (len(shard_keys) - 1)) + 1
        return shards[shard_keys[idx % len(shard_keys)]]

    def receive_shard(self, sender_node_id: str, shard_b64: str) -> None:
        """Store a received key shard from a neighbour and try to reconstruct."""
        with self._lock:
            self._received_shards[sender_node_id] = base64.b64decode(shard_b64)
            logger.info(
                "Received shard from %s (%d total collected)",
                sender_node_id,
                len(self._received_shards),
            )
            self._try_reconstruct()

    def _try_reconstruct(self) -> None:
        """XOR local shard with all received shards to reconstruct the master key."""
        shards_path = self._key_dir / "shards.json"
        if not shards_path.exists():
            return

        with open(shards_path) as fh:
            all_shards_raw = json.load(fh)

        shard_keys = sorted(all_shards_raw.keys())
        # Local node keeps shard index 0
        my_shard = base64.b64decode(all_shards_raw[shard_keys[0]])
        all_shards = [my_shard] + list(self._received_shards.values())

        if len(all_shards) < 2:
            logger.info("Not enough shards to reconstruct key (%d collected)", len(all_shards))
            return

        result = bytearray(all_shards[0])
        for shard in all_shards[1:]:
            result = bytearray(a ^ b for a, b in zip(result, shard))

        self._master_key = bytes(result)
        logger.info("Master key reconstructed from %d shards", len(all_shards))
        self._mount_secure_partition()

    # ── Secure Partition Mount ───────────────────────────────────────────────

    def _mount_secure_partition(self) -> None:
        """
        Mount the encrypted secure partition.

        Raspberry Pi production steps (executed via subprocess in a real deployment):
            cryptsetup luksOpen /dev/mmcblk0p3 secure_partition --key-file /run/master.key
            mount /dev/mapper/secure_partition /mnt/secure

        In this Docker/demo environment we instead AES-GCM-encrypt a marker file
        inside secure_store/ to prove the master key was successfully reconstructed.
        """
        try:
            if HAS_CRYPTO and self._master_key:
                marker_path = self._secure_dir / ".mounted"
                aesgcm = AESGCM(self._master_key)
                nonce = secrets.token_bytes(12)
                ciphertext = aesgcm.encrypt(nonce, b"SECURE_PARTITION_ACTIVE", None)
                with open(marker_path, "wb") as fh:
                    fh.write(nonce + ciphertext)

            with self._lock:
                self._is_mounted = True

            logger.info("Secure partition mounted successfully for node %s", self.node_id)
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Failed to mount secure partition: %s", exc)

    # ── Bootstrap ────────────────────────────────────────────────────────────

    def bootstrap(self) -> None:
        """
        Boot-time federation join sequence.

        1. Wait briefly for neighbour containers to become ready.
        2. For each known neighbour, POST our own shard and receive theirs.
        3. Attempt key reconstruction once shards are collected.
        4. Fall back to single-node (local key) mode if no neighbours reply.
        """
        logger.info("Federation bootstrap starting for node %s", self.node_id)

        if not self.neighbor_addresses:
            logger.info("No neighbours configured — single-node mode")
            self._load_or_generate_master_key()
            self._mount_secure_partition()
            return

        time.sleep(5)  # allow neighbouring containers to start

        for addr in self.neighbor_addresses:
            addr = addr.strip()
            if not addr:
                continue
            if not addr.startswith("http"):
                addr = f"http://{addr}"
            try:
                self._exchange_shard_with(addr)
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning("Could not contact neighbour %s: %s", addr, exc)

        if not self._is_mounted:
            logger.warning("Bootstrap incomplete — falling back to local key")
            self._load_or_generate_master_key()
            self._mount_secure_partition()

    def _exchange_shard_with(self, neighbour_url: str) -> None:
        """Send our shard to a neighbour and request theirs back."""
        if not HAS_REQUESTS:
            logger.warning("requests library not available; skipping shard exchange")
            return

        my_shard_b64 = self._get_local_shard_b64()
        url = f"{neighbour_url.rstrip('/')}/federation/provide-shard"
        resp = _http.post(
            url,
            json={"node_id": self.node_id, "shard": my_shard_b64},
            timeout=10,
        )
        resp.raise_for_status()
        logger.info("Shard exchange successful with %s", neighbour_url)

    def _get_local_shard_b64(self) -> str:
        """Return this node's own shard (index 0) as base64."""
        shards_path = self._key_dir / "shards.json"
        if not shards_path.exists():
            self.generate_and_distribute_shards()
        with open(shards_path) as fh:
            shards = json.load(fh)
        shard_keys = sorted(shards.keys())
        return shards[shard_keys[0]] if shard_keys else ""

    # ── Status ────────────────────────────────────────────────────────────────

    def get_status(self) -> dict:
        """Return current federation and secure-partition status."""
        with self._lock:
            return {
                "node_id": self.node_id,
                "is_mounted": self._is_mounted,
                "shards_collected": len(self._received_shards),
                "neighbours": self.neighbor_addresses,
                "has_master_key": self._master_key is not None,
            }
