#!/usr/bin/env python3
"""
Federation Agent — Federated File System Security
==================================================
Handles cryptographic key lifecycle for the federated edge filesystem.

Security model
--------------
* Each node stores one Shamir share assignment of the master AES-256 key.
* On boot the node requests shares from trusted federation neighbours.
* Once threshold k shares are available, the key is reconstructed.
* The reconstructed key is handed off to the real LUKS mount path (preferred)
    or to simulation mode for local development.

Node communication
------------------
Each node exposes /federation/request-shard and /federation/provide-shard
REST endpoints. Requests are only honoured for trusted nodes, and signed
payload metadata is used by the API layer for request authenticity.
"""

import base64
import hashlib
import hmac
import json
import logging
import math
import os
import secrets
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_GF256_MOD = 0x11B


def _clamp(value: int, min_value: int, max_value: int) -> int:
    return max(min_value, min(value, max_value))


def _gf_mul(a: int, b: int) -> int:
    """Multiply two numbers in GF(2^8) with AES polynomial 0x11B."""
    result = 0
    a &= 0xFF
    b &= 0xFF
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= _GF256_MOD
        b >>= 1
    return result & 0xFF


def _gf_pow(a: int, power: int) -> int:
    result = 1
    base = a & 0xFF
    exp = power
    while exp > 0:
        if exp & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        exp >>= 1
    return result


def _gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("Cannot invert zero in GF(2^8)")
    # In GF(256), a^(255) = 1 for non-zero a, so inverse is a^(254).
    return _gf_pow(a, 254)


def _gf_div(a: int, b: int) -> int:
    return _gf_mul(a, _gf_inv(b))


def _eval_poly(coeffs: list[int], x: int) -> int:
    """Evaluate polynomial c0 + c1*x + c2*x^2 + ... in GF(2^8)."""
    acc = 0
    for coeff in reversed(coeffs):
        acc = _gf_mul(acc, x) ^ coeff
    return acc & 0xFF


def canonicalize_federation_payload(payload: dict) -> str:
    """Return canonical JSON payload for deterministic federation signatures."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def federation_payload_signature(payload: dict, shared_secret: str) -> str:
    """Compute an HMAC-SHA256 signature for a federation payload."""
    signing_payload = {k: v for k, v in payload.items() if k != "signature"}
    canonical = canonicalize_federation_payload(signing_payload)
    return hmac.new(
        shared_secret.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _split_secret_shamir(secret: bytes, threshold_k: int, total_n: int) -> dict[int, bytes]:
    """Split a secret into n shares where any k reconstruct using Shamir."""
    if not secret:
        raise ValueError("Secret cannot be empty")
    if not 2 <= threshold_k <= total_n <= 255:
        raise ValueError("Shamir parameters must satisfy 2 <= k <= n <= 255")

    share_buffers: dict[int, bytearray] = {
        x: bytearray(len(secret)) for x in range(1, total_n + 1)
    }

    for idx, secret_byte in enumerate(secret):
        coeffs = [secret_byte] + list(secrets.token_bytes(threshold_k - 1))
        for x in range(1, total_n + 1):
            share_buffers[x][idx] = _eval_poly(coeffs, x)

    return {x: bytes(buf) for x, buf in share_buffers.items()}


def _recover_secret_shamir(shares: list[tuple[int, bytes]], threshold_k: int) -> bytes:
    """Recover the original secret from at least k unique Shamir shares."""
    if len(shares) < threshold_k:
        raise ValueError("Not enough shares to reconstruct the secret")

    unique: dict[int, bytes] = {}
    for x, share in shares:
        x_int = int(x)
        if x_int <= 0 or x_int > 255:
            raise ValueError("Share x-coordinate must be in range 1..255")
        if x_int not in unique:
            unique[x_int] = share

    if len(unique) < threshold_k:
        raise ValueError("Need at least k unique shares to reconstruct")

    selected = sorted(unique.items(), key=lambda item: item[0])[:threshold_k]
    share_lengths = {len(share_bytes) for _, share_bytes in selected}
    if len(share_lengths) != 1:
        raise ValueError("All shares must have the same byte length")
    secret_len = next(iter(share_lengths))

    recovered = bytearray(secret_len)
    for byte_idx in range(secret_len):
        secret_byte = 0
        for i, (x_i, y_i_bytes) in enumerate(selected):
            y_i = y_i_bytes[byte_idx]
            basis = 1
            for j, (x_j, _y_j_bytes) in enumerate(selected):
                if i == j:
                    continue
                numerator = x_j
                denominator = x_j ^ x_i
                if denominator == 0:
                    raise ValueError("Duplicate share coordinates encountered")
                basis = _gf_mul(basis, _gf_div(numerator, denominator))
            secret_byte ^= _gf_mul(y_i, basis)
        recovered[byte_idx] = secret_byte
    return bytes(recovered)

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
    from requests.exceptions import RequestException as _RequestException
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    _http = None
    _RequestException = OSError  # type: ignore[assignment,misc]


class FederationAgent:
    """Manages federation membership and the cryptographic key lifecycle."""

    def __init__(self, node_id: str, data_dir: str, neighbor_addresses: list):
        self.node_id = node_id
        self.data_dir = Path(data_dir)
        self.neighbor_addresses = [a for a in neighbor_addresses if a.strip()]
        self._neighbor_telemetry: dict[str, dict] = {
            n: {
                "successes": 0,
                "failures": 0,
                "last_latency_ms": None,
                "last_error": None,
                "last_attempt_at": None,
                "last_success_at": None,
            }
            for n in self.neighbor_addresses
        }

        self._key_dir = self.data_dir / "keys"
        self._secure_dir = self.data_dir / "secure_store"
        self._key_dir.mkdir(parents=True, exist_ok=True)
        self._secure_dir.mkdir(parents=True, exist_ok=True)

        self._private_key = None
        self._public_key = None
        self._master_key: bytes | None = None
        self._received_shards: dict[str, tuple[int, bytes, str | None]] = {}
        self._is_mounted = False
        self._share_epoch_id: str | None = None
        self._threshold_k: int | None = None
        self._total_shares_n: int | None = None
        # RLock so that receive_shard → _try_reconstruct → _mount_secure_partition
        # can all run within the same call chain without deadlocking.
        self._lock = threading.RLock()
        self._node_shared_secret = os.environ.get(
            "NODE_SHARED_SECRET",
            os.environ.get("FEDERATION_SHARED_SECRET", ""),
        ).strip()
        self._mount_mode = os.environ.get("FEDERATION_MOUNT_MODE", "auto").strip().lower()
        self._luks_mount_script = Path(
            os.environ.get("LUKS_MOUNT_SCRIPT", "/usr/local/bin/mount_secure_fs.sh")
        )
        self._master_key_tmpfs_path = Path(
            os.environ.get("MASTER_KEY_TMPFS_PATH", "/run/master.key")
        )
        self._allow_simulation_fallback = (
            os.environ.get("ALLOW_SIMULATION_FALLBACK", "1") == "1"
        )
        self._mount_backend = "none"

        self._load_or_generate_keypair()

    def _build_signed_federation_payload(self, payload: dict) -> dict:
        """Attach anti-replay metadata and signature to outgoing federation payloads."""
        signed = dict(payload)
        signed["timestamp"] = int(time.time())
        signed["nonce"] = secrets.token_hex(16)
        if self._node_shared_secret:
            signed["signature"] = federation_payload_signature(signed, self._node_shared_secret)
        return signed

    def _ensure_neighbor_metric(self, neighbour_url: str) -> dict:
        metric = self._neighbor_telemetry.get(neighbour_url)
        if metric is not None:
            return metric

        metric = {
            "successes": 0,
            "failures": 0,
            "last_latency_ms": None,
            "last_error": None,
            "last_attempt_at": None,
            "last_success_at": None,
        }
        self._neighbor_telemetry[neighbour_url] = metric
        return metric

    def _record_neighbor_attempt(
        self,
        neighbour_url: str,
        success: bool,
        latency_ms: Optional[int] = None,
        error: Optional[str] = None,
    ) -> None:
        metric = self._ensure_neighbor_metric(neighbour_url)
        now = int(time.time())
        metric["last_attempt_at"] = now
        if latency_ms is not None:
            metric["last_latency_ms"] = latency_ms

        if success:
            metric["successes"] = int(metric.get("successes", 0)) + 1
            metric["last_success_at"] = now
            metric["last_error"] = None
        else:
            metric["failures"] = int(metric.get("failures", 0)) + 1
            metric["last_error"] = error or "unknown"

    def _neighbor_score(self, neighbour_url: str) -> float:
        metric = self._ensure_neighbor_metric(neighbour_url)
        successes = int(metric.get("successes", 0))
        failures = int(metric.get("failures", 0))
        attempts = successes + failures

        # Bayesian-smoothed reliability starts neutral before first probe.
        reliability = (successes + 1.0) / (attempts + 2.0)

        latency_ms = metric.get("last_latency_ms")
        if latency_ms is None:
            latency_factor = 0.5
        else:
            bounded_latency = min(max(int(latency_ms), 0), 5000)
            latency_factor = 1.0 - (bounded_latency / 5000.0)

        score = (0.7 * reliability) + (0.3 * latency_factor)
        return round(score, 4)

    def get_ranked_neighbors(self) -> list[str]:
        """Return neighbors ranked by health/latency/reliability score."""
        ranked = sorted(
            self.neighbor_addresses,
            key=lambda n: (-self._neighbor_score(n), n),
        )
        return ranked

    def get_neighbor_diagnostics(self) -> list[dict]:
        """Return detailed score diagnostics for admin visibility."""
        diagnostics = []
        ranked = self.get_ranked_neighbors()
        for idx, neighbour in enumerate(ranked):
            metric = self._ensure_neighbor_metric(neighbour)
            diagnostics.append(
                {
                    "neighbor": neighbour,
                    "rank": idx + 1,
                    "score": self._neighbor_score(neighbour),
                    "successes": int(metric.get("successes", 0)),
                    "failures": int(metric.get("failures", 0)),
                    "last_latency_ms": metric.get("last_latency_ms"),
                    "last_error": metric.get("last_error"),
                    "last_attempt_at": metric.get("last_attempt_at"),
                    "last_success_at": metric.get("last_success_at"),
                }
            )
        return diagnostics

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

    def _compute_default_threshold(self, total_n: int) -> int:
        return _clamp(math.ceil(0.6 * total_n), 2, min(7, total_n))

    def _persist_shard_bundle(self, bundle: dict) -> None:
        shards_path = self._key_dir / "shards.json"
        with open(shards_path, "w", encoding="utf-8") as fh:
            json.dump(bundle, fh, indent=2, sort_keys=True)

    def _load_shard_bundle(self) -> dict:
        shards_path = self._key_dir / "shards.json"
        if not shards_path.exists():
            return self.generate_and_distribute_shards()

        with open(shards_path, encoding="utf-8") as fh:
            payload = json.load(fh)

        # Legacy format conversion (old XOR dict: shard-id -> b64)
        if isinstance(payload, dict) and "scheme" not in payload:
            legacy_keys = sorted(payload.keys())
            shares = {
                str(i + 1): payload[key]
                for i, key in enumerate(legacy_keys)
            }
            total_n = len(shares)
            bundle = {
                "scheme": "legacy-xor-migrated",
                "node_id": self.node_id,
                "epoch_id": self._calculate_deterministic_epoch_id(),
                "threshold_k": total_n,
                "total_shares_n": total_n,
                "shares": shares,
                "assignments": {self.node_id: 1},
            }
            self._persist_shard_bundle(bundle)
            payload = bundle

        self._share_epoch_id = payload.get("epoch_id")
        self._threshold_k = int(payload.get("threshold_k", 0)) or None
        self._total_shares_n = int(payload.get("total_shares_n", 0)) or None
        return payload

    def _calculate_deterministic_epoch_id(self, trusted_node_ids: list[str] | None = None) -> str:
        """
        Calculate a deterministic epoch ID based on sorted NODE_IDs only.
        
        This ensures all nodes in the cluster compute the SAME epoch_id,
        regardless of their configured neighbor addresses or runtime environment.
        
        The epoch is based on:
        1. This node's NODE_ID (from NODE_ID env var)
        2. All other node IDs that are trusted in the database (if provided)
        
        If no trusted nodes are provided yet (first bootstrap), we use just this node's ID,
        which will be overwritten once nodes exchange shards and both nodes sync via 
        the provided trusted_node_ids from the database.
        
        Args:
            trusted_node_ids: List of node IDs that are trusted in DB (e.g., ["node-1", "node-2"])
        
        Returns:
            Hex string: first 16 chars of SHA256 hash of sorted node IDs
        """
        # Collect all known node IDs: self + any trusted peers from DB
        all_node_ids = [self.node_id]
        if trusted_node_ids:
            all_node_ids.extend(trusted_node_ids)
        
        # Sort for determinism: both nodes will produce same list regardless of discovery order
        all_node_ids = sorted(set(all_node_ids))
        
        node_list_str = "|".join(all_node_ids)
        epoch_hash = hashlib.sha256(node_list_str.encode("utf-8")).hexdigest()
        return epoch_hash[:16]  # Use first 16 chars (8 bytes when hex-encoded)

    def generate_and_distribute_shards(
        self,
        n_nodes: int | None = None,
        threshold_k: int | None = None,
        trusted_node_ids: list[str] | None = None,
    ) -> dict:
        """
        Split the master key into Shamir k-of-n shares and persist them.

        Returns the persisted shard bundle payload.
        
        Args:
            n_nodes: Number of shares (N in k-of-n). Defaults to len(neighbors) + 1.
            threshold_k: Threshold (K in k-of-n). Defaults to computed value.
            trusted_node_ids: List of trusted node IDs for deterministic epoch calculation.
        """
        if not self._master_key:
            self._load_or_generate_master_key()

        total_n = n_nodes if n_nodes is not None else max(2, len(self.neighbor_addresses) + 1)
        total_n = _clamp(int(total_n), 2, 255)

        env_threshold = os.environ.get("SHARD_THRESHOLD_K", "").strip()
        if threshold_k is None and env_threshold.isdigit():
            threshold_k = int(env_threshold)
        if threshold_k is None:
            threshold_k = self._compute_default_threshold(total_n)

        threshold_k = _clamp(int(threshold_k), 2, min(7, total_n))
        raw_shares = _split_secret_shamir(self._master_key, threshold_k, total_n)

        bundle = {
            "scheme": "shamir-k-of-n",
            "node_id": self.node_id,
            "epoch_id": self._calculate_deterministic_epoch_id(trusted_node_ids),
            "threshold_k": threshold_k,
            "total_shares_n": total_n,
            "shares": {
                str(x): base64.b64encode(share_bytes).decode("ascii")
                for x, share_bytes in raw_shares.items()
            },
            "assignments": {self.node_id: 1},
        }
        self._persist_shard_bundle(bundle)

        self._share_epoch_id = bundle["epoch_id"]
        self._threshold_k = threshold_k
        self._total_shares_n = total_n

        logger.info(
            "Generated Shamir shares for node %s (k=%d, n=%d, epoch=%s)",
            self.node_id,
            threshold_k,
            total_n,
            self._share_epoch_id,
        )
        return bundle

    def _get_or_assign_share_x(self, requesting_node_id: str, bundle: dict) -> int | None:
        assignments = bundle.setdefault("assignments", {})
        shares = bundle.get("shares", {})
        total_n = int(bundle.get("total_shares_n", 0))
        if total_n < 2 or not shares:
            return None

        if requesting_node_id in assignments:
            try:
                return int(assignments[requesting_node_id])
            except (TypeError, ValueError):
                return None

        if requesting_node_id == self.node_id:
            assignments[self.node_id] = 1
            self._persist_shard_bundle(bundle)
            return 1

        used = set()
        for value in assignments.values():
            try:
                used.add(int(value))
            except (TypeError, ValueError):
                continue

        available = [x for x in range(2, total_n + 1) if x not in used and str(x) in shares]
        if not available:
            logger.warning("No available shard assignments left for node %s", requesting_node_id)
            return None

        start_idx = int(hashlib.md5(requesting_node_id.encode()).hexdigest(), 16) % len(available)
        chosen_x = available[start_idx]
        assignments[requesting_node_id] = chosen_x
        self._persist_shard_bundle(bundle)
        return chosen_x

    def get_shard_for_node(self, requesting_node_id: str) -> str | None:
        """
        Return the shard intended for a requesting neighbour (base64).
        Each unique node_id deterministically maps to a shard index so that
        repeated calls for the same node always return the same shard.
        """
        shard_payload = self.get_shard_payload_for_node(requesting_node_id)
        if not shard_payload:
            return None
        return shard_payload["shard"]

    def get_shard_payload_for_node(self, requesting_node_id: str) -> dict | None:
        """Return shard payload metadata for a requesting node."""
        bundle = self._load_shard_bundle()
        share_x = self._get_or_assign_share_x(requesting_node_id, bundle)
        if share_x is None:
            return None

        shard_b64 = bundle.get("shares", {}).get(str(share_x))
        if not shard_b64:
            return None

        return {
            "shard": shard_b64,
            "share_x": share_x,
            "epoch_id": bundle.get("epoch_id"),
            "threshold_k": int(bundle.get("threshold_k", 0)),
            "total_shares_n": int(bundle.get("total_shares_n", 0)),
        }

    def get_catchup_payload_for_node(self, requesting_node_id: str) -> dict | None:
        """Return epoch + assigned-share payload for offline-node catch-up."""
        shard_payload = self.get_shard_payload_for_node(requesting_node_id)
        if not shard_payload:
            return None

        return {
            "epoch_id": shard_payload.get("epoch_id"),
            "threshold_k": shard_payload.get("threshold_k"),
            "total_shares_n": shard_payload.get("total_shares_n"),
            "assigned_share_x": shard_payload.get("share_x"),
            "assigned_share": shard_payload.get("shard"),
        }

    def apply_catchup_payload(self, payload: dict) -> tuple[bool, str]:
        """
        Apply catch-up state received from a trusted peer for this node.

        The payload must include the node's assigned share for the latest epoch.
        """
        epoch_id = str(payload.get("epoch_id", "")).strip()
        assigned_share = str(payload.get("assigned_share", "")).strip()

        try:
            threshold_k = int(payload.get("threshold_k", 0))
            total_shares_n = int(payload.get("total_shares_n", 0))
            assigned_share_x = int(payload.get("assigned_share_x", 0))
        except (TypeError, ValueError):
            return False, "Invalid catch-up payload numeric values"

        if not epoch_id or not assigned_share:
            return False, "Catch-up payload missing epoch_id or assigned_share"
        if threshold_k < 2 or total_shares_n < threshold_k:
            return False, "Catch-up payload has invalid threshold parameters"
        if assigned_share_x <= 0 or assigned_share_x > total_shares_n:
            return False, "Catch-up payload has invalid assigned_share_x"

        # Validate assigned share is valid base64 payload.
        try:
            base64.b64decode(assigned_share)
        except Exception:  # pragma: no cover - defensive decode guard
            return False, "Catch-up payload assigned_share is not valid base64"

        with self._lock:
            existing = self._load_shard_bundle()
            local_epoch = str(existing.get("epoch_id", "")).strip()

            if local_epoch == epoch_id:
                return True, "Catch-up payload epoch already applied"

            catchup_bundle = {
                "scheme": "shamir-k-of-n",
                "node_id": self.node_id,
                "epoch_id": epoch_id,
                "threshold_k": threshold_k,
                "total_shares_n": total_shares_n,
                "shares": {str(assigned_share_x): assigned_share},
                "assignments": {self.node_id: assigned_share_x},
            }
            self._persist_shard_bundle(catchup_bundle)
            self._share_epoch_id = epoch_id
            self._threshold_k = threshold_k
            self._total_shares_n = total_shares_n
            self._received_shards = {}

        return True, "Catch-up payload applied"

    def receive_shard(
        self,
        sender_node_id: str,
        shard_b64: str,
        share_x: int | None = None,
        epoch_id: str | None = None,
    ) -> None:
        """Store a received key shard from a neighbour and try to reconstruct."""
        with self._lock:
            bundle = self._load_shard_bundle()
            total_n = int(bundle.get("total_shares_n", 0))

            if epoch_id and bundle.get("epoch_id") and epoch_id != bundle.get("epoch_id"):
                logger.warning(
                    "Ignoring shard from %s due to epoch mismatch (%s != %s)",
                    sender_node_id,
                    epoch_id,
                    bundle.get("epoch_id"),
                )
                return

            if share_x is None:
                assignments = bundle.get("assignments", {})
                mapped = assignments.get(sender_node_id)
                if mapped is not None:
                    try:
                        share_x = int(mapped)
                    except (TypeError, ValueError):
                        share_x = None

            if share_x is None:
                logger.warning("Ignoring shard from %s because share_x is missing", sender_node_id)
                return
            if share_x <= 0 or (total_n and share_x > total_n):
                logger.warning("Ignoring shard from %s due to invalid share_x=%s", sender_node_id, share_x)
                return

            self._received_shards[sender_node_id] = (
                share_x,
                base64.b64decode(shard_b64),
                epoch_id,
            )
            logger.info(
                "Received shard from %s (%d total collected)",
                sender_node_id,
                len(self._received_shards),
            )
            self._try_reconstruct()

    def _try_reconstruct(self) -> None:
        """Attempt strict k-of-n reconstruction using local + received Shamir shares."""
        bundle = self._load_shard_bundle()
        threshold_k = int(bundle.get("threshold_k", 0))
        shares = bundle.get("shares", {})
        if threshold_k < 2 or not shares:
            return

        local_x = int(bundle.get("assignments", {}).get(self.node_id, 1))
        local_shard_b64 = shares.get(str(local_x))
        if not local_shard_b64:
            logger.warning("Local shard x=%d missing; cannot reconstruct", local_x)
            return

        unique_shares: dict[int, bytes] = {
            local_x: base64.b64decode(local_shard_b64)
        }

        current_epoch = bundle.get("epoch_id")
        for _sender_id, (share_x, share_bytes, shard_epoch) in self._received_shards.items():
            if shard_epoch and current_epoch and shard_epoch != current_epoch:
                continue
            if share_x not in unique_shares:
                unique_shares[share_x] = share_bytes

        if len(unique_shares) < threshold_k:
            logger.info(
                "Not enough shards to reconstruct key (%d/%d collected)",
                len(unique_shares),
                threshold_k,
            )
            return

        selected = [(x, unique_shares[x]) for x in sorted(unique_shares.keys())[:threshold_k]]

        try:
            self._master_key = _recover_secret_shamir(selected, threshold_k)
        except ValueError as exc:
            logger.warning("Shard reconstruction failed: %s", exc)
            return

        logger.info("Master key reconstructed from %d/%d shares", len(selected), threshold_k)
        self._mount_secure_partition()

    # ── Secure Partition Mount ───────────────────────────────────────────────

    def _can_use_luks_mount(self) -> bool:
        if os.name == "nt":
            return False
        if self._mount_mode not in ("auto", "luks"):
            return False
        return self._luks_mount_script.exists() and os.access(self._luks_mount_script, os.X_OK)

    def _write_master_key_tmpfs(self) -> None:
        if not self._master_key:
            raise ValueError("Master key is not available")
        self._master_key_tmpfs_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._master_key_tmpfs_path, "wb") as fh:
            fh.write(self._master_key)
        os.chmod(self._master_key_tmpfs_path, 0o600)

    def _wipe_master_key_tmpfs(self) -> None:
        if not self._master_key_tmpfs_path.exists():
            return
        try:
            if shutil.which("shred"):
                subprocess.run(
                    ["shred", "-u", str(self._master_key_tmpfs_path)],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
            elif self._master_key_tmpfs_path.exists():
                self._master_key_tmpfs_path.unlink(missing_ok=True)
        except OSError:
            self._master_key_tmpfs_path.unlink(missing_ok=True)

    def _mount_via_luks_script(self) -> bool:
        """Use host-level mount script to unlock and mount LUKS secure partition."""
        if not self._master_key:
            logger.error("Cannot mount via LUKS script without reconstructed master key")
            return False
        if not self._luks_mount_script.exists():
            logger.error("LUKS mount script not found: %s", self._luks_mount_script)
            return False

        try:
            self._write_master_key_tmpfs()
            result = subprocess.run(
                [str(self._luks_mount_script), "open"],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                logger.error(
                    "LUKS mount script failed (%s): %s",
                    result.returncode,
                    (result.stderr or result.stdout).strip(),
                )
                return False

            self._mount_backend = "luks"
            return True
        except (OSError, subprocess.SubprocessError) as exc:
            logger.error("Failed to execute LUKS mount script: %s", exc)
            return False
        finally:
            # The script should wipe this itself, but we defensively wipe leftovers.
            self._wipe_master_key_tmpfs()

    def _mount_via_simulation(self) -> bool:
        """Fallback mode for local development where host LUKS is unavailable."""
        try:
            if HAS_CRYPTO and self._master_key:
                marker_path = self._secure_dir / ".mounted"
                aesgcm = AESGCM(self._master_key)
                nonce = secrets.token_bytes(12)
                ciphertext = aesgcm.encrypt(nonce, b"SECURE_PARTITION_ACTIVE", None)
                with open(marker_path, "wb") as fh:
                    fh.write(nonce + ciphertext)
            self._mount_backend = "simulation"
            return True
        except OSError as exc:
            logger.error("Simulation mount failed: %s", exc)
            return False

    def _mount_secure_partition(self) -> None:
        """
        Mount the encrypted secure partition.

        Raspberry Pi production steps (executed via subprocess in a real deployment):
            cryptsetup luksOpen /dev/mmcblk0p3 secure_partition --key-file /run/master.key
            mount /dev/mapper/secure_partition /mnt/secure

        In this Docker/demo environment we instead AES-GCM-encrypt a marker file
        inside secure_store/ to prove the master key was successfully reconstructed.
        """
        mounted = False

        if self._can_use_luks_mount():
            mounted = self._mount_via_luks_script()
        elif self._mount_mode == "luks":
            logger.error(
                "FEDERATION_MOUNT_MODE=luks but LUKS mount prerequisites are not met (script=%s)",
                self._luks_mount_script,
            )

        if not mounted:
            if self._mount_mode == "simulation" or (
                self._mount_mode == "auto" and self._allow_simulation_fallback
            ):
                mounted = self._mount_via_simulation()
            elif self._mount_mode == "auto" and not self._allow_simulation_fallback:
                logger.error("Auto mount failed and simulation fallback is disabled")

        if not mounted:
            with self._lock:
                self._is_mounted = False
            logger.error("Failed to mount secure partition for node %s", self.node_id)
            return

        with self._lock:
            self._is_mounted = True

        self._initialize_secure_store()
        logger.info(
            "Secure partition mounted successfully for node %s using %s backend",
            self.node_id,
            self._mount_backend,
        )

    def _initialize_secure_store(self) -> None:
        """
        Create secure folder structure used by the portal file API.

        The directories are intentionally kept mostly empty so administrators
        can place their own protected content. A single sample file is created
        to verify download flow after authentication and security checks.
        """
        folder_names = ["basic", "premium", "shared"]
        for folder in folder_names:
            folder_path = self._secure_dir / folder
            folder_path.mkdir(parents=True, exist_ok=True)

        sample_file = self._secure_dir / "shared" / "welcome.txt"
        if not sample_file.exists():
            sample_file.write_text(
                (
                    "Secure file area is active.\n"
                    f"Node: {self.node_id}\n"
                    "This file can be downloaded only after login, device authorization, "
                    "and mounted secure partition checks pass.\n"
                ),
                encoding="utf-8",
            )

        logger.info("Secure store initialised in %s", self._secure_dir)

    # ── Bootstrap ────────────────────────────────────────────────────────────

    def bootstrap(self, trusted_node_ids: list[str] | None = None) -> None:
        """
        Boot-time federation join sequence.

        1. Generate master key and calculate deterministic epoch based on trusted peers.
        2. Wait briefly for neighbour containers to become ready.
        3. For each known neighbour, POST our own shard and receive theirs.
        4. Attempt key reconstruction once shards are collected.
        5. Fall back to single-node (local key) mode if no neighbours reply.
        
        Args:
            trusted_node_ids: List of trusted node IDs from database (for deterministic epoch).
                             If provided, used to calculate the epoch so all peers compute the same value.
        """
        logger.info("Federation bootstrap starting for node %s", self.node_id)

        # Generate master key with deterministic epoch if trusted nodes are known
        self._load_or_generate_master_key()
        if trusted_node_ids:
            self.generate_and_distribute_shards(trusted_node_ids=trusted_node_ids)
            epoch = self._share_epoch_id
            logger.info("Generated shards with deterministic epoch: %s", epoch)

        if not self.neighbor_addresses:
            logger.info("No neighbours configured — single-node mode")
            self._mount_secure_partition()
            return

        time.sleep(5)  # allow neighbouring containers to start

        for addr in self.get_ranked_neighbors():
            addr = addr.strip()
            if not addr:
                continue
            if not addr.startswith("http"):
                addr = f"http://{addr}"
            started = time.perf_counter()
            try:
                self._exchange_shard_with(addr)
                latency_ms = int((time.perf_counter() - started) * 1000)
                self._record_neighbor_attempt(addr, success=True, latency_ms=latency_ms)
            except (OSError, _RequestException) as exc:
                latency_ms = int((time.perf_counter() - started) * 1000)
                self._record_neighbor_attempt(
                    addr,
                    success=False,
                    latency_ms=latency_ms,
                    error=str(exc),
                )
                logger.warning("Could not contact neighbour %s: %s", addr, exc)

        if not self._is_mounted:
            logger.warning("Bootstrap incomplete — falling back to local key")
            self._mount_secure_partition()

    def _exchange_shard_with(self, neighbour_url: str) -> None:
        """Send our assigned shard to a neighbour and request our shard back."""
        if not HAS_REQUESTS:
            logger.warning("requests library not available; skipping shard exchange")
            return

        base_url = neighbour_url.rstrip("/")

        neighbour_id = None
        try:
            info_resp = _http.get(f"{base_url}/federation/info", timeout=10)
            info_resp.raise_for_status()
            neighbour_id = (info_resp.json() or {}).get("node_id")
        except (OSError, _RequestException, ValueError):
            logger.warning("Could not fetch neighbour identity from %s/federation/info", base_url)

        if not neighbour_id:
            neighbour_id = base_url.split("://", 1)[-1]

        my_payload = self.get_shard_payload_for_node(neighbour_id)
        if not my_payload:
            logger.warning("No shard available to send to neighbour %s", neighbour_id)
            return

        provide_url = f"{base_url}/federation/provide-shard"
        provide_resp = _http.post(
            provide_url,
            json=self._build_signed_federation_payload(
                {
                "node_id": self.node_id,
                "shard": my_payload["shard"],
                "share_x": my_payload["share_x"],
                "epoch_id": my_payload["epoch_id"],
                }
            ),
            timeout=10,
        )
        provide_resp.raise_for_status()

        request_url = f"{base_url}/federation/request-shard"
        request_resp = _http.post(
            request_url,
            json=self._build_signed_federation_payload({"node_id": self.node_id}),
            timeout=10,
        )
        request_resp.raise_for_status()
        request_data = request_resp.json() or {}
        their_shard = request_data.get("shard", "")
        if their_shard:
            self.receive_shard(
                sender_node_id=neighbour_id,
                shard_b64=their_shard,
                share_x=request_data.get("share_x"),
                epoch_id=request_data.get("epoch_id"),
            )
        logger.info("Shard exchange successful with %s", neighbour_url)

    def _get_local_shard_b64(self) -> str:
        """Return this node's locally assigned shard as base64."""
        payload = self.get_shard_payload_for_node(self.node_id)
        return payload["shard"] if payload else ""

    # ── Status ────────────────────────────────────────────────────────────────

    def get_status(self) -> dict:
        """Return current federation and secure-partition status."""
        bundle = self._load_shard_bundle()
        with self._lock:
            return {
                "node_id": self.node_id,
                "is_mounted": self._is_mounted,
                "mount_mode": self._mount_mode,
                "mount_backend": self._mount_backend,
                "shards_collected": len(self._received_shards),
                "neighbours": self.neighbor_addresses,
                "ranked_neighbors": self.get_ranked_neighbors(),
                "neighbor_diagnostics": self.get_neighbor_diagnostics(),
                "has_master_key": self._master_key is not None,
                "scheme": bundle.get("scheme", "unknown"),
                "threshold_k": int(bundle.get("threshold_k", 0)),
                "total_shares_n": int(bundle.get("total_shares_n", 0)),
                "share_epoch": bundle.get("epoch_id"),
            }
