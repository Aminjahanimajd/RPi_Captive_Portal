#!/usr/bin/env python3
"""
Membership Management — Multi-Node Federation Lifecycle
========================================================

Handles dynamic node addition/removal with automatic shard redistribution
and epoch-based key rotation.

Features:
  - Join workflows: Add new node with shard recalculation
  - Leave workflows: Remove node with share rebalancing
  - Epoch tracking: Each key epoch has version, timestamp, creation node
  - Key rotation: Automatic rotation on membership changes
  - Idempotency: Safe to retry join/leave operations
"""

import hashlib
import json
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class MembershipEvent(Enum):
    """Types of membership events."""
    NODE_JOINED = "node_joined"
    NODE_LEFT = "node_left"
    KEY_ROTATED = "key_rotated"
    EPOCH_TRANSITIONED = "epoch_transitioned"


@dataclass
class NodeMember:
    """Represents a node in the federation."""
    node_id: str
    hostname: str
    ip_address: str
    port: int = 5000
    is_trusted: bool = False
    joined_at: str = None  # ISO 8601 timestamp
    epoch_version: int = 0  # Number of epochs this node has seen
    
    def __post_init__(self):
        if self.joined_at is None:
            self.joined_at = datetime.now(timezone.utc).isoformat()


@dataclass
class KeyEpoch:
    """Represents a cryptographic key epoch."""
    epoch_id: str  # Unique identifier for this key version
    epoch_number: int  # Sequential epoch counter (0, 1, 2, ...)
    created_at: str  # ISO 8601 timestamp
    created_by_node: str  # Which node initiated this epoch
    total_shares: int  # N in Shamir scheme
    threshold_shares: int  # K in Shamir scheme (how many needed to reconstruct)
    
    membership_root_hash: str  # Hash of current membership
    is_active: bool = True
    rotated_at: Optional[str] = None  # When key rotation completed
    
    def to_dict(self):
        return {
            "epoch_id": self.epoch_id,
            "epoch_number": self.epoch_number,
            "created_at": self.created_at,
            "created_by_node": self.created_by_node,
            "total_shares": self.total_shares,
            "threshold_shares": self.threshold_shares,
            "membership_root_hash": self.membership_root_hash,
            "is_active": self.is_active,
            "rotated_at": self.rotated_at,
        }


class MembershipManager:
    """Manages federation node membership and key epochs."""
    
    def __init__(self, node_id: str, data_dir: str, coordinator_hint: Optional[str] = None):
        """
        Initialize membership manager.
        
        Args:
            node_id: Current node's identifier
            data_dir: Directory for persisting membership state
        """
        self.node_id = node_id
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._coordinator_hint = coordinator_hint or node_id
        self._rekey_lock = threading.Lock()
        
        # Membership state
        self._members: dict[str, NodeMember] = {}  # node_id -> NodeMember
        self._current_epoch: Optional[KeyEpoch] = None
        self._epoch_history: list[KeyEpoch] = []  # Past epochs
        self._coordination_state: dict = {
            "last_coordinator": None,
            "last_rekey_at": None,
            "pending": [],
        }
        
        # Persistence
        self._members_file = self.data_dir / "federation_members.json"
        self._epochs_file = self.data_dir / "federation_epochs.json"
        
        self._load_state()
        
        # Bootstrap self as a trusted member if not already present
        if self.node_id not in self._members:
            self._members[self.node_id] = NodeMember(
                node_id=self.node_id,
                hostname="localhost",
                ip_address="127.0.0.1",
                port=5000,
                is_trusted=True,
            )
            self._save_state()
            logger.info(f"Bootstrapped self as trusted member: {self.node_id}")
    
    # ── State Persistence ────────────────────────────────────────────────────
    
    def _load_state(self):
        """Load membership and epoch state from disk."""
        try:
            if self._members_file.exists():
                with open(self._members_file) as f:
                    data = json.load(f)
                    for node_id, member_data in data.items():
                        self._members[node_id] = NodeMember(**member_data)
                logger.info(f"Loaded {len(self._members)} members from {self._members_file}")
            
            if self._epochs_file.exists():
                with open(self._epochs_file) as f:
                    data = json.load(f)
                    self._epoch_history = [KeyEpoch(**epoch_data) for epoch_data in data["history"]]
                    current_epoch_data = data.get("current")
                    if current_epoch_data:
                        self._current_epoch = KeyEpoch(**current_epoch_data)
                    coordination_data = data.get("coordination")
                    if isinstance(coordination_data, dict):
                        self._coordination_state["last_coordinator"] = coordination_data.get("last_coordinator")
                        self._coordination_state["last_rekey_at"] = coordination_data.get("last_rekey_at")
                        self._coordination_state["pending"] = list(coordination_data.get("pending", []))
                logger.info(f"Loaded {len(self._epoch_history)} epochs from {self._epochs_file}")
        except Exception as e:
            logger.error(f"Failed to load state: {e}")
    
    def _save_state(self):
        """Persist membership and epoch state to disk."""
        try:
            # Save members
            members_data = {
                node_id: {
                    "node_id": m.node_id,
                    "hostname": m.hostname,
                    "ip_address": m.ip_address,
                    "port": m.port,
                    "is_trusted": m.is_trusted,
                    "joined_at": m.joined_at,
                    "epoch_version": m.epoch_version,
                }
                for node_id, m in self._members.items()
            }
            with open(self._members_file, "w") as f:
                json.dump(members_data, f, indent=2)
            
            # Save epochs
            epochs_data = {
                "current": self._current_epoch.to_dict() if self._current_epoch else None,
                "history": [epoch.to_dict() for epoch in self._epoch_history],
                "coordination": {
                    "coordinator_hint": self._coordinator_hint,
                    "leader_node_id": self.get_leader_node_id(),
                    "last_coordinator": self._coordination_state.get("last_coordinator"),
                    "last_rekey_at": self._coordination_state.get("last_rekey_at"),
                    "pending": self._coordination_state.get("pending", []),
                },
            }
            with open(self._epochs_file, "w") as f:
                json.dump(epochs_data, f, indent=2)
            
            logger.info(f"Persisted state: {len(self._members)} members, {len(self._epoch_history)} epochs")
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
    
    # ── Membership Queries ───────────────────────────────────────────────────
    
    def get_members(self) -> dict[str, NodeMember]:
        """Get all federation members."""
        return dict(self._members)
    
    def get_trusted_members(self) -> dict[str, NodeMember]:
        """Get only trusted members."""
        return {nid: m for nid, m in self._members.items() if m.is_trusted}
    
    def get_member(self, node_id: str) -> Optional[NodeMember]:
        """Get a specific member."""
        return self._members.get(node_id)
    
    def node_exists(self, node_id: str) -> bool:
        """Check if node is in membership."""
        return node_id in self._members
    
    def count_members(self, trusted_only: bool = False) -> int:
        """Count members."""
        if trusted_only:
            return len(self.get_trusted_members())
        return len(self._members)
    
    def count_trusted_members(self) -> int:
        """Count trusted members (convenience method)."""
        return self.count_members(trusted_only=True)

    def get_leader_node_id(self) -> Optional[str]:
        """Get deterministic coordinator leader for membership transitions."""
        trusted_members = self.get_trusted_members()
        if not trusted_members:
            return None

        if self._coordinator_hint in trusted_members:
            return self._coordinator_hint

        return sorted(trusted_members.keys())[0]

    def is_leader(self, node_id: Optional[str] = None) -> bool:
        """Check if node is the current deterministic leader."""
        candidate = node_id or self.node_id
        leader = self.get_leader_node_id()
        return bool(leader and candidate == leader)

    def coordination_status(self) -> dict:
        """Get leader/coordinator and pending transition status."""
        return {
            "coordinator_hint": self._coordinator_hint,
            "leader_node_id": self.get_leader_node_id(),
            "is_local_leader": self.is_leader(),
            "last_coordinator": self._coordination_state.get("last_coordinator"),
            "last_rekey_at": self._coordination_state.get("last_rekey_at"),
            "pending_rekeys": list(self._coordination_state.get("pending", [])),
            "pending_rekey_count": len(self._coordination_state.get("pending", [])),
        }

    def _queue_pending_rekey(self, change_type: str, affected_node_id: str) -> None:
        self._coordination_state.setdefault("pending", []).append(
            {
                "change_type": change_type,
                "affected_node_id": affected_node_id,
                "queued_at": datetime.now(timezone.utc).isoformat(),
            }
        )

    def coordinate_membership_rekey(
        self,
        change_type: str,
        affected_node_id: str,
        requester_node_id: Optional[str] = None,
        force: bool = False,
    ) -> tuple[bool, str]:
        """
        Coordinate membership rekey through deterministic leader selection.

        Non-leader requests are queued for the leader unless force=True.
        """
        requester = requester_node_id or self.node_id
        trusted_count = len(self.get_trusted_members())
        if trusted_count < 2:
            return True, f"Rekey skipped: not enough trusted members ({trusted_count})"

        leader = self.get_leader_node_id()
        if not leader:
            return False, "No trusted leader available for rekey coordination"

        if not force and requester != leader:
            self._queue_pending_rekey(change_type, affected_node_id)
            self._save_state()
            return True, f"Rekey deferred; coordinator is {leader}"

        with self._rekey_lock:
            success, msg = self._rotate_key_for_membership_change(change_type, affected_node_id)
            if success:
                self._coordination_state["last_coordinator"] = requester
                self._coordination_state["last_rekey_at"] = datetime.now(timezone.utc).isoformat()
                self._save_state()
            return success, msg

    def process_pending_rekeys(self, requester_node_id: Optional[str] = None) -> tuple[bool, str]:
        """Process queued rekeys. Only the current leader can process the queue."""
        requester = requester_node_id or self.node_id
        if not self.is_leader(requester):
            return False, f"Node {requester} is not current leader"

        pending = list(self._coordination_state.get("pending", []))
        if not pending:
            return True, "No pending rekeys"

        last_message = ""
        for item in pending:
            success, last_message = self.coordinate_membership_rekey(
                change_type=item.get("change_type", "rotation"),
                affected_node_id=item.get("affected_node_id", "pending"),
                requester_node_id=requester,
                force=True,
            )
            if not success:
                return False, last_message

        self._coordination_state["pending"] = []
        self._save_state()
        return True, last_message or "Processed pending rekeys"
    
    # ── Epoch Management ─────────────────────────────────────────────────────
    
    def get_current_epoch(self) -> Optional[KeyEpoch]:
        """Get the current active key epoch."""
        return self._current_epoch
    
    def get_epoch_history(self) -> list[KeyEpoch]:
        """Get all past epochs."""
        return list(self._epoch_history)
    
    def _calculate_membership_hash(self, members: dict[str, NodeMember]) -> str:
        """Calculate a hash of current membership for epoch tracking."""
        member_ids = sorted(members.keys())
        member_str = ",".join(f"{nid}:{members[nid].is_trusted}" for nid in member_ids)
        return hashlib.sha256(member_str.encode()).hexdigest()[:8]
    
    # ── Node Join Workflow ───────────────────────────────────────────────────
    
    def node_join_request(
        self,
        node_id: str,
        hostname: str,
        ip_address: str,
        port: int = 5000,
    ) -> tuple[bool, str]:
        """
        Process a node join request.
        
        Returns:
            (success, message): success flag and status message
        """
        if node_id in self._members:
            return False, f"Node {node_id} already in membership"
        
        # Add member (untrusted initially)
        member = NodeMember(
            node_id=node_id,
            hostname=hostname,
            ip_address=ip_address,
            port=port,
            is_trusted=False,
            epoch_version=self._current_epoch.epoch_number if self._current_epoch else 0,
        )
        self._members[node_id] = member
        self._save_state()
        
        logger.info(f"Node {node_id} added (untrusted, pending approval)")
        return True, f"Node {node_id} added (pending trust approval)"
    
    def approve_node_join(self, node_id: str) -> tuple[bool, str]:
        """
        Approve a pending node join and trigger share recalculation.
        
        Returns:
            (success, message): success flag and message
        """
        if node_id not in self._members:
            return False, f"Node {node_id} not found"
        
        member = self._members[node_id]
        if member.is_trusted:
            return False, f"Node {node_id} already trusted"
        
        # Mark as trusted
        member.is_trusted = True
        self._save_state()
        
        success, msg = self.coordinate_membership_rekey(
            change_type="join",
            affected_node_id=node_id,
            requester_node_id=self.node_id,
        )
        if not success:
            logger.error(f"Key rotation coordination failed for node {node_id}: {msg}")
            return False, f"Failed to coordinate key rotation: {msg}"

        logger.info(f"Node {node_id} approved with coordinator flow: {msg}")
        return True, f"Node {node_id} approved ({msg})"
    
    # ── Node Leave Workflow ──────────────────────────────────────────────────
    
    def node_leave_request(self, node_id: str) -> tuple[bool, str]:
        """
        Process a node leave request and trigger share recalculation.
        
        Returns:
            (success, message): success flag and message
        """
        if node_id not in self._members:
            return False, f"Node {node_id} not found"
        
        if node_id == self.node_id:
            return False, "Cannot remove self from membership"
        
        # Remove member
        removed_member = self._members.pop(node_id)

        # Persist removal first to keep membership state consistent.
        self._save_state()

        success, msg = self.coordinate_membership_rekey(
            change_type="leave",
            affected_node_id=node_id,
            requester_node_id=self.node_id,
        )
        if success:
            logger.info(f"Node {node_id} removed with coordinator flow: {msg}")
            return True, f"Node {node_id} removed ({msg})"

        # Revert on coordination failure.
        self._members[node_id] = removed_member
        self._save_state()
        return False, f"Failed to coordinate key rotation: {msg}"
    
    # ── Key Rotation ─────────────────────────────────────────────────────────
    
    def _rotate_key_for_membership_change(
        self,
        change_type: str,  # "join" or "leave"
        affected_node_id: str,
    ) -> tuple[bool, str]:
        """
        Trigger key rotation due to membership change.
        
        This should be called when:
          - A new node joins the trusted group
          - A node leaves the federation
          - Membership trust levels change
        
        Returns:
            (success, message)
        """
        # Calculate new parameters
        trusted_count = len(self.get_trusted_members())
        if trusted_count < 2:
            return False, f"Not enough trusted members ({trusted_count}) for Shamir (need >= 2)"
        
        # New parameters: k = ceil(n/2 + 1) for n-of-2n-1 scheme
        new_total_shares = trusted_count
        new_threshold = max(2, (trusted_count + 1) // 2 + 1)  # Strict majority
        
        # Create new epoch
        new_epoch_number = (self._current_epoch.epoch_number + 1) if self._current_epoch else 0
        epoch_time = datetime.now(timezone.utc).isoformat()
        
        new_epoch = KeyEpoch(
            epoch_id=secrets.token_hex(8),
            epoch_number=new_epoch_number,
            created_at=epoch_time,
            created_by_node=self.node_id,
            total_shares=new_total_shares,
            threshold_shares=new_threshold,
            membership_root_hash=self._calculate_membership_hash(self._members),
        )
        
        # Archive old epoch if it exists
        if self._current_epoch:
            self._current_epoch.is_active = False
            self._current_epoch.rotated_at = epoch_time
            self._epoch_history.append(self._current_epoch)
        
        self._current_epoch = new_epoch
        self._save_state()
        
        logger.info(
            f"KEY ROTATION: {change_type} {affected_node_id}, "
            f"new epoch {new_epoch.epoch_number} ({new_total_shares} shares, k={new_threshold})"
        )
        return True, f"Key rotated to epoch {new_epoch.epoch_number} ({new_total_shares}n-{new_threshold}k)"
    
    def initiate_key_rotation(self) -> tuple[bool, str]:
        """
        Initiate an explicit key rotation (not tied to membership change).
        Can be used for scheduled rotation or security refresh.
        
        Returns:
            (success, message)
        """
        return self._rotate_key_for_membership_change("rotation", "scheduled")
    
    # ── Epoch Transition ─────────────────────────────────────────────────────
    
    def transition_to_epoch(self, epoch_data: dict) -> tuple[bool, str]:
        """
        Accept a new epoch transition from another node.
        
        Used when a remote node initiates key rotation and broadcasts
        the new epoch details to all members.
        
        Returns:
            (success, message)
        """
        new_epoch = KeyEpoch(**epoch_data)
        
        # Validate epoch
        if self._current_epoch and new_epoch.epoch_number <= self._current_epoch.epoch_number:
            return False, f"Epoch {new_epoch.epoch_number} not newer than current {self._current_epoch.epoch_number}"
        
        # Archive old epoch
        if self._current_epoch:
            self._current_epoch.is_active = False
            rotated_time = datetime.now(timezone.utc).isoformat()
            self._current_epoch.rotated_at = rotated_time
            self._epoch_history.append(self._current_epoch)
        
        self._current_epoch = new_epoch
        self._save_state()
        
        logger.info(f"Transitioned to epoch {new_epoch.epoch_number} (initiated by {new_epoch.created_by_node})")
        return True, f"Transitioned to epoch {new_epoch.epoch_number}"

    def accept_remote_epoch_transition(
        self,
        epoch_data: dict,
        source_node_id: Optional[str] = None,
    ) -> tuple[bool, str]:
        """
        Accept a remote epoch transition only if it is newer than local state.

        This method is intended for offline-node catch-up flows.
        """
        epoch_number_raw = epoch_data.get("epoch_number")
        try:
            incoming_epoch_number = int(epoch_number_raw)
        except (TypeError, ValueError):
            return False, "Invalid epoch_number in transition payload"

        if self._current_epoch and incoming_epoch_number <= self._current_epoch.epoch_number:
            return (
                False,
                (
                    "Stale epoch transition rejected: "
                    f"incoming={incoming_epoch_number}, current={self._current_epoch.epoch_number}"
                ),
            )

        expected_source = epoch_data.get("created_by_node")
        if source_node_id and expected_source and source_node_id != expected_source:
            return (
                False,
                (
                    "Epoch source mismatch: "
                    f"payload created_by_node={expected_source}, source={source_node_id}"
                ),
            )

        return self.transition_to_epoch(epoch_data)
    
    # ── Summary ──────────────────────────────────────────────────────────────
    
    def summary(self) -> dict:
        """Get membership and epoch summary."""
        return {
            "node_id": self.node_id,
            "members": {
                "total": len(self._members),
                "trusted": len(self.get_trusted_members()),
                "list": [
                    {
                        "node_id": m.node_id,
                        "hostname": m.hostname,
                        "is_trusted": m.is_trusted,
                        "joined_at": m.joined_at,
                    }
                    for m in self._members.values()
                ],
            },
            "current_epoch": self._current_epoch.to_dict() if self._current_epoch else None,
            "epoch_history_count": len(self._epoch_history),
            "coordination": self.coordination_status(),
        }
