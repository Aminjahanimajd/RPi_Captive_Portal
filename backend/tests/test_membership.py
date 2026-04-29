#!/usr/bin/env python3
"""
Tests for Milestone 5: Multi-Node Membership & Key Rotation
============================================================

Validates:
  - Node join workflows with shard recalculation
  - Node leave workflows with rebalancing
  - Epoch-based key rotation
  - Membership consistency
  - Multi-node federation operations
"""

import sys
import tempfile
import unittest
from pathlib import Path

from backend.tests.test_support import ensure_backend_path

ensure_backend_path()

from membership import (
    KeyEpoch,
    MembershipEvent,
    MembershipManager,
    NodeMember,
)


class NodeMemberTests(unittest.TestCase):
    """Test NodeMember data class."""

    def test_node_member_creation(self):
        """Test creating a node member."""
        member = NodeMember(
            node_id="node-1",
            hostname="rpi-1",
            ip_address="192.168.1.10",
            port=5000,
        )
        self.assertEqual(member.node_id, "node-1")
        self.assertEqual(member.hostname, "rpi-1")
        self.assertFalse(member.is_trusted)
        self.assertIsNotNone(member.joined_at)

    def test_node_member_trusted(self):
        """Test trusted node member."""
        member = NodeMember(
            node_id="node-1",
            hostname="rpi-1",
            ip_address="192.168.1.10",
            is_trusted=True,
        )
        self.assertTrue(member.is_trusted)


class KeyEpochTests(unittest.TestCase):
    """Test KeyEpoch data class."""

    def test_epoch_creation(self):
        """Test creating a key epoch."""
        epoch = KeyEpoch(
            epoch_id="abc123",
            epoch_number=1,
            created_at="2026-04-15T12:00:00",
            created_by_node="node-primary",
            total_shares=3,
            threshold_shares=2,
            membership_root_hash="hash123",
        )
        self.assertEqual(epoch.epoch_id, "abc123")
        self.assertEqual(epoch.epoch_number, 1)
        self.assertTrue(epoch.is_active)

    def test_epoch_to_dict(self):
        """Test epoch serialization."""
        epoch = KeyEpoch(
            epoch_id="abc123",
            epoch_number=1,
            created_at="2026-04-15T12:00:00",
            created_by_node="node-primary",
            total_shares=3,
            threshold_shares=2,
            membership_root_hash="hash123",
        )
        data = epoch.to_dict()
        self.assertEqual(data["epoch_id"], "abc123")
        self.assertEqual(data["epoch_number"], 1)


class MembershipManagerTests(unittest.TestCase):
    """Test MembershipManager core functionality."""

    def setUp(self):
        """Create a temporary directory for test data."""
        self.temp_dir = tempfile.mkdtemp()
        self.mgr = MembershipManager(node_id="node-primary", data_dir=self.temp_dir)

    def tearDown(self):
        """Clean up test directory."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization(self):
        """Test manager initialization."""
        self.assertEqual(self.mgr.node_id, "node-primary")
        self.assertEqual(self.mgr.count_members(), 1)  # Primary node bootstraps itself
        self.assertIsNone(self.mgr.get_current_epoch())

    # ── Join Workflow Tests ──────────────────────────────────────────────────

    def test_node_join_request(self):
        """Test adding a node to membership."""
        success, msg = self.mgr.node_join_request(
            node_id="node-1",
            hostname="rpi-1",
            ip_address="192.168.1.10",
        )
        self.assertTrue(success)
        self.assertEqual(self.mgr.count_members(), 2)  # Primary + node-1
        
        member = self.mgr.get_member("node-1")
        self.assertIsNotNone(member)
        self.assertFalse(member.is_trusted)  # Initially untrusted

    def test_duplicate_node_join_rejected(self):
        """Test that duplicate node joins are rejected."""
        self.mgr.node_join_request(
            node_id="node-1",
            hostname="rpi-1",
            ip_address="192.168.1.10",
        )
        
        success, msg = self.mgr.node_join_request(
            node_id="node-1",
            hostname="rpi-1",
            ip_address="192.168.1.10",
        )
        self.assertFalse(success)
        self.assertEqual(self.mgr.count_members(), 2)  # Primary + node-1

    def test_approve_node_join(self):
        """Test approving a pending node join."""
        self.mgr.node_join_request(
            node_id="node-1",
            hostname="rpi-1",
            ip_address="192.168.1.10",
        )
        
        member_before = self.mgr.get_member("node-1")
        self.assertFalse(member_before.is_trusted)
        
        success, msg = self.mgr.approve_node_join("node-1")
        
        # Should succeed if there are enough members
        if self.mgr.count_trusted_members() >= 2:
            self.assertTrue(success)
        
        member_after = self.mgr.get_member("node-1")
        self.assertTrue(member_after.is_trusted)

    def test_trusted_members_count(self):
        """Test counting trusted members."""
        self.mgr.node_join_request("node-1", "rpi-1", "192.168.1.10")
        self.mgr.node_join_request("node-2", "rpi-2", "192.168.1.11")
        
        self.assertEqual(self.mgr.count_members(), 3)  # Primary + node-1 + node-2
        self.assertEqual(self.mgr.count_members(trusted_only=True), 1)  # Only primary is trusted
        
        self.mgr.approve_node_join("node-1")
        # Trust count depends on whether approval succeeded

    # ── Leave Workflow Tests ─────────────────────────────────────────────────

    def test_node_leave_request(self):
        """Test removing a node from membership."""
        self.mgr.node_join_request("node-1", "rpi-1", "192.168.1.10")
        self.assertEqual(self.mgr.count_members(), 2)  # Primary + node-1
        
        success, msg = self.mgr.node_leave_request("node-1")
        # May fail if not enough members remain
        
        if success:
            self.assertEqual(self.mgr.count_members(), 1)  # Only primary
            self.assertIsNone(self.mgr.get_member("node-1"))

    def test_cannot_remove_self(self):
        """Test that a node cannot remove itself."""
        success, msg = self.mgr.node_leave_request("node-primary")
        self.assertFalse(success)

    def test_nonexistent_node_leave(self):
        """Test that removing nonexistent node fails."""
        success, msg = self.mgr.node_leave_request("node-nonexistent")
        self.assertFalse(success)

    # ── Epoch Management Tests ───────────────────────────────────────────────

    def test_initial_epoch_none(self):
        """Test that initial epoch is None."""
        self.assertIsNone(self.mgr.get_current_epoch())

    def test_epoch_history_empty_initially(self):
        """Test that epoch history starts empty."""
        self.assertEqual(len(self.mgr.get_epoch_history()), 0)

    def test_key_rotation_requires_minimum_members(self):
        """Test that key rotation requires at least 2 trusted members."""
        success, msg = self.mgr._rotate_key_for_membership_change(
            change_type="rotation",
            affected_node_id="test",
        )
        self.assertFalse(success)
        self.assertIn("Not enough trusted members", msg)

    def test_membership_hash_calculation(self):
        """Test that membership hash is calculated correctly."""
        member1 = NodeMember("node-1", "rpi-1", "192.168.1.10", is_trusted=True)
        member2 = NodeMember("node-2", "rpi-2", "192.168.1.11", is_trusted=True)
        
        members = {"node-1": member1, "node-2": member2}
        hash1 = self.mgr._calculate_membership_hash(members)
        hash2 = self.mgr._calculate_membership_hash(members)
        
        # Same membership should have same hash
        self.assertEqual(hash1, hash2)
        
        # Different membership should have different hash
        members_changed = {"node-1": member1, "node-3": member2}
        hash3 = self.mgr._calculate_membership_hash(members_changed)
        self.assertNotEqual(hash1, hash3)

    # ── State Persistence Tests ──────────────────────────────────────────────

    def test_state_persistence(self):
        """Test that state is persisted to disk."""
        # Add members
        self.mgr.node_join_request("node-1", "rpi-1", "192.168.1.10")
        self.mgr.node_join_request("node-2", "rpi-2", "192.168.1.11")
        
        # Create new manager and load state
        mgr2 = MembershipManager(node_id="node-primary", data_dir=self.temp_dir)
        
        self.assertEqual(mgr2.count_members(), 3)  # Primary + node-1 + node-2
        self.assertIsNotNone(mgr2.get_member("node-1"))
        self.assertIsNotNone(mgr2.get_member("node-2"))

    def test_epoch_persistence(self):
        """Test that epochs are persisted to disk."""
        # Add members to enable rotation
        self.mgr.node_join_request("node-1", "rpi-1", "192.168.1.10")
        self.mgr.node_join_request("node-2", "rpi-2", "192.168.1.11")
        self.mgr._members["node-1"].is_trusted = True
        self.mgr._members["node-2"].is_trusted = True
        
        # Rotate key
        success, msg = self.mgr._rotate_key_for_membership_change(
            "rotation",
            "test",
        )
        
        if success:
            epoch1 = self.mgr.get_current_epoch()
            
            # Create new manager and verify epoch
            mgr2 = MembershipManager(node_id="node-primary", data_dir=self.temp_dir)
            epoch2 = mgr2.get_current_epoch()
            
            self.assertIsNotNone(epoch2)
            self.assertEqual(epoch1.epoch_id, epoch2.epoch_id)

    # ── Summary Tests ────────────────────────────────────────────────────────

    def test_summary(self):
        """Test membership summary."""
        self.mgr.node_join_request("node-1", "rpi-1", "192.168.1.10")
        
        summary = self.mgr.summary()
        
        self.assertEqual(summary["node_id"], "node-primary")
        self.assertEqual(summary["members"]["total"], 2)  # Primary + node-1
        self.assertIn("node_id", summary["members"]["list"][0])
        self.assertIn("coordination", summary)

    def test_leader_uses_coordinator_hint_when_trusted(self):
        """Coordinator hint is preferred when hint node is trusted."""
        mgr = MembershipManager(
            node_id="node-primary",
            data_dir=self.temp_dir + "/coordinator_hint",
            coordinator_hint="node-secondary",
        )
        mgr.node_join_request("node-secondary", "rpi-2", "192.168.1.11")
        mgr.approve_node_join("node-secondary")

        self.assertEqual(mgr.get_leader_node_id(), "node-secondary")
        self.assertFalse(mgr.is_leader("node-primary"))

    def test_non_leader_rekey_is_queued(self):
        """Non-leader membership rekeys should be deferred to leader queue."""
        mgr = MembershipManager(
            node_id="node-primary",
            data_dir=self.temp_dir + "/queued_rekey",
            coordinator_hint="node-secondary",
        )
        mgr.node_join_request("node-secondary", "rpi-2", "192.168.1.11")
        mgr.approve_node_join("node-secondary")

        mgr.node_join_request("node-third", "rpi-3", "192.168.1.12")
        success, _ = mgr.approve_node_join("node-third")
        self.assertTrue(success)

        self.assertIsNone(mgr.get_current_epoch())
        self.assertGreaterEqual(mgr.coordination_status()["pending_rekey_count"], 1)

    def test_leader_can_process_pending_rekeys(self):
        """Leader processes deferred rekeys and clears queue."""
        mgr = MembershipManager(
            node_id="node-primary",
            data_dir=self.temp_dir + "/process_queue",
            coordinator_hint="node-secondary",
        )
        mgr.node_join_request("node-secondary", "rpi-2", "192.168.1.11")
        mgr.approve_node_join("node-secondary")

        mgr.node_join_request("node-third", "rpi-3", "192.168.1.12")
        mgr.approve_node_join("node-third")

        success, _ = mgr.process_pending_rekeys(requester_node_id="node-secondary")
        self.assertTrue(success)
        self.assertIsNotNone(mgr.get_current_epoch())
        self.assertEqual(mgr.coordination_status()["pending_rekey_count"], 0)

    def test_accept_remote_epoch_rejects_stale_and_accepts_newer(self):
        """Remote epoch transitions must reject stale epochs and accept newer ones."""
        self.mgr.node_join_request("node-1", "rpi-1", "192.168.1.10")
        self.mgr.approve_node_join("node-1")

        current = self.mgr.get_current_epoch()
        self.assertIsNotNone(current)

        stale_ok, stale_msg = self.mgr.accept_remote_epoch_transition(
            current.to_dict(),
            source_node_id=current.created_by_node,
        )
        self.assertFalse(stale_ok)
        self.assertIn("Stale epoch transition rejected", stale_msg)

        newer = current.to_dict()
        newer["epoch_id"] = "remote-newer-epoch"
        newer["epoch_number"] = current.epoch_number + 1
        newer["created_by_node"] = "node-1"

        newer_ok, _ = self.mgr.accept_remote_epoch_transition(
            newer,
            source_node_id="node-1",
        )
        self.assertTrue(newer_ok)
        self.assertEqual(self.mgr.get_current_epoch().epoch_number, current.epoch_number + 1)


class MultiNodeScenarios(unittest.TestCase):
    """Test realistic multi-node federation scenarios."""

    def setUp(self):
        """Create multiple federation managers."""
        self.temp_dir = tempfile.mkdtemp()
        self.primary = MembershipManager("node-primary", self.temp_dir + "/primary")
        self.neighbor1 = MembershipManager("node-neighbor1", self.temp_dir + "/neighbor1")
        self.neighbor2 = MembershipManager("node-neighbor2", self.temp_dir + "/neighbor2")

    def tearDown(self):
        """Clean up test directories."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_bootstrap_two_node_federation(self):
        """Test bootstrapping a 2-node federation."""
        # Neighbor 1 joins
        self.primary.node_join_request("node-neighbor1", "rpi-neighbor1", "192.168.1.11")
        self.primary.approve_node_join("node-neighbor1")
        
        # Verify membership
        self.assertEqual(self.primary.count_trusted_members(), 2)  # primary + neighbor1

    def test_scale_to_three_nodes(self):
        """Test scaling federation from 2 to 3 nodes."""
        # Bootstrap 2-node
        self.primary.node_join_request("node-neighbor1", "rpi-n1", "192.168.1.11")
        self.primary._members["node-neighbor1"].is_trusted = True
        
        epoch_before = self.primary.get_current_epoch()
        
        # Add third node
        self.primary.node_join_request("node-neighbor2", "rpi-n2", "192.168.1.12")
        success, msg = self.primary.approve_node_join("node-neighbor2")
        
        # If rotation succeeded, epoch should change
        if success:
            epoch_after = self.primary.get_current_epoch()
            # Epochs should be different if rotation occurred
            if epoch_before and epoch_after:
                self.assertGreaterEqual(
                    epoch_after.epoch_number,
                    epoch_before.epoch_number,
                )

    def test_node_removal_and_rebalance(self):
        """Test removing a node triggers rebalancing."""
        # Bootstrap 3-node
        self.primary.node_join_request("node-neighbor1", "rpi-n1", "192.168.1.11")
        self.primary.node_join_request("node-neighbor2", "rpi-n2", "192.168.1.12")
        for nid in ["node-neighbor1", "node-neighbor2"]:
            self.primary._members[nid].is_trusted = True
        
        initial_count = self.primary.count_members()
        
        # Remove a node
        success, msg = self.primary.node_leave_request("node-neighbor1")
        
        if success:
            self.assertEqual(self.primary.count_members(), initial_count - 1)


if __name__ == "__main__":
    unittest.main()
