import tempfile
import unittest
import base64
from pathlib import Path
from backend.tests.test_support import ensure_backend_path

ensure_backend_path()

import app as app_module
from federation import FederationAgent
from membership import MembershipManager


class AppMembershipApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.db_path = str(Path(self.temp_dir.name) / "portal.db")
        self.membership_dir = str(Path(self.temp_dir.name) / "membership")
        self.federation_dir = str(Path(self.temp_dir.name) / "federation")

        app_module.app.config["TESTING"] = True
        app_module.DATABASE = self.db_path
        app_module.federation = FederationAgent(
            node_id=app_module.NODE_ID,
            data_dir=self.federation_dir,
            neighbor_addresses=[],
        )
        app_module.membership = MembershipManager(
            node_id=app_module.NODE_ID,
            data_dir=self.membership_dir,
        )

        app_module.init_db()
        self.client = app_module.app.test_client()

        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin"
            sess["role"] = "admin"

    def _prepare_authorized_admin_device(self, mac_address: str = "AA:BB:CC:DD:EE:FF") -> None:
        with app_module.app.app_context():
            db = app_module.get_db()
            db.execute("UPDATE users SET mac_address = ? WHERE id = 1", (mac_address,))
            db.execute(
                """INSERT INTO devices (mac_address, hostname, ip_address, user_id, is_authorized)
                   VALUES (?, ?, ?, ?, 1)
                   ON CONFLICT(mac_address) DO UPDATE SET
                       hostname = excluded.hostname,
                       ip_address = excluded.ip_address,
                       user_id = excluded.user_id,
                       is_authorized = 1,
                       last_seen = CURRENT_TIMESTAMP""",
                (mac_address, "admin-device", "10.0.0.10", 1),
            )
            db.commit()

    def test_add_node_creates_pending_membership_entry(self):
        resp = self.client.post(
            "/admin/nodes",
            json={
                "node_id": "node-a",
                "hostname": "rpi-a",
                "ip_address": "10.0.0.2",
                "port": 5000,
            },
        )
        self.assertEqual(resp.status_code, 200)

        member = app_module.membership.get_member("node-a")
        self.assertIsNotNone(member)
        self.assertFalse(member.is_trusted)

    def test_toggle_trust_promotes_and_demotes_membership(self):
        self.client.post(
            "/admin/nodes",
            json={
                "node_id": "node-b",
                "hostname": "rpi-b",
                "ip_address": "10.0.0.3",
                "port": 5000,
            },
        )

        trust_resp = self.client.post("/admin/nodes/node-b/trust")
        self.assertEqual(trust_resp.status_code, 200)
        self.assertEqual(trust_resp.get_json()["is_trusted"], 1)

        member = app_module.membership.get_member("node-b")
        self.assertIsNotNone(member)
        self.assertTrue(member.is_trusted)

        untrust_resp = self.client.post("/admin/nodes/node-b/trust")
        self.assertEqual(untrust_resp.status_code, 200)
        self.assertEqual(untrust_resp.get_json()["is_trusted"], 0)

        member_after = app_module.membership.get_member("node-b")
        self.assertIsNone(member_after)

    def test_delete_node_removes_membership_entry(self):
        self.client.post(
            "/admin/nodes",
            json={
                "node_id": "node-c",
                "hostname": "rpi-c",
                "ip_address": "10.0.0.4",
                "port": 5000,
            },
        )

        del_resp = self.client.post("/admin/nodes/node-c/delete")
        self.assertEqual(del_resp.status_code, 200)
        self.assertEqual(del_resp.get_json()["status"], "ok")

        self.assertIsNone(app_module.membership.get_member("node-c"))

    def test_admin_membership_status_endpoint(self):
        self.client.post(
            "/admin/nodes",
            json={
                "node_id": "node-d",
                "hostname": "rpi-d",
                "ip_address": "10.0.0.5",
                "port": 5000,
            },
        )
        self.client.post("/admin/nodes/node-d/trust")

        resp = self.client.get("/admin/membership")
        self.assertEqual(resp.status_code, 200)

        payload = resp.get_json()
        self.assertIn("members", payload)
        self.assertIn("current_epoch", payload)
        self.assertGreaterEqual(payload["members"]["trusted"], 2)

    def test_admin_membership_epochs_endpoint(self):
        self.client.post(
            "/admin/nodes",
            json={
                "node_id": "node-e",
                "hostname": "rpi-e",
                "ip_address": "10.0.0.6",
                "port": 5000,
            },
        )
        self.client.post("/admin/nodes/node-e/trust")

        resp = self.client.get("/admin/membership/epochs")
        self.assertEqual(resp.status_code, 200)

        payload = resp.get_json()
        self.assertIn("current_epoch", payload)
        self.assertIn("epoch_history", payload)
        self.assertIn("epoch_history_count", payload)

        self.assertIsNotNone(payload["current_epoch"])
        self.assertGreaterEqual(payload["current_epoch"]["epoch_number"], 0)

    def test_admin_membership_leader_endpoint(self):
        resp = self.client.get("/admin/membership/leader")
        self.assertEqual(resp.status_code, 200)

        payload = resp.get_json()
        self.assertIn("leader_node_id", payload)
        self.assertIn("is_local_leader", payload)
        self.assertIn("pending_rekey_count", payload)

    def test_admin_membership_rekey_process_pending_requires_leader(self):
        app_module.membership = MembershipManager(
            node_id=app_module.NODE_ID,
            data_dir=self.membership_dir,
            coordinator_hint="node-z",
        )

        self.client.post(
            "/admin/nodes",
            json={
                "node_id": "node-z",
                "hostname": "rpi-z",
                "ip_address": "10.0.0.9",
                "port": 5000,
            },
        )
        self.client.post("/admin/nodes/node-z/trust")

        self.client.post(
            "/admin/nodes",
            json={
                "node_id": "node-f",
                "hostname": "rpi-f",
                "ip_address": "10.0.0.10",
                "port": 5000,
            },
        )
        self.client.post("/admin/nodes/node-f/trust")

        resp = self.client.post("/admin/membership/rekey", json={"process_pending": True})
        self.assertEqual(resp.status_code, 409)
        self.assertIn("error", resp.get_json())

    def test_admin_membership_catchup_applies_remote_state(self):
        epoch_payload = {
            "epoch_id": "remote-epoch-1",
            "epoch_number": 1,
            "created_at": "2026-04-19T10:00:00+00:00",
            "created_by_node": "node-remote",
            "total_shares": 3,
            "threshold_shares": 2,
            "membership_root_hash": "abcd1234",
            "is_active": True,
            "rotated_at": None,
        }
        federation_payload = {
            "epoch_id": "remote-epoch-1",
            "threshold_k": 2,
            "total_shares_n": 3,
            "assigned_share_x": 2,
            "assigned_share": base64.b64encode(bytes([3] * 32)).decode("ascii"),
        }

        resp = self.client.post(
            "/admin/membership/catchup",
            json={
                "source_node_id": "node-remote",
                "epoch": epoch_payload,
                "federation": federation_payload,
            },
        )
        self.assertEqual(resp.status_code, 200)

        payload = resp.get_json()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["membership"]["current_epoch"]["epoch_id"], "remote-epoch-1")
        self.assertEqual(payload["federation"]["share_epoch"], "remote-epoch-1")

    def test_admin_membership_catchup_rejects_stale_epoch(self):
        epoch_payload = {
            "epoch_id": "remote-epoch-2",
            "epoch_number": 2,
            "created_at": "2026-04-19T11:00:00+00:00",
            "created_by_node": "node-remote",
            "total_shares": 3,
            "threshold_shares": 2,
            "membership_root_hash": "dcba4321",
            "is_active": True,
            "rotated_at": None,
        }
        federation_payload = {
            "epoch_id": "remote-epoch-2",
            "threshold_k": 2,
            "total_shares_n": 3,
            "assigned_share_x": 2,
            "assigned_share": base64.b64encode(bytes([4] * 32)).decode("ascii"),
        }

        first = self.client.post(
            "/admin/membership/catchup",
            json={
                "source_node_id": "node-remote",
                "epoch": epoch_payload,
                "federation": federation_payload,
            },
        )
        self.assertEqual(first.status_code, 200)

        second = self.client.post(
            "/admin/membership/catchup",
            json={
                "source_node_id": "node-remote",
                "epoch": epoch_payload,
                "federation": federation_payload,
            },
        )
        self.assertEqual(second.status_code, 409)

    def test_dashboard_redirects_when_session_user_is_missing(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = 999
            sess["username"] = "ghost"
            sess["role"] = "user"

        resp = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/portal", resp.headers["Location"])

    def test_federation_catchup_endpoint_returns_epoch_and_share(self):
        old_unsigned = app_module.FEDERATION_ALLOW_UNSIGNED
        app_module.FEDERATION_ALLOW_UNSIGNED = True
        self.addCleanup(setattr, app_module, "FEDERATION_ALLOW_UNSIGNED", old_unsigned)

        self.client.post(
            "/admin/nodes",
            json={
                "node_id": "node-catchup",
                "hostname": "rpi-catchup",
                "ip_address": "10.0.0.11",
                "port": 5000,
            },
        )
        self.client.post("/admin/nodes/node-catchup/trust")

        resp = self.client.post("/federation/catchup", json={"node_id": "node-catchup"})
        self.assertEqual(resp.status_code, 200)
        payload = resp.get_json()
        self.assertIn("epoch", payload)
        self.assertIn("federation", payload)
        self.assertEqual(payload["source_node_id"], app_module.NODE_ID)

    def test_admin_federation_neighbors_endpoint(self):
        app_module.federation.neighbor_addresses = ["n1:5000", "n2:5000"]
        app_module.federation._record_neighbor_attempt("n1:5000", success=True, latency_ms=15)
        app_module.federation._record_neighbor_attempt("n2:5000", success=False, latency_ms=200, error="timeout")

        resp = self.client.get("/admin/federation/neighbors")
        self.assertEqual(resp.status_code, 200)

        payload = resp.get_json()
        self.assertIn("neighbors", payload)
        self.assertIn("ranked_neighbors", payload)
        self.assertEqual(len(payload["neighbors"]), 2)

    def test_federation_request_shard_rejects_transitive_trust_hint(self):
        old_unsigned = app_module.FEDERATION_ALLOW_UNSIGNED
        app_module.FEDERATION_ALLOW_UNSIGNED = True
        self.addCleanup(setattr, app_module, "FEDERATION_ALLOW_UNSIGNED", old_unsigned)

        self.client.post(
            "/admin/nodes",
            json={
                "node_id": "node-direct",
                "hostname": "rpi-direct",
                "ip_address": "10.0.0.12",
                "port": 5000,
            },
        )
        self.client.post("/admin/nodes/node-direct/trust")

        resp = self.client.post(
            "/federation/request-shard",
            json={
                "node_id": "node-direct",
                "via_node": "proxy-node",
            },
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Direct trust only", resp.get_json()["error"])

    def test_admin_graph_endpoint_contract(self):
        self.client.post(
            "/admin/nodes",
            json={
                "node_id": "node-graph",
                "hostname": "rpi-graph",
                "ip_address": "10.0.0.13",
                "port": 5000,
            },
        )
        self.client.post("/admin/nodes/node-graph/trust")

        resp = self.client.get("/admin/graph")
        self.assertEqual(resp.status_code, 200)

        payload = resp.get_json()
        self.assertIn("graph", payload)
        self.assertIn("summary", payload)
        self.assertIn("generated_at", payload)
        self.assertIn("nodes", payload["graph"])
        self.assertIn("edges", payload["graph"])

    def test_status_includes_runtime_profile(self):
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        payload = resp.get_json()
        self.assertIn("runtime_profile", payload)
        self.assertTrue(payload["runtime_profile"])
        self.assertIn("security_state", payload)

    def test_secure_files_are_locked_without_trusted_peer(self):
        self._prepare_authorized_admin_device()

        resp = self.client.get("/api/files")
        self.assertEqual(resp.status_code, 503)
        self.assertIn("locked", resp.get_json()["error"].lower())

    def test_secure_state_becomes_ready_after_trusted_peer_and_shards(self):
        self.client.post(
            "/admin/nodes",
            json={
                "node_id": "node-ready",
                "hostname": "rpi-ready",
                "ip_address": "10.0.0.14",
                "port": 5000,
            },
        )
        self.client.post("/admin/nodes/node-ready/trust")
        app_module.federation.generate_and_distribute_shards(n_nodes=2, threshold_k=2)
        app_module.federation._received_shards = {
            "node-ready": (1, bytes([3] * 32), None)
        }
        app_module.federation._is_mounted = True
        app_module.federation._mount_backend = "simulation"
        app_module.federation._initialize_secure_store()
        self._prepare_authorized_admin_device()

        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        payload = resp.get_json()
        self.assertTrue(payload["security_state"]["is_ready"])


if __name__ == "__main__":
    unittest.main()
