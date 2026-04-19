import base64
import tempfile
import unittest
from backend.tests.test_support import ensure_backend_path

ensure_backend_path()

from federation import FederationAgent, _recover_secret_shamir


class FederationShamirTests(unittest.TestCase):
    def _make_agent(self) -> FederationAgent:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        agent = FederationAgent(
            node_id="node-test",
            data_dir=temp_dir.name,
            neighbor_addresses=["node-a:5000", "node-b:5000", "node-c:5000", "node-d:5000"],
        )
        # Avoid side effects in tests when reconstruction succeeds.
        agent._mount_secure_partition = lambda: setattr(agent, "_is_mounted", True)
        return agent

    def test_recover_secret_with_exact_threshold(self):
        agent = self._make_agent()
        known_key = bytes(range(32))
        agent._master_key = known_key

        bundle = agent.generate_and_distribute_shards(n_nodes=5, threshold_k=3)
        shares = bundle["shares"]

        selected = []
        for x in (1, 3, 5):
            selected.append((x, base64.b64decode(shares[str(x)])))

        recovered = _recover_secret_shamir(selected, threshold_k=3)
        self.assertEqual(known_key, recovered)

    def test_reject_reconstruction_below_threshold(self):
        agent = self._make_agent()
        original_key = bytes([42] * 32)
        agent._master_key = original_key

        bundle = agent.generate_and_distribute_shards(n_nodes=5, threshold_k=4)
        shares = bundle["shares"]
        epoch = bundle["epoch_id"]

        # Simulate a fresh boot where only local shard exists initially.
        agent._master_key = None
        agent._is_mounted = False

        # Provide only 2 remote shares => total unique shares = 3 (< k=4)
        agent.receive_shard("node-a", shares["2"], share_x=2, epoch_id=epoch)
        agent.receive_shard("node-b", shares["3"], share_x=3, epoch_id=epoch)

        self.assertIsNone(agent._master_key)
        self.assertFalse(agent._is_mounted)

    def test_reconstruct_when_threshold_reached(self):
        agent = self._make_agent()
        original_key = bytes([99] * 32)
        agent._master_key = original_key

        bundle = agent.generate_and_distribute_shards(n_nodes=5, threshold_k=4)
        shares = bundle["shares"]
        epoch = bundle["epoch_id"]

        # Simulate a fresh boot where key is not loaded yet.
        agent._master_key = None
        agent._is_mounted = False

        # local share(1) + these 3 shares = 4 total => should reconstruct.
        agent.receive_shard("node-a", shares["2"], share_x=2, epoch_id=epoch)
        agent.receive_shard("node-b", shares["3"], share_x=3, epoch_id=epoch)
        agent.receive_shard("node-c", shares["4"], share_x=4, epoch_id=epoch)

        self.assertEqual(original_key, agent._master_key)
        self.assertTrue(agent._is_mounted)

    def test_apply_catchup_payload_sets_latest_epoch_and_assignment(self):
        agent = self._make_agent()

        payload = {
            "epoch_id": "epoch-catchup-1",
            "threshold_k": 3,
            "total_shares_n": 5,
            "assigned_share_x": 2,
            "assigned_share": base64.b64encode(bytes([1] * 32)).decode("ascii"),
        }

        ok, msg = agent.apply_catchup_payload(payload)
        self.assertTrue(ok, msg)

        status = agent.get_status()
        self.assertEqual(status["share_epoch"], "epoch-catchup-1")
        self.assertEqual(status["threshold_k"], 3)
        self.assertEqual(status["total_shares_n"], 5)

    def test_apply_catchup_payload_rejects_invalid_assignment(self):
        agent = self._make_agent()
        payload = {
            "epoch_id": "epoch-catchup-2",
            "threshold_k": 3,
            "total_shares_n": 5,
            "assigned_share_x": 6,
            "assigned_share": base64.b64encode(bytes([2] * 32)).decode("ascii"),
        }

        ok, msg = agent.apply_catchup_payload(payload)
        self.assertFalse(ok)
        self.assertIn("invalid assigned_share_x", msg)


if __name__ == "__main__":
    unittest.main()
