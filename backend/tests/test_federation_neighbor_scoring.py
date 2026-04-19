import sys
import tempfile
import unittest
from pathlib import Path

# Allow importing backend/federation.py as a module.
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from federation import FederationAgent


class FederationNeighborScoringTests(unittest.TestCase):
    def _make_agent(self) -> FederationAgent:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        return FederationAgent(
            node_id="node-score-test",
            data_dir=temp_dir.name,
            neighbor_addresses=["n1:5000", "n2:5000", "n3:5000"],
        )

    def test_ranked_neighbors_prefers_successful_low_latency_nodes(self):
        agent = self._make_agent()

        # n1: strong reliability + low latency
        for _ in range(4):
            agent._record_neighbor_attempt("n1:5000", success=True, latency_ms=20)

        # n2: mixed reliability
        agent._record_neighbor_attempt("n2:5000", success=True, latency_ms=80)
        agent._record_neighbor_attempt("n2:5000", success=False, latency_ms=120, error="timeout")

        # n3: mostly failing + high latency
        agent._record_neighbor_attempt("n3:5000", success=False, latency_ms=900, error="connection")
        agent._record_neighbor_attempt("n3:5000", success=False, latency_ms=1100, error="connection")

        ranked = agent.get_ranked_neighbors()
        self.assertEqual(ranked[0], "n1:5000")
        self.assertEqual(ranked[-1], "n3:5000")

    def test_neighbor_diagnostics_contains_rank_and_score(self):
        agent = self._make_agent()
        agent._record_neighbor_attempt("n1:5000", success=True, latency_ms=10)

        diagnostics = agent.get_neighbor_diagnostics()
        self.assertEqual(len(diagnostics), 3)
        self.assertIn("neighbor", diagnostics[0])
        self.assertIn("rank", diagnostics[0])
        self.assertIn("score", diagnostics[0])


if __name__ == "__main__":
    unittest.main()
