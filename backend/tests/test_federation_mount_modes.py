import os
import tempfile
import unittest
from backend.tests.test_support import ensure_backend_path

ensure_backend_path()

from federation import FederationAgent


class FederationMountModeTests(unittest.TestCase):
    def _with_env(self, **updates):
        old = {k: os.environ.get(k) for k in updates}
        for key, value in updates.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = str(value)

        def restore():
            for key, prev in old.items():
                if prev is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = prev

        self.addCleanup(restore)

    def _make_agent(self) -> FederationAgent:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        return FederationAgent(
            node_id="node-mount-test",
            data_dir=temp_dir.name,
            neighbor_addresses=[],
        )

    def test_auto_mode_uses_simulation_when_luks_not_available(self):
        self._with_env(
            FEDERATION_MOUNT_MODE="auto",
            LUKS_MOUNT_SCRIPT="/definitely/missing/mount_secure_fs.sh",
            ALLOW_SIMULATION_FALLBACK="1",
        )
        agent = self._make_agent()
        agent._master_key = bytes([7] * 32)

        agent._mount_secure_partition()

        self.assertTrue(agent._is_mounted)
        self.assertEqual("simulation", agent._mount_backend)

    def test_luks_mode_fails_without_script_when_fallback_disabled(self):
        self._with_env(
            FEDERATION_MOUNT_MODE="luks",
            LUKS_MOUNT_SCRIPT="/definitely/missing/mount_secure_fs.sh",
            ALLOW_SIMULATION_FALLBACK="0",
        )
        agent = self._make_agent()
        agent._master_key = bytes([8] * 32)

        agent._mount_secure_partition()

        self.assertFalse(agent._is_mounted)
        self.assertEqual("none", agent._mount_backend)


if __name__ == "__main__":
    unittest.main()
