import os
import unittest
from backend.tests.test_support import ensure_backend_path

ensure_backend_path()

from runtime_profile import load_runtime_profile


class RuntimeProfileTests(unittest.TestCase):
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

    def test_linux_profile_applies_expected_defaults(self):
        self._with_env(
            RUNTIME_PROFILE="linux-rpi-venv",
            DATA_DIR=None,
            DATABASE=None,
            FEDERATION_MOUNT_MODE=None,
            ALLOW_SIMULATION_FALLBACK=None,
        )

        profile = load_runtime_profile()

        self.assertEqual(profile, "linux-rpi-venv")
        self.assertEqual(os.environ["DATA_DIR"], "/var/lib/captive-portal")
        self.assertEqual(os.environ["DATABASE"], "/var/lib/captive-portal/db/portal.db")
        self.assertEqual(os.environ["FEDERATION_MOUNT_MODE"], "auto")
        self.assertEqual(os.environ["ALLOW_SIMULATION_FALLBACK"], "0")

    def test_unknown_profile_is_preserved(self):
        self._with_env(RUNTIME_PROFILE="custom-profile")
        profile = load_runtime_profile()
        self.assertEqual(profile, "custom-profile")
        self.assertEqual(os.environ["RUNTIME_PROFILE"], "custom-profile")


if __name__ == "__main__":
    unittest.main()
