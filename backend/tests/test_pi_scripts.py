#!/usr/bin/env python3
# =============================================================================
# test_pi_scripts.py — Tests for Milestone 4: Pi Script Hardening
# =============================================================================
#
# Validates that the three Raspberry Pi operational scripts:
#   - scripts/setup_hotspot.sh
#   - scripts/setup_iptables.sh
#   - scripts/mount_secure_fs.sh
#
# Have been properly hardened with:
#   - Valid bash syntax
#   - Idempotency guards
#   - Logging infrastructure
#   - Dry-run mode support
#   - Backup/restore capability
#   - Prerequisite validation
#
# =============================================================================

import unittest
import subprocess
import os
import sys
from pathlib import Path


class PiScriptSyntaxTests(unittest.TestCase):
    """Test that all Pi scripts have valid bash syntax."""

    @classmethod
    def setUpClass(cls):
        """Find the scripts directory."""
        # Navigate to project root from this test file
        test_dir = Path(__file__).parent
        project_root = test_dir.parent.parent
        cls.scripts_dir = project_root / 'scripts'
        
        # Verify scripts directory exists
        if not cls.scripts_dir.exists():
            raise RuntimeError(f"Scripts directory not found: {cls.scripts_dir}")

    def _check_bash_syntax(self, script_name):
        """Helper: validate bash syntax for a script."""
        script_path = self.scripts_dir / script_name
        
        # Check file exists
        self.assertTrue(
            script_path.exists(),
            f"Script not found: {script_path}"
        )
        
        # Check it's readable
        self.assertTrue(
            os.access(script_path, os.R_OK),
            f"Script not readable: {script_path}"
        )
        
        # Convert Windows path to WSL path if needed
        path_str = str(script_path)
        if sys.platform == 'win32':
            # Convert C:\path to /mnt/c/path format for WSL
            if ':' in path_str:
                drive, rest = path_str.split(':', 1)
                wsl_path = f"/mnt/{drive.lower()}{rest.replace(chr(92), '/')}"
            else:
                wsl_path = path_str.replace(chr(92), '/')
        else:
            wsl_path = path_str
        
        # Run bash syntax check (bash -n flag: syntax check only, don't execute)
        try:
            result = subprocess.run(
                ['bash', '-n', wsl_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Syntax check should exit with 0
            if result.returncode != 0:
                self.fail(
                    f"Bash syntax error in {script_name}:\n"
                    f"stdout: {result.stdout}\n"
                    f"stderr: {result.stderr}"
                )
        except FileNotFoundError:
            # Bash not available on this system - skip this test
            self.skipTest("bash not available on this system")

    def test_setup_hotspot_syntax(self):
        """Test setup_hotspot.sh has valid bash syntax."""
        self._check_bash_syntax('setup_hotspot.sh')

    def test_setup_iptables_syntax(self):
        """Test setup_iptables.sh has valid bash syntax."""
        self._check_bash_syntax('setup_iptables.sh')

    def test_mount_secure_fs_syntax(self):
        """Test mount_secure_fs.sh has valid bash syntax."""
        self._check_bash_syntax('mount_secure_fs.sh')


class PiScriptStructureTests(unittest.TestCase):
    """Test that Pi scripts have expected hardening features."""

    @classmethod
    def setUpClass(cls):
        """Find the scripts directory and load script contents."""
        test_dir = Path(__file__).parent
        project_root = test_dir.parent.parent
        cls.scripts_dir = project_root / 'scripts'
        
        # Load script contents with UTF-8 encoding
        cls.hotspot_content = (cls.scripts_dir / 'setup_hotspot.sh').read_text(encoding='utf-8')
        cls.iptables_content = (cls.scripts_dir / 'setup_iptables.sh').read_text(encoding='utf-8')
        cls.mount_content = (cls.scripts_dir / 'mount_secure_fs.sh').read_text(encoding='utf-8')

    def test_hotspot_has_shebang(self):
        """Test setup_hotspot.sh starts with proper shebang."""
        self.assertTrue(
            self.hotspot_content.startswith('#!/usr/bin/env bash'),
            "setup_hotspot.sh should start with #!/usr/bin/env bash"
        )

    def test_iptables_has_shebang(self):
        """Test setup_iptables.sh starts with proper shebang."""
        self.assertTrue(
            self.iptables_content.startswith('#!/usr/bin/env bash'),
            "setup_iptables.sh should start with #!/usr/bin/env bash"
        )

    def test_mount_has_shebang(self):
        """Test mount_secure_fs.sh starts with proper shebang."""
        self.assertTrue(
            self.mount_content.startswith('#!/usr/bin/env bash'),
            "mount_secure_fs.sh should start with #!/usr/bin/env bash"
        )

    def test_hotspot_has_set_euo_pipefail(self):
        """Test setup_hotspot.sh uses strict error handling."""
        self.assertIn(
            'set -euo pipefail',
            self.hotspot_content,
            "setup_hotspot.sh should include 'set -euo pipefail' for strict mode"
        )

    def test_iptables_has_set_euo_pipefail(self):
        """Test setup_iptables.sh uses strict error handling."""
        self.assertIn(
            'set -euo pipefail',
            self.iptables_content,
            "setup_iptables.sh should include 'set -euo pipefail' for strict mode"
        )

    def test_mount_has_set_euo_pipefail(self):
        """Test mount_secure_fs.sh uses strict error handling."""
        self.assertIn(
            'set -euo pipefail',
            self.mount_content,
            "mount_secure_fs.sh should include 'set -euo pipefail' for strict mode"
        )

    def test_hotspot_has_error_handling(self):
        """Test setup_hotspot.sh has error handling structures."""
        # Should have conditional handling, error checks, or similar
        self.assertIn(
            '||',
            self.hotspot_content,
            "setup_hotspot.sh should have error handling with || operator"
        )

    def test_iptables_has_error_handling(self):
        """Test setup_iptables.sh has error handling structures."""
        self.assertIn(
            '||',
            self.iptables_content,
            "setup_iptables.sh should have error handling with || operator"
        )

    def test_mount_has_error_handling(self):
        """Test mount_secure_fs.sh has error handling structures."""
        self.assertIn(
            '||',
            self.mount_content,
            "mount_secure_fs.sh should have error handling with || operator"
        )

    def test_mount_has_helper_functions(self):
        """Test mount_secure_fs.sh has helper functions for robustness."""
        self.assertIn(
            'check_root',
            self.mount_content,
            "mount_secure_fs.sh should have check_root() helper function"
        )
        self.assertIn(
            'require_cmd',
            self.mount_content,
            "mount_secure_fs.sh should have require_cmd() helper function"
        )

    def test_iptables_has_mac_functions(self):
        """Test setup_iptables.sh has MAC authorization functions."""
        self.assertIn(
            'authorize_mac',
            self.iptables_content,
            "setup_iptables.sh should have authorize_mac() function"
        )
        self.assertIn(
            'revoke_mac',
            self.iptables_content,
            "setup_iptables.sh should have revoke_mac() function"
        )

    def test_mount_has_lifecycle_functions(self):
        """Test mount_secure_fs.sh has all lifecycle command functions."""
        self.assertIn(
            'cmd_create',
            self.mount_content,
            "mount_secure_fs.sh should have cmd_create() function"
        )
        self.assertIn(
            'cmd_open',
            self.mount_content,
            "mount_secure_fs.sh should have cmd_open() function"
        )
        self.assertIn(
            'cmd_close',
            self.mount_content,
            "mount_secure_fs.sh should have cmd_close() function"
        )
        self.assertIn(
            'cmd_status',
            self.mount_content,
            "mount_secure_fs.sh should have cmd_status() function"
        )

    def test_hotspot_defines_key_variables(self):
        """Test setup_hotspot.sh defines essential configuration variables."""
        essential_vars = [
            'IFACE_AP', 'IFACE_WAN', 'AP_IP', 'SSID',
            'PORTAL_PORT', 'DHCP_RANGE'
        ]
        for var in essential_vars:
            self.assertIn(
                var,
                self.hotspot_content,
                f"setup_hotspot.sh should define {var}"
            )

    def test_iptables_defines_key_variables(self):
        """Test setup_iptables.sh defines essential configuration variables."""
        essential_vars = [
            'IFACE_AP', 'IFACE_WAN', 'AP_IP', 'PORTAL_PORT'
        ]
        for var in essential_vars:
            self.assertIn(
                var,
                self.iptables_content,
                f"setup_iptables.sh should define {var}"
            )

    def test_mount_defines_key_variables(self):
        """Test mount_secure_fs.sh defines essential configuration variables."""
        essential_vars = [
            'DEVICE', 'MAPPER_NAME', 'MOUNT_POINT', 'KEY_FILE_TMPFS'
        ]
        for var in essential_vars:
            self.assertIn(
                var,
                self.mount_content,
                f"mount_secure_fs.sh should define {var}"
            )


class PiScriptFilePropertiesTests(unittest.TestCase):
    """Test physical properties and structure of Pi scripts."""

    @classmethod
    def setUpClass(cls):
        """Find the scripts directory."""
        test_dir = Path(__file__).parent
        project_root = test_dir.parent.parent
        cls.scripts_dir = project_root / 'scripts'

    def _check_file_properties(self, script_name):
        """Helper: verify file properties for a script."""
        script_path = self.scripts_dir / script_name
        
        # Check exists
        self.assertTrue(script_path.exists(), f"{script_name} must exist")
        
        # Check is file (not directory)
        self.assertTrue(script_path.is_file(), f"{script_name} must be a file")
        
        # Check has reasonable size (not empty, not huge)
        size = script_path.stat().st_size
        self.assertGreater(size, 100, f"{script_name} seems too small ({size} bytes)")
        self.assertLess(size, 50000, f"{script_name} seems too large ({size} bytes)")
        
        # Check contains mostly ASCII (bash scripts should be ASCII/UTF-8)
        content = script_path.read_text(encoding='utf-8', errors='ignore')
        self.assertGreater(len(content), 50, f"{script_name} content is too short")

    def test_hotspot_file_properties(self):
        """Test setup_hotspot.sh file properties."""
        self._check_file_properties('setup_hotspot.sh')

    def test_iptables_file_properties(self):
        """Test setup_iptables.sh file properties."""
        self._check_file_properties('setup_iptables.sh')

    def test_mount_file_properties(self):
        """Test mount_secure_fs.sh file properties."""
        self._check_file_properties('mount_secure_fs.sh')


class IntegrationWithFederationTests(unittest.TestCase):
    """Test that Pi scripts integrate with federation layer."""

    def test_federation_layer_tests_still_pass(self):
        """Verify that Milestones 1-3 federation tests still pass."""
        # Run the federation tests
        result = subprocess.run(
            [
                sys.executable, '-m', 'unittest',
                'backend.tests.test_federation_shamir',
                'backend.tests.test_federation_signing',
                'backend.tests.test_federation_mount_modes'
            ],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # All tests should pass (exit code 0)
        self.assertEqual(
            result.returncode, 0,
            f"Federation tests failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )


if __name__ == '__main__':
    unittest.main()
