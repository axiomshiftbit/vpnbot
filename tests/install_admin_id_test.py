#!/usr/bin/env python3
"""WEB-01: init.sh sets the bot owner at installation (VPNBOT_ADMIN_ID)."""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('bash'), 'нужен bash')
class InstallAdminIdTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.source = (ROOT / 'scripts/init.sh').read_text()
        function = re.search(r'^normalize_admin_id\(\) \{.*?^\}\n', self.source, re.M | re.S).group()
        self.script = self.tmp / 'run.sh'
        self.script.write_text('set -euo pipefail\n' + function + 'normalize_admin_id\nprintf "%s" "${ADMIN_ID:-}"\n')
        (self.tmp / 'install/app').mkdir(parents=True)

    def run_id(self, value=None):
        env = {'PATH': '/usr/bin:/bin', 'INSTALL_DIR': str(self.tmp / 'install')}
        if value is not None:
            env['VPNBOT_ADMIN_ID'] = value
        return subprocess.run(['bash', str(self.script)], env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True)

    def test_new_installation_requires_a_numeric_owner_id(self):
        for value in (None, '', 'abc', '0123', '12 34x', '-5', '1' * 17, "1;system('id')"):
            with self.subTest(value=value):
                result = self.run_id(value)
                self.assertEqual(1, result.returncode)
                self.assertIn('VPNBOT_ADMIN_ID', result.stderr)
        for value, expected in (('123456789', '123456789'), (' 987654321\r\n', '987654321')):
            with self.subTest(value=value):
                result = self.run_id(value)
                self.assertEqual((0, expected), (result.returncode, result.stdout), result.stderr)

    def test_existing_config_keeps_its_owner(self):
        (self.tmp / 'install/app/config.php').write_text("<?php $c = ['key' => 'SYNTHETIC', 'admin' => [1]];\n")
        result = self.run_id()
        self.assertEqual(0, result.returncode, result.stderr)

    def test_config_php_is_written_with_the_owner_and_validation_runs_before_changes(self):
        self.assertIn("\\$c = ['key' => '$KEY', 'admin' => [$ADMIN_ID]];", self.source)
        self.assertIn('if [ "$MODE" = full ]; then normalize_bot_key; normalize_admin_id; fi', self.source)
        self.assertLess(self.source.index('normalize_bot_key; normalize_admin_id'), self.source.index('install_from_git\nfi'))


if __name__ == '__main__':
    unittest.main()
