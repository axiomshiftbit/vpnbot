import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('hot_privacy', Path(__file__).resolve().parents[1] / 'scripts/xray_hot_apply.py')
hot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hot)


class HotPrivacyTest(unittest.TestCase):
    def setUp(self):
        mask = hot.os.umask(0o077)
        self.addCleanup(hot.os.umask, mask)

    def test_failure_reason_excludes_command_arguments_and_input(self):
        marker = 'private-fixture@example.test'
        errors = [subprocess.TimeoutExpired(['xray', 'api', 'statsonline', '-email', marker], 8),
                  subprocess.CalledProcessError(1, ['xray', marker]), KeyError(marker)]
        for error in errors:
            with self.subTest(kind=type(error).__name__), tempfile.TemporaryDirectory() as directory:
                output = io.StringIO()
                with patch.object(hot, 'STATE', Path(directory)), patch.object(hot.os, 'geteuid', return_value=0), \
                     patch.object(hot, 'private_dir'), patch.object(hot, 'mark', side_effect=error), \
                     patch('sys.argv', ['hot', 'mark', '--pid', '1']), contextlib.redirect_stdout(output):
                    self.assertEqual(hot.main(), 1)
                self.assertEqual(output.getvalue(), 'RESTART\n')
                reason = (Path(directory) / 'last-reason').read_text()
                self.assertNotIn(marker, reason)
                self.assertIn(type(error).__name__, reason)


if __name__ == '__main__':
    unittest.main()
