#!/usr/bin/env python3
"""init.sh: проверка ключа бота до записи config.php (чистая установка)."""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEY = '1234567890:AAH' + 'x' * 32
CURL = '''#!/bin/sh
printf '%s\\n' "$*" > "$LOG.args"
cat > "$LOG.stdin"
[ "$MODE" = offline ] && exit 6
case "$MODE" in ok) echo '{"ok":true,"result":{"id":1}}' ;; *) echo '{"ok":false,"error_code":401,"description":"Unauthorized"}' ;; esac
'''


@unittest.skipUnless(shutil.which('bash'), 'нужен bash')
class InstallBotKeyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        source = (ROOT / 'scripts/init.sh').read_text()
        functions = re.search(r'^normalize_bot_key\(\) \{.*?^check_bot_key\(\) \{.*?^\}\n', source, re.M | re.S).group()
        (self.tmp / 'bin').mkdir()
        (self.tmp / 'bin/curl').write_text(CURL); (self.tmp / 'bin/curl').chmod(0o755)
        self.script = self.tmp / 'run.sh'
        self.script.write_text('set -euo pipefail\nKEY=$VPNBOT_KEY\n' + functions
                               + 'normalize_bot_key\ncheck_bot_key\nprintf "%s" "$KEY" > "$LOG.key"\n')

    def run_key(self, key, mode):
        env = {'PATH': f'{self.tmp}/bin:/usr/bin:/bin', 'VPNBOT_KEY': key, 'MODE': mode, 'LOG': str(self.tmp / 'curl')}
        return subprocess.run(['bash', str(self.script)], env=env, capture_output=True, text=True)

    def test_accepted_key_is_normalized_and_never_in_arguments(self):
        result = self.run_key(' ' + KEY + '\r\n', 'ok')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(KEY, (self.tmp / 'curl.key').read_text(), 'пробелы и \\r убраны')
        self.assertNotIn(KEY, (self.tmp / 'curl.args').read_text(), 'ключ не в аргументах curl (виден в ps)')
        self.assertIn(f'bot{KEY}/getMe', (self.tmp / 'curl.stdin').read_text())
        self.assertNotIn(KEY, result.stdout + result.stderr)

    def test_rejected_key_stops_install_without_printing_it(self):
        result = self.run_key(KEY, 'unauthorized')
        self.assertEqual(1, result.returncode)
        self.assertIn('401', result.stderr)
        self.assertFalse((self.tmp / 'curl.key').exists(), 'config.php не пишется')
        self.assertNotIn(KEY, result.stdout + result.stderr)

    def test_unreachable_telegram_only_warns(self):
        result = self.run_key(KEY, 'offline')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('WARN', result.stderr)
        self.assertNotIn(KEY, result.stdout + result.stderr)

    def test_malformed_key_rejected_before_any_request(self):
        for bad in ("123:AA'x;system('id');//" + 'x' * 30, 'AAH' + 'x' * 40, KEY + ':extra', '1234567890:short'):
            with self.subTest(bad=bad[:12]):
                for name in ('curl.args', 'curl.key'): (self.tmp / name).unlink(missing_ok=True)
                result = self.run_key(bad, 'ok')
                self.assertEqual(1, result.returncode)
                self.assertFalse((self.tmp / 'curl.args').exists(), 'запрос не отправлялся')
                self.assertNotIn(bad, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
