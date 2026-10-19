#!/usr/bin/env python3
"""init.sh: автозапуск после перезагрузки на чистой установке."""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('bash') and shutil.which('make'), 'нужны bash и make')
class InstallAutostartTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / 'bin').mkdir()
        # Как настоящий crontab: таблица заменяется после чтения всего stdin.
        self.stub('crontab', '[ "$1" = "-l" ] && { cat "$TAB" 2>/dev/null || exit 1; exit 0; }\n'
                             '[ "$1" = "-" ] && { cat > "$TAB.new"; mv "$TAB.new" "$TAB"; }\n')

    def stub(self, name, body):
        path = self.tmp / 'bin' / name
        path.write_text('#!/bin/sh\n' + body); path.chmod(0o755)

    def env(self, **extra):
        return {'PATH': f'{self.tmp}/bin:/usr/bin:/bin', 'TAB': str(self.tmp / 'tab')} | extra

    def autostart(self, unit_enabled, make_ok=True):
        source = (ROOT / 'scripts/init.sh').read_text()
        function = re.search(r'^install_autostart\(\) \{.*?^\}\n', source, re.M | re.S).group()
        self.stub('systemctl', f'exit {0 if unit_enabled else 1}\n')
        self.stub('make', f'echo "$*" >> "$TAB.make"; exit {0 if make_ok else 2}\n')
        script = self.tmp / 'run.sh'
        script.write_text('set -euo pipefail\n' + function + 'install_autostart\necho done\n')
        return subprocess.run(['bash', str(script)], env=self.env(), capture_output=True, text=True)

    def test_cron_is_installed_when_service_is_absent(self):
        result = self.autostart(unit_enabled=False)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('cron\n', (self.tmp / 'tab.make').read_text())
        self.assertIn('done', result.stdout)

    def test_enabled_service_is_not_duplicated_by_cron(self):
        result = self.autostart(unit_enabled=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse((self.tmp / 'tab.make').exists(), 'make cron не вызывался')

    def test_cron_failure_only_warns(self):
        result = self.autostart(unit_enabled=False, make_ok=False)
        self.assertEqual(0, result.returncode, 'установка не падает')
        self.assertIn('WARN', result.stderr)
        self.assertIn('done', result.stdout)

    def test_make_cron_keeps_other_jobs_and_one_reboot_line(self):
        (self.tmp / 'tab').write_text('0 3 * * 6 /opt/scripts/update.sh\n'
                                      '@reboot sh -c "sleep 10 && cd /root/vpnbot && make r"\n')
        for _ in range(2):
            subprocess.run(['make', '-s', '-C', str(ROOT), 'cron'], env=self.env(), check=True, capture_output=True)
        lines = (self.tmp / 'tab').read_text().splitlines()
        self.assertEqual(1, sum('cd /root/vpnbot && make r' in line for line in lines), lines)
        self.assertIn('0 3 * * 6 /opt/scripts/update.sh', lines)

    def test_make_finds_sbin_tools_under_cron_path(self):
        # cron даёт make только /usr/bin:/bin, а modprobe/sysctl/nft — в sbin.
        result = subprocess.run(['make', '-s', '-C', str(ROOT), '--eval=vpnbot-print-path: ; @echo "$$PATH"', 'vpnbot-print-path'],
                                env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, check=True)
        path = result.stdout.strip().split(':')
        self.assertEqual(['/usr/bin', '/bin'], path[:2], 'исходный PATH идёт первым')
        for directory in ('/usr/local/sbin', '/usr/sbin', '/sbin'):
            self.assertIn(directory, path)


if __name__ == '__main__':
    unittest.main()
