"""Модуль xfrm_interface: загрузка при установке и обновлении не обязательна.

На ядре с ipv6.disable=1 модуль не загружается; установка и запуск
контейнеров от этого падать не должны, а автозагрузка не должна записываться.
"""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallXfrmTest(unittest.TestCase):
    def block(self):
        source = (ROOT / 'scripts/init.sh').read_text()
        found = re.search(r'\nif modprobe xfrm_interface 2>/dev/null; then\n.*?\nfi\n', source, re.S)
        self.assertIsNotNone(found, 'init.sh must try to load xfrm_interface')
        return found.group(0)

    def run_block(self, script, loads):
        with tempfile.TemporaryDirectory() as tmp:
            script = script.replace('/etc/modules-load.d', tmp)
            result = subprocess.run(['sh', '-euc', 'modprobe() { [ "$LOADS" = 1 ]; }\n' + script + '\necho AFTER'],
                                    env={'LOADS': '1' if loads else '0', 'PATH': '/usr/bin:/bin'}, capture_output=True, text=True)
            written = Path(tmp, 'vpnbot-xfrm.conf')
            return result, written.read_text() if written.exists() else None

    def test_loaded_module_is_made_persistent(self):
        result, written = self.run_block(self.block(), True)
        self.assertEqual((result.returncode, written), (0, 'xfrm_interface\n'))

    def test_kernel_without_ipv6_does_not_fail_the_installation(self):
        result, written = self.run_block(self.block(), False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('AFTER', result.stdout)
        self.assertIsNone(written)
        self.assertIn('IPsec works without it', result.stdout)

    def test_update_path_tries_the_module_quietly_and_never_stops_make(self):
        lines = [line for line in (ROOT / 'makefile').read_text().splitlines() if 'modprobe xfrm_interface' in line]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith('\t-'), 'make must not stop when the module is missing')
        command = lines[0][2:]
        self.assertTrue(command.endswith('|| true'))
        for loads in (True, False):
            result, written = self.run_block(command, loads)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, 'AFTER\n', ''))
            self.assertEqual(written, 'xfrm_interface\n' if loads else None)

    def test_module_is_loaded_before_containers_start(self):
        text = (ROOT / 'makefile').read_text()
        self.assertLess(text.index('modprobe xfrm_interface'), text.index('protocol_modules.py compose up -d --force-recreate'))


if __name__ == '__main__':
    unittest.main()
