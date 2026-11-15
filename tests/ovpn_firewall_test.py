"""Config-driven OpenVPN isolation: no real firewall or runtime configuration."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OpenVpnFirewallTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / 'server.conf'
        self.log = self.root / 'commands'
        self.bin = self.root / 'bin'; self.bin.mkdir()
        commands = {
            'pidof': '#!/bin/sh\n[ "$RUNNING" = 1 ]\n',
            'iptables-restore': '''#!/bin/sh
name=${0##*/}
printf '%s %s\\n' "$name" "$*" >> "$LOG"
cat >> "$LOG"
[ "$FAIL" != "$name" ]
''',
            'iptables': '''#!/bin/sh
name=${0##*/}
printf '%s %s\\n' "$name" "$*" >> "$LOG"
case "$*" in *' -C '*) [ "$EXISTS" = 1 ];; *) [ "$FAIL" != "$name" ];; esac
''',
        }
        commands['ip6tables-restore'] = commands['iptables-restore']
        commands['ip6tables'] = commands['iptables']
        for name, source in commands.items():
            path = self.bin / name; path.write_text(source); path.chmod(0o755)

    def apply(self, config, **env):
        self.config.write_text(config); self.log.unlink(missing_ok=True)
        result = subprocess.run(['sh', str(ROOT / 'scripts/ovpn_firewall.sh'), str(self.config)],
                                capture_output=True, text=True, timeout=5,
                                env=os.environ | {'PATH': str(self.bin) + ':' + os.environ['PATH'],
                                    'LOG': str(self.log), 'FAIL': '', 'RUNNING': '0', 'EXISTS': '0'} | env)
        return result, self.log.read_text() if self.log.exists() else ''

    def test_config_toggle_replaces_both_family_chains_without_global_flush(self):
        for config, isolated in [('dev tun\n#client-to-client\n', True),
                                 ('dev tun\n; client-to-client\n', True),
                                 ('dev tun\n client-to-client # enabled\n', False),
                                 ('dev tun\n#client-to-client\n', True)]:
            with self.subTest(config=config):
                result, log = self.apply(config)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(log.count('-i tun+ -o tun+ -j REJECT'), 2 if isolated else 0)
                self.assertEqual(log.count('--wait 5 --noflush'), 2)
                self.assertEqual(log.count('-I FORWARD 1 -j VPNBOT_OVPN_CLIENTS'), 2)
                self.assertNotIn('-F FORWARD', log)

    def test_named_device_and_existing_hooks(self):
        result, log = self.apply('dev tun7\n', EXISTS='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(log.count('-i tun7 -o tun7 -j REJECT'), 2)
        self.assertNotIn('-I FORWARD', log)

    def test_each_required_restore_or_hook_failure_prevents_start(self):
        for command in ('iptables-restore', 'ip6tables-restore', 'iptables', 'ip6tables'):
            with self.subTest(command=command):
                result, log = self.apply('dev tun\n', FAIL=command)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('FATAL:', result.stderr)

    def test_invalid_config_and_running_daemon_leave_rules_untouched(self):
        for config in ('# absent dev\n', 'dev tun\nconfig nested.conf\n', 'dev tun\ndev tun1\n', 'dev invalid+\n'):
            result, log = self.apply(config)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(log, '')
        result, log = self.apply('dev tun\n', RUNNING='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(log, '')


if __name__ == '__main__':
    unittest.main()
