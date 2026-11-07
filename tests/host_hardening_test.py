#!/usr/bin/env python3
"""scripts/host_hardening.sh: neighbour sysctl, nf_conntrack at boot, LLMNR off; idempotent."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/host_hardening.sh'


class HostHardening(unittest.TestCase):
    def run_script(self, root, wan='eth0', resolved=True):
        bin_dir = root / 'bin'; bin_dir.mkdir(exist_ok=True)
        log = root / 'calls.log'
        stubs = {
            'ip': f'echo "default via 192.0.2.1 dev {wan} proto static"',
            'sysctl': f'echo "sysctl $*" >> {log}; [ "$3" = - ] && cat >> {log}; true',
            'modprobe': f'echo "modprobe $*" >> {log}',
            'systemctl': f'echo "systemctl $*" >> {log}; [ "$2" != --quiet ] || {"true" if resolved else "false"}',
        }
        for name, body in stubs.items():
            (bin_dir / name).write_text('#!/bin/bash\n' + body + '\n'); (bin_dir / name).chmod(0o755)
        env = dict(os.environ, PATH=f'{bin_dir}:{os.environ["PATH"]}', VPNBOT_HARDENING_ROOT=str(root))
        result = subprocess.run(['bash', str(SCRIPT)], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return log.read_text() if log.exists() else ''

    def test_files_and_idempotence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'etc/sysctl.d').mkdir(parents=True)
            (root / 'etc/sysctl.d/99-system-setup.conf').write_text('net.ipv6.conf.all.disable_ipv6 = 1\nnet.netfilter.nf_conntrack_tcp_loose = 0\n')
            calls = self.run_script(root)
            neighbour = (root / 'etc/sysctl.d/97-vpnbot-neighbor.conf').read_text()
            for line in ('net.ipv4.conf.all.arp_ignore = 1', 'net.ipv4.conf.default.arp_announce = 2',
                         'net.ipv4.conf.all.send_redirects = 0', 'net.ipv4.conf.eth0.send_redirects = 0',
                         'net.ipv4.tcp_syncookies = 1'):
                self.assertIn(line, neighbour)
            self.assertEqual((root / 'etc/modules-load.d/vpnbot-conntrack.conf').read_text(), 'nf_conntrack\n')
            self.assertIn('LLMNR=no', (root / 'etc/systemd/resolved.conf.d/90-vpnbot-no-llmnr.conf').read_text())
            self.assertIn('modprobe nf_conntrack', calls)
            # Only netfilter keys are re-applied: an absent IPv6 key must not break it.
            self.assertIn('net.netfilter.nf_conntrack_tcp_loose = 0', calls)
            self.assertNotIn('disable_ipv6', calls.split('modprobe nf_conntrack', 1)[1])
            self.assertIn('systemctl try-restart systemd-resolved', calls)
            first = sorted(p.relative_to(root) for p in root.rglob('*') if p.is_file() and 'bin' not in p.parts and p.name != 'calls.log')
            self.run_script(root)
            self.assertEqual(neighbour, (root / 'etc/sysctl.d/97-vpnbot-neighbor.conf').read_text())
            self.assertEqual(first, sorted(p.relative_to(root) for p in root.rglob('*') if p.is_file() and 'bin' not in p.parts and p.name != 'calls.log'))

    def test_unsafe_interface_name_and_no_resolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            calls = self.run_script(root, wan='eth0.100;x', resolved=False)
            neighbour = (root / 'etc/sysctl.d/97-vpnbot-neighbor.conf').read_text()
            self.assertNotIn('eth0.100', neighbour)
            self.assertIn('net.ipv4.conf.all.send_redirects = 0', neighbour)
            self.assertFalse((root / 'etc/systemd/resolved.conf.d').exists())
            self.assertNotIn('try-restart', calls)

    def test_init_runs_hardening_for_both_modes(self):
        source = (SCRIPT.parent / 'init.sh').read_text()
        hardening = source.index('bash scripts/host_hardening.sh')
        self.assertLess(source.index('cd "$INSTALL_DIR"'), hardening)
        self.assertLess(hardening, source.index('exec python3 -I scripts/node_setup.py'))


if __name__ == '__main__':
    unittest.main()
