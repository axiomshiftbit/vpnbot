#!/usr/bin/env python3
"""host_sysctl.sh: 99-vpnbot-sysctl.conf полного бота и ноды."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def render(mode):
    with tempfile.TemporaryDirectory() as directory:
        result = subprocess.run(['bash', str(ROOT / 'scripts/host_sysctl.sh'), mode], capture_output=True, text=True,
                                env=dict(os.environ, VPNBOT_HARDENING_ROOT=directory))
        path = Path(directory) / 'etc/sysctl.d/99-vpnbot-sysctl.conf'
        return result, path.read_text() if path.exists() else '', oct(path.stat().st_mode & 0o777) if path.exists() else ''


def values(text):
    out = {}
    for line in text.splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            key, _, value = line.partition('=')
            out[key.strip()] = value.strip()
    return out


class HostSysctl(unittest.TestCase):
    def test_full_bot_routes_and_keeps_ipv6(self):
        result, text, mode = render('full')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('0o644', mode)
        v = values(text)
        self.assertEqual('1', v['net.ipv4.ip_forward'])
        self.assertEqual('bbr', v['net.ipv4.tcp_congestion_control'])
        self.assertEqual('fq', v['net.core.default_qdisc'])
        self.assertEqual('131072', v['net.netfilter.nf_conntrack_max'])
        self.assertEqual('0', v['net.ipv6.conf.all.accept_redirects'])
        # Выключение IPv6 и отказ от RA — только закомментированы.
        self.assertNotIn('net.ipv6.conf.all.disable_ipv6', v)
        self.assertIn('#net.ipv6.conf.all.disable_ipv6 = 1', text)
        self.assertNotIn('net.ipv6.conf.all.accept_ra', v)
        self.assertNotIn('net.ipv6.conf.all.forwarding', v)

    def test_node_does_not_route(self):
        result, text, _ = render('node')
        self.assertEqual(0, result.returncode, result.stderr)
        v = values(text)
        self.assertNotIn('net.ipv4.ip_forward', v)
        self.assertEqual('bbr', v['net.ipv4.tcp_congestion_control'])
        self.assertIn('#net.ipv6.conf.default.disable_ipv6 = 1', text)

    def test_mode_is_required_and_init_calls_it_after_hardening(self):
        result, text, _ = render('other')
        self.assertEqual(2, result.returncode)
        self.assertEqual('', text)
        init = (ROOT / 'scripts/init.sh').read_text()
        self.assertLess(init.index('bash scripts/host_hardening.sh'), init.index('bash scripts/host_sysctl.sh "$MODE"'))
        call = init.index('bash scripts/host_sysctl.sh "$MODE"')
        self.assertLess(call, init.index('scripts/node_setup.py'))

    def test_keys_exist_in_this_kernel_where_available(self):
        # Ключи без опечаток: каждый, кроме net.netfilter.* (модуль) и bbr, есть в /proc/sys.
        _, text, _ = render('full')
        for key in values(text):
            if key.startswith('net.netfilter.'):
                continue
            path = Path('/proc/sys') / key.replace('.', '/')
            if key.startswith('net.ipv6.') and not Path('/proc/sys/net/ipv6').exists():
                continue
            with self.subTest(key=key):
                self.assertTrue(path.exists(), key)


if __name__ == '__main__':
    unittest.main()
