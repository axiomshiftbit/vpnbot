"""Ошибки обязательных правил не допускают запуск VPN/SOCKS. Команды ядра замоканы."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def function(source, name):
    return re.search(r'^' + re.escape(name) + r'\(\) \{\n.*?^\}', source, re.M | re.S).group()


class ClientFirewallFailureTest(unittest.TestCase):
    def test_each_required_rule_stops_before_daemon_start(self):
        for service, guard, count in [('oc', 'oc_guard', 4), ('ovpn', 'ovpn_guard', 4), ('ipsec', 'ipsec_guard', 12)]:
            source = (ROOT / ('scripts/start_' + service + '.sh')).read_text()
            block = source[source.index(guard + '() {'):]
            block = block[:block.index('\niptables -t nat')]
            for fail in range(count + 1):
                with self.subTest(service=service, failed_rule=fail):
                    script = '''
VPN_DEVICE=vpns; L2TP_SUBNET=10.7.0.0/24; IKEV2_SUBNET=10.9.0.0/24; DNS=10.10.0.5
count=0
iptables() { count=$((count + 1)); [ "$count" != "$FAIL_RULE" ]; }
log() { printf '%s\\n' "$*" >&2; }
''' + block + '\nprintf "DAEMON_START_REACHED\\n"\n'
                    result = subprocess.run(['sh', '-c', script], env=os.environ | {'FAIL_RULE': str(fail)},
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0 if fail == 0 else 1, result.stderr)
                    self.assertEqual('DAEMON_START_REACHED' in result.stdout, fail == 0)


class WarpFirewallFailureTest(unittest.TestCase):
    def test_watchdog_retries_failed_mode_change_before_starting_proxy(self):
        source = (ROOT / 'scripts/start_wp.sh').read_text()
        loop = source[source.index('while true; do\n    wait_tick'):]
        script = '''
MODE=wireguard; ALPN=h3; MASQUE_READY=0; MASQUE_WAITING=0
PROXY_FIREWALL_READY=1; tick=0; attempts=0; FAILS=0; BOUNCES=0
wait_tick() { tick=$((tick + 1)); [ "$tick" -lt 3 ] || exit 0; echo "tick=$tick"; }
warp_mode() { echo masque; }
masque_alpn() { echo h3; }
mode_name() { echo "$1"; }
socks_stop() { echo proxy-stopped; }
link_down() { echo link-stopped; }
proxy_firewall() {
    PROXY_FIREWALL_READY=0; attempts=$((attempts + 1)); echo "guard-attempt=$attempts"
    [ "$attempts" -gt 1 ] || return 1
    PROXY_FIREWALL_READY=1
}
warp_disabled() { return 1; }
link_ready() { return 1; }
link_up() { echo link-ready; }
socks_start() { echo proxy-started; }
''' + loop
        result = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(lines.count('proxy-started'), 1)
        self.assertLess(lines.index('proxy-stopped'), lines.index('guard-attempt=1'))
        self.assertLess(lines.index('guard-attempt=1'), lines.index('tick=2'))
        self.assertLess(lines.index('tick=2'), lines.index('guard-attempt=2'))
        self.assertLess(lines.index('guard-attempt=2'), lines.index('proxy-started'))

    def run_case(self, fail):
        source = (ROOT / 'scripts/start_wp.sh').read_text()
        functions = '\n'.join(function(source, name) for name in ('proxy_firewall', 'socks_start', 'socks_running'))
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'calls'
            script = '''
set +e
MODE=wireguard; WGCF_IF=wgcf; SOCKS_PORT=1080; SOCKS_UDP_PORTS=40000:40100
PROXY_UID=30000; MS_PID=; PROXY_FIREWALL_READY=1
count=0
firewall() {
    count=$((count + 1))
    printf '%s|%s\\n' "$count" "$*" >> "$CALLS"
    [ "$count" != "$FAIL_RULE" ] || return 1
    [ "$2" != -N ] || return 1
}
iptables() { firewall iptables "$@"; }
ip6tables() { firewall ip6tables "$@"; }
wg() { echo 51820; }
su() { echo PROXY_START_REACHED; }
mode_mark() { :; }
''' + functions + '''
proxy_firewall
printf 'FIREWALL_END\\n' >> "$CALLS"
socks_start
rc=$?
wait
exit "$rc"
'''
            result = subprocess.run(['sh', '-c', script], env=os.environ | {'FAIL_RULE': str(fail), 'CALLS': str(log)},
                                    capture_output=True, text=True)
            return result, log.read_text().split('FIREWALL_END\n')[0].splitlines()

    def test_every_rule_failure_prevents_proxy_restart(self):
        control, calls = self.run_case(0)
        self.assertEqual(control.returncode, 0, control.stderr)
        self.assertIn('PROXY_START_REACHED', control.stdout)
        for line in calls:
            number, command = line.split('|', 1)
            if ' -N ' in command:
                continue  # Существующая цепочка: штатно используется -F.
            with self.subTest(command=command):
                result, _ = self.run_case(int(number))
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('PROXY_START_REACHED', result.stdout)


if __name__ == '__main__':
    unittest.main()
