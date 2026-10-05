import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WarpServiceTest(unittest.TestCase):
    def test_proc_udp_range_is_read_by_production_shell(self):
        source = (ROOT / 'scripts/start_wp.sh').read_text()
        guard = source[source.index('udp_range=$('):source.index('cat > /run/warp-socks.json')]
        expected = ':'.join(Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split())
        for shell in ('sh', 'bash'):
            with self.subTest(shell=shell):
                result = subprocess.run([shell, '-c', 'set -e\n' + guard],
                                        env=dict(os.environ, SOCKS_UDP_PORTS=expected), capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_failed_handshake_does_not_leave_ready_interface(self):
        source = (ROOT / 'scripts/start_wp.sh').read_text()
        functions = source[source.index('tunnel_up() {'):source.index('MS_PID=""')]
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, WARP_TEST_DIR=tmp)
            script = '''
WGCF_IF=wgcf-profile
WGCF_CONF=unused
sleep() { :; }
wg() {
    [ -e "$WARP_TEST_DIR/interface" ] || return 1
    [ "$3" != latest-handshakes ] || printf 'peer\\t0\\n'
}
wg-quick() {
    if [ "$1" = up ]; then touch "$WARP_TEST_DIR/interface";
    else rm -f "$WARP_TEST_DIR/interface"; fi
}
''' + functions + '\nwarp_up && exit 10\ntunnel_up && exit 11\nexit 0\n'
            result = subprocess.run(['bash', '-c', script], env=env, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == '__main__':
    unittest.main()
