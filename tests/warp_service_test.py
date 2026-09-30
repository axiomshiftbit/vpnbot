import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WarpServiceTest(unittest.TestCase):
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
