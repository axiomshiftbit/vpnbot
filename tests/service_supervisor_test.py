"""Настоящие локальные процессы/сокеты; адаптер синтетический, VPN не эмулируется."""
import os
import fcntl
import json
from pathlib import Path
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ServicePortPolicyTest(unittest.TestCase):
    def ports(self, name, content):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'synthetic-config'
            config.write_text(json.dumps(content) if isinstance(content, dict) else content)
            adapter = root / 'adapter.sh'
            adapter.write_text((ROOT / 'scripts/service_daemon.sh').read_text()
                .replace('/config.json', str(config)).replace('/config/AdGuardHome.yaml', str(config)))
            result = subprocess.run(['sh', str(adapter), 'ports', name], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            return set(result.stdout.splitlines())

    def test_adguard_checks_dns_and_every_enabled_tls_listener(self):
        value = 'dns:\n  port: 5353\ntls:\n  enabled: true\n  port_https: 8443\n  port_dns_over_tls: 8853\n  port_dns_over_quic: 8854\n'
        self.assertEqual(self.ports('adguard', value),
            {'tcp:5353', 'udp:5353', 'tcp:8443', 'tcp:8853', 'udp:8854'})
        self.assertEqual(self.ports('adguard', value.replace('enabled: true', 'enabled: false')),
            {'tcp:5353', 'udp:5353'})
        self.assertEqual(self.ports('adguard', value.replace('port: 5353', 'port: 0')),
            {'tcp:8443', 'tcp:8853', 'udp:8854'})

    @unittest.skipUnless(shutil.which("jq"), "jq is required by the real Shadowsocks adapter")
    def test_sslocal_checks_tcp_and_udp_and_inherited_modes(self):
        self.assertEqual(self.ports('sslocal', {'local_port':1080, 'mode':'tcp_and_udp'}), {'tcp:1080','udp:1080'})
        self.assertEqual(self.ports('sslocal', {'mode':'tcp_and_udp', 'locals':[
            {'local_port':1081}, {'local_port':1082, 'mode':'udp_only'}, {'local_port':1083, 'mode':'tcp_only'}]}),
            {'tcp:1081','udp:1081','udp:1082','tcp:1083'})


class ServiceSupervisorTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.state = self.root / 'state'
        self.helper = self.root / 'supervisor.sh'
        self.adapter = self.root / 'adapter.sh'
        self.daemon = self.root / 'daemon.py'
        self.daemon.write_text('import socket,time\nfrom pathlib import Path\ns=socket.socket();s.bind(("127.0.0.1",0));s.listen();'
            + 'Path(' + repr(str(self.state / 'sslocal/ports')) + ').write_text("tcp:"+str(s.getsockname()[1])+"\\n");time.sleep(300)\n')
        source = (ROOT / 'scripts/service_supervisor.sh').read_text()
        self.helper.write_text(source.replace('BASE=/run/vpnbot-services', 'BASE=' + shlex.quote(str(self.state)))
                               .replace('HELPER=/service_daemon.sh', 'HELPER=' + shlex.quote(str(self.adapter))))
        executable = shlex.quote(os.path.realpath(sys.executable))
        self.adapter.write_text('case "$1" in\nexecutable) echo ' + executable + ';;\n'
            'enabled|stopped) exit 0;;\nrun) exec ' + executable + ' ' + shlex.quote(str(self.daemon)) + ';;\nesac\n')
        self.guardian = subprocess.Popen(['sh', str(self.helper), 'supervise', 'proxy'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.children = []
        self.addCleanup(self.cleanup_processes)
        self.wait_ready()

    def cleanup_processes(self):
        if self.guardian.poll() is None:
            self.guardian.send_signal(signal.SIGCONT)
            self.guardian.terminate()
            try:
                self.guardian.wait(timeout=12)
            except subprocess.TimeoutExpired:
                self.guardian.kill()
                self.guardian.wait()
        for child in self.children:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)

    def control(self, action, name='sslocal'):
        return subprocess.run(['sh', str(self.helper), action, name], capture_output=True, text=True, timeout=48)

    def pid(self):
        return int((self.state / 'sslocal/pid').read_text().split()[0])

    def wait_ready(self, previous=None):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if self.control('status').returncode == 0 and (previous is None or self.pid() != previous):
                return
            time.sleep(.1)
        detail = self.control('status').stderr.strip()
        logs = list(self.state.glob('*/launcher.log'))
        detail += ' ' + (logs[0].read_text()[-300:] if logs else 'no launcher log')
        detail += ' record=' + str((self.state/'sslocal/pid').read_text() if (self.state/'sslocal/pid').exists() else 'none')
        self.fail('actual process/listener did not become ready: ' + detail)

    def test_crash_recovers_but_intentional_off_does_not_restart(self):
        old = self.pid()
        os.kill(old, signal.SIGKILL)
        self.wait_ready(previous=old)
        stopped = self.control('stop')
        self.assertEqual((stopped.returncode, stopped.stdout.strip()), (0, 'VPNBOT_SERVICE_STOPPED:sslocal'))
        time.sleep(2)
        self.assertFalse((self.state / 'sslocal/pid').exists())
        self.assertIsNone(self.guardian.poll())
        self.assertEqual(self.control('status').returncode, 3)
        self.assertEqual(self.control('health').returncode, 0)
        self.assertEqual(self.control('start').stdout.strip(), 'VPNBOT_SERVICE_READY:sslocal')
        self.wait_ready()

    def test_start_is_idempotent_and_restart_replaces_owned_pid(self):
        before = self.pid()
        self.assertEqual(self.control('start').returncode, 0)
        self.assertEqual(self.pid(), before)
        self.assertEqual(self.control('restart').stdout.strip(), 'VPNBOT_SERVICE_READY:sslocal')
        self.assertNotEqual(self.pid(), before)
        self.assertNotEqual(self.control('start', 'adguard').returncode, 0)

    def pause_guardian(self):
        # Do not suspend it while it owns the service lock.
        with (self.state / 'sslocal/lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.guardian.send_signal(signal.SIGSTOP)
            fcntl.flock(lock, fcntl.LOCK_UN)

    def test_off_intent_never_confirms_a_still_running_owned_process(self):
        pid = self.pid()
        self.pause_guardian()
        (self.state / 'sslocal/desired').write_text('off\n')
        os.kill(pid, 0)  # The actual owned daemon is still alive.
        self.assertNotEqual(self.control('status').returncode, 3)
        self.assertNotEqual(self.control('health').returncode, 0)
        self.assertEqual(self.control('stop').returncode, 0)
        self.assertEqual(self.control('status').returncode, 3)
        self.assertEqual(self.control('health').returncode, 0)

    def test_off_with_dead_identity_passes_but_malformed_identity_fails_closed(self):
        record = (self.state / 'sslocal/pid').read_text()
        self.assertEqual(self.control('stop').returncode, 0)
        path = self.state / 'sslocal/pid'
        path.write_text(record)
        self.assertEqual(self.control('status').returncode, 3)
        self.assertEqual(self.control('health').returncode, 0)
        for invalid in ('', 'invalid\n', '1 2 extra\n', '1 2\n3 4\n', '0 0\n'):
            with self.subTest(record=invalid):
                path.write_text(invalid)
                self.assertNotEqual(self.control('status').returncode, 3)
                self.assertNotEqual(self.control('health').returncode, 0)
        path.write_text(record)
        plugin = self.state / 'sslocal/plugin-executable'
        for invalid in ('', 'relative-path\n', '/one\n/two\n'):
            plugin.write_text(invalid)
            self.assertNotEqual(self.control('status').returncode, 3)
            self.assertNotEqual(self.control('health').returncode, 0)
        plugin.unlink()
        path.unlink()

    def test_off_does_not_confirm_dead_parent_with_live_owned_plugin(self):
        self.assertEqual(self.control('stop').returncode, 0)
        child_record = self.root / 'plugin-child'
        self.daemon.write_text('import subprocess,socket,time,sys\nfrom pathlib import Path\n'
            'child=subprocess.Popen([sys.executable,"-c","import time;time.sleep(300)"])\n'
            'Path(' + repr(str(child_record)) + ').write_text(str(child.pid))\n'
            'Path(' + repr(str(self.state/'sslocal/plugin-executable')) + ').write_text(' + repr(os.path.realpath(sys.executable)+'\n') + ')\n'
            's=socket.socket();s.bind(("127.0.0.1",0));s.listen()\n'
            'Path(' + repr(str(self.state/'sslocal/ports')) + ').write_text("tcp:"+str(s.getsockname()[1])+"\\n")\n'
            'time.sleep(300)\n')
        self.assertEqual(self.control('start').returncode, 0)
        self.pause_guardian()
        pid = self.pid(); child = int(child_record.read_text())
        os.kill(pid, signal.SIGKILL)
        end = time.monotonic() + 5
        while time.monotonic() < end:
            stat = Path('/proc/' + str(pid) + '/stat')
            if not stat.exists() or stat.read_text().rsplit(') ', 1)[1].startswith('Z '):
                break
            time.sleep(.05)
        os.kill(child, 0)  # Real child remains in the tracked setsid session.
        (self.state / 'sslocal/desired').write_text('off\n')
        self.assertNotEqual(self.control('status').returncode, 3)
        self.assertNotEqual(self.control('health').returncode, 0)
        self.assertEqual(self.control('stop').returncode, 0)
        self.assertEqual(self.control('status').returncode, 3)
        self.assertEqual(self.control('health').returncode, 0)

    def test_stale_pid_record_does_not_signal_reused_pid(self):
        self.assertEqual(self.control('stop').returncode, 0)
        sentinel = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'])
        self.children.append(sentinel)
        (self.state / 'sslocal/pid').write_text(str(sentinel.pid) + ' 0\n')
        self.assertEqual(self.control('stop').returncode, 0)
        self.assertIsNone(sentinel.poll())

    def test_daemon_exit_during_start_is_reported_and_can_be_retried(self):
        self.assertEqual(self.control('stop').returncode, 0)
        previous = self.daemon.read_text()
        self.daemon.write_text('raise SystemExit(2)\n')
        failed = self.control('start')
        self.assertNotEqual(failed.returncode, 0)
        self.assertNotIn('VPNBOT_SERVICE_READY', failed.stdout)
        self.assertNotEqual(self.control('health').returncode, 0)
        self.daemon.write_text(previous)
        self.assertEqual(self.control('start').returncode, 0)
        self.wait_ready()

    def test_correct_pid_with_only_wrong_port_never_reports_ready(self):
        self.assertEqual(self.control('stop').returncode, 0)
        previous = self.daemon.read_text()
        # A real listener exists on this exact executable/PID, but the declared
        # protocol port is different (the metrics-only false positive).
        self.daemon.write_text(previous.replace('str(s.getsockname()[1])', 'str(s.getsockname()[1]-1)'))
        failed = self.control('start')
        self.assertNotEqual(failed.returncode, 0)
        self.assertNotIn('VPNBOT_SERVICE_READY', failed.stdout)
        self.daemon.write_text(previous)
        self.assertEqual(self.control('start').returncode, 0)
        self.wait_ready()

    def test_foreign_socket_cannot_make_tracked_process_ready(self):
        self.assertEqual(self.control('stop').returncode, 0)
        self.guardian.send_signal(signal.SIGSTOP)
        sentinel = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'])
        self.children.append(sentinel)
        start = Path('/proc/' + str(sentinel.pid) + '/stat').read_text().rsplit(') ', 1)[1].split()[19]
        (self.state / 'sslocal/pid').write_text(str(sentinel.pid) + ' ' + start + '\n')
        (self.state / 'sslocal/desired').write_text('on\n')
        with socket.socket() as other:
            other.bind(('127.0.0.1', 0))
            other.listen()
            self.assertNotEqual(self.control('status').returncode, 0)
            self.assertNotEqual(self.control('health').returncode, 0)


if __name__ == '__main__':
    unittest.main()
