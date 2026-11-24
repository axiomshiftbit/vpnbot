"""Order the real worker around container startup and in-flight operations."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WorkerStopTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ('update', 'scripts', 'config'):
            (self.root / name).mkdir()
        shutil.copy2(ROOT / 'update/update.sh', self.root / 'update/update.sh')
        shutil.copy2(ROOT / 'scripts/stop_update.sh', self.root / 'scripts/stop_update.sh')
        (self.root / '.env').write_text('TELEGRAM_API=synthetic.invalid\n')
        (self.root / 'config/protocol-services.json').write_text('{}')
        # A gate holds the child at the same boundary as a slow Compose call.
        (self.root / 'scripts/protocol_modules.py').write_text('''from pathlib import Path
import time
Path('entered').touch()
end=time.monotonic()+10
while not Path('release').exists() and time.monotonic()<end:time.sleep(.02)
Path('completed').touch()
''')

    def worker(self):
        worker = subprocess.Popen(['bash', 'update/update.sh'], cwd=self.root,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  start_new_session=True)
        def cleanup():
            (self.root / 'release').touch()
            try: os.killpg(worker.pid, signal.SIGTERM)
            except ProcessLookupError: pass
            worker.wait(timeout=5)
        self.addCleanup(cleanup)
        end = time.monotonic() + 5
        while not (self.root / 'entered').exists():
            if worker.poll() is not None or time.monotonic() >= end:
                self.fail('worker did not enter the protocol operation')
            time.sleep(.02)
        return worker

    def assert_child_drained(self, orphan=False):
        worker = self.worker()
        if orphan:
            worker.terminate(); worker.wait(timeout=5)
        with subprocess.Popen(['sh', 'scripts/stop_update.sh', 'update/update_pid'], cwd=self.root,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as stop:
            try:
                time.sleep(.15)
                self.assertIsNone(stop.poll(), 'stop returned while the protocol child was still running')
            finally:
                (self.root / 'release').touch()
            self.assertEqual(0, stop.wait(timeout=5))
        self.assertTrue((self.root / 'completed').exists())
        worker.wait(timeout=5)

    def test_stop_waits_for_the_in_flight_protocol_child(self):
        self.assert_child_drained()

    def test_stale_worker_pid_still_drains_its_surviving_child(self):
        self.assert_child_drained(orphan=True)

    def test_unrelated_reused_pid_is_not_signalled(self):
        with subprocess.Popen(['sleep', '10']) as other:
            try:
                (self.root / 'update/update_pid').write_text(str(other.pid))
                result = subprocess.run(['sh', 'scripts/stop_update.sh', 'update/update_pid'],
                                        cwd=self.root, capture_output=True, timeout=5)
                self.assertEqual(0, result.returncode)
                self.assertIsNone(other.poll())
            finally:
                other.terminate()

    def test_make_d_does_not_stop_containers_when_worker_stop_failed(self):
        (self.root / 'scripts/stop_update.sh').write_text('#!/bin/sh\nexit 1\n')
        binary = self.root / 'docker'
        binary.write_text('#!/bin/sh\ntouch docker-was-called\n'); binary.chmod(0o700)
        result = subprocess.run(['make', '-f', str(ROOT / 'makefile'), 'd'], cwd=self.root,
                                env=os.environ | {'PATH': str(self.root) + ':' + os.environ['PATH']},
                                capture_output=True, timeout=5)
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.root / 'docker-was-called').exists())

    def assert_start_order(self, failed_start=False):
        shutil.copy2(ROOT / 'makefile', self.root / 'makefile')
        # Exercise the real make dependencies and real worker, holding only
        # the Compose boundary. No Docker command or host setup is executed.
        (self.root / 'startup-test.mk').write_text('pull:\n\t@true\nstart:\n\t@python3 start_gate.py\n')
        (self.root / 'start_gate.py').write_text('''from pathlib import Path
import time,sys
Path('start-entered').touch()
end=time.monotonic()+5
while not Path('release-start').exists() and time.monotonic()<end:time.sleep(.02)
Path('start-completed').touch()
sys.exit(''' + str(int(failed_start)) + ''')
''')
        process = subprocess.Popen(['make', '-j2', '-f', 'makefile', '-f', 'startup-test.mk',
                                    'IP=203.0.113.10', 'VER=audit', 'u'], cwd=self.root,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   start_new_session=True)
        def cleanup():
            (self.root / 'release-start').touch()
            (self.root / 'release').touch()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            # preup uses setsid: the worker outlives make and owns a separate
            # session. Its child must release the worker lock before rmtree.
            pidfile = self.root / 'update/update_pid'
            if process.returncode == 0:
                deadline = time.monotonic() + 5
                while not (pidfile.is_file() and pidfile.stat().st_size):
                    if time.monotonic() >= deadline:
                        self.fail('started worker did not publish its PID')
                    time.sleep(.02)
            if pidfile.is_file():
                subprocess.run(['sh', 'scripts/stop_update.sh', str(pidfile)], cwd=self.root,
                               check=True, timeout=10)
        self.addCleanup(cleanup)
        deadline = time.monotonic() + 5
        while not (self.root / 'start-entered').exists():
            if process.poll() is not None or time.monotonic() >= deadline:
                self.fail('make did not enter container startup')
            time.sleep(.02)
        time.sleep(.3)
        early = (self.root / 'entered').exists()
        (self.root / 'release-start').touch()
        result = process.wait(timeout=5)
        if failed_start:
            self.assertNotEqual(0, result)
            self.assertFalse((self.root / 'update/update_pid').exists(), 'worker started after failed container startup')
        else:
            self.assertEqual(0, result)
            deadline = time.monotonic() + 5
            while not (self.root / 'entered').exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue((self.root / 'entered').exists(), 'worker did not start after successful startup')
        self.assertFalse(early, 'worker managed protocols before container startup finished')

    def test_make_u_starts_worker_after_successful_container_startup(self):
        self.assert_start_order()

    def test_make_u_does_not_start_worker_after_failed_container_startup(self):
        self.assert_start_order(failed_start=True)


if __name__ == '__main__':
    unittest.main()
