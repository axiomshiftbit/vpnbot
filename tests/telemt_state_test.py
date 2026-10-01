import importlib.util
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('telemt_state', Path(__file__).resolve().parents[1] / 'scripts/telemt_state.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TelemtStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = MODULE.TelemtState(self.root)
        self.configure()

    def configure(self, quota=True):
        self.state.config.write_text('[access.users]\nalice = "secret"\nbob = "other"\n'
                                     + ('[access.user_data_quota]\nalice = 1000\n' if quota else ''))

    def initial(self, used=100):
        data = {'last_reset_epoch_secs': 5, 'users': {
            'alice': {'used_bytes': used, 'last_reset_epoch_secs': 5},
            'bob': {'used_bytes': 333, 'last_reset_epoch_secs': 0}}}
        self.state.write(data)
        return data

    def snapshot(self, used=200, epoch=5):
        return {'users': [{'username': 'alice', 'used_bytes': used, 'last_reset_epoch_secs': epoch}]}

    def test_missing_state_does_not_grant_fresh_quota(self):
        with self.assertRaises(ValueError): self.state.prepare()
        self.assertFalse(self.state.path.exists())

    def test_unlimited_first_start_and_deleted_names(self):
        self.configure(False)
        self.state.prepare()
        self.assertEqual(0, self.state.read()['users']['alice']['used_bytes'])
        self.initial()
        self.state.config.write_text('[access.users]\nbob = "other"\n')
        self.state.prepare()
        self.assertEqual(['bob'], list(self.state.read()['users']))
        self.configure(False)
        self.state.prepare()
        self.assertEqual(0, self.state.read()['users']['alice']['used_bytes'])
        self.assertEqual(333, self.state.read()['users']['bob']['used_bytes'])

    def test_private_atomic_file_and_failed_replace(self):
        data = self.initial()
        self.assertEqual(0o600, self.state.path.stat().st_mode & 0o777)
        with patch.object(MODULE.os, 'replace', side_effect=OSError('disk full')):
            with self.assertRaises(OSError): self.state.write({'last_reset_epoch_secs': 0, 'users': {}})
        self.assertEqual(data, self.state.read())
        self.assertEqual([], list(self.state.path.parent.glob('.quota-*')))

    def test_corrupt_state_is_not_reset(self):
        self.initial()
        self.state.path.write_text('{bad')
        for action in [self.state.prepare, lambda: self.state.reset('alice')]:
            with self.assertRaises(ValueError): action()
        self.assertEqual('{bad', self.state.path.read_text())

    def test_validation_bounds(self):
        for value in [-1, True, 1.5, '100', 2**64, None]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.state.validate({'last_reset_epoch_secs': 0, 'users': {'alice': {'used_bytes': value, 'last_reset_epoch_secs': 0}}})
        self.state.validate({'last_reset_epoch_secs': 0, 'users': {'alice': {'used_bytes': 2**64-1, 'last_reset_epoch_secs': 0}}})

    def test_symlink_rejected(self):
        self.initial()
        other = self.root / 'other'; other.write_text(self.state.path.read_text())
        self.state.path.unlink(); self.state.path.symlink_to(other)
        with self.assertRaises(ValueError): self.state.read()
        other.unlink()
        with self.assertRaises(ValueError): self.state.read()

    def test_checkpoint_merges_and_skips_unchanged_writes(self):
        self.initial()
        with patch.object(self.state, 'processes', return_value={123: '456'}), patch.object(self.state, 'fetch', return_value=self.snapshot()):
            self.state.checkpoint()
            first = self.state.path.stat().st_ino
            self.state.checkpoint()
        self.assertEqual(first, self.state.path.stat().st_ino)
        self.assertEqual(200, self.state.read()['users']['alice']['used_bytes'])
        self.assertEqual(333, self.state.read()['users']['bob']['used_bytes'])

    def test_counter_regression_or_incomplete_api_preserves_file(self):
        before = self.initial()
        for response in [self.snapshot(99), self.snapshot(1000, 4), {'users': []}, {'users': self.snapshot()['users'] * 2}]:
            with self.subTest(response=response), patch.object(self.state, 'processes', return_value={123: '456'}), patch.object(self.state, 'fetch', return_value=response):
                with self.assertRaises(ValueError): self.state.checkpoint()
                self.assertEqual(before, self.state.read())

    def test_restart_during_fetch_is_rejected(self):
        before = self.initial()
        with patch.object(self.state, 'processes', side_effect=[{123: '456'}, {124: '789'}]), patch.object(self.state, 'fetch', return_value=self.snapshot()):
            with self.assertRaises(ValueError): self.state.checkpoint()
        self.assertEqual(before, self.state.read())

    def test_reset_only_selected_stopped_user(self):
        self.initial()
        with patch.object(self.state, 'processes', return_value={123: '456'}):
            with self.assertRaises(ValueError): self.state.reset('alice')
        self.state.reset('alice')
        self.assertEqual(0, self.state.read()['users']['alice']['used_bytes'])
        self.assertEqual(333, self.state.read()['users']['bob']['used_bytes'])
        with self.assertRaises(ValueError): self.state.reset('unknown')

    def test_graceful_stop_waits_for_final_atomic_save(self):
        self.initial()
        child = self.root / 'child.py'
        child.write_text('import os,sys,signal,time,json\nfrom pathlib import Path\n'
                         'p=Path(sys.argv[1]).parent/"data/telemt.limit.json"\n'
                         'def stop(*args):\n'
                         ' d=json.loads(p.read_text()); d["users"]["alice"]["used_bytes"]=777\n'
                         ' t=p.with_suffix(".tmp"); t.write_text(json.dumps(d)); os.replace(t,p); sys.exit(0)\n'
                         'signal.signal(signal.SIGTERM,stop)\n'
                         'Path(sys.argv[1]).with_suffix(".ready").touch()\n'
                         'while True: time.sleep(.05)\n')
        process = subprocess.Popen([sys.executable, str(child), str(self.state.config)])
        try:
            end = time.monotonic() + 3
            while not self.state.config.with_suffix('.ready').exists() and time.monotonic() < end: time.sleep(.01)
            self.assertIn(process.pid, self.state.processes())
            self.state.stop(timeout=3)
            process.wait(3)
            self.assertEqual(0, process.returncode)
            self.assertEqual(777, self.state.read()['users']['alice']['used_bytes'])
        finally:
            if process.poll() is None: process.kill(); process.wait()

    def test_stop_timeout_does_not_force_kill(self):
        self.initial()
        with patch.object(self.state, 'processes', return_value={123: '456'}), patch.object(self.state, 'checkpoint'), patch.object(MODULE.os, 'kill') as kill:
            with self.assertRaises(ValueError): self.state.stop(timeout=0)
            kill.assert_called_once_with(123, signal.SIGTERM)

    def test_watcher_yields_to_bot_lock_and_stops_on_sigterm(self):
        lock_path = self.root / 'telemt.lock'
        marker = self.root / 'checkpoint'
        code = ('import importlib.util,sys\nfrom pathlib import Path\n'
                's=importlib.util.spec_from_file_location("state",sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n'
                'state=m.TelemtState(sys.argv[2]);state.checkpoint=lambda:Path(sys.argv[3]).touch()\n'
                'state.watch(sys.argv[4])\n')
        with lock_path.open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            child = subprocess.Popen([sys.executable, '-c', code, SPEC.origin, str(self.root), str(marker), str(lock_path)])
            try:
                time.sleep(1.2)
                self.assertFalse(marker.exists(), 'Снимок не пересекается с изменением лимитов')
                fcntl.flock(lock, fcntl.LOCK_UN)
                end = time.monotonic() + 3
                while not marker.exists() and time.monotonic() < end: time.sleep(.05)
                self.assertTrue(marker.exists())
                child.terminate(); child.wait(3)
                self.assertEqual(0, child.returncode)
            finally:
                if child.poll() is None: child.kill(); child.wait()


if __name__ == '__main__': unittest.main()
