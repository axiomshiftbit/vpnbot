"""Реальный ограниченный subprocess: corrupt desired/quarantine закрывают старый процесс."""
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from protocol_service import Supervisor, atomic_json
from mieru_service import MieruSupervisor
from masque_service import MasqueSupervisor
from snolc_service import SnolcSupervisor


class ProtocolQuarantineTest(unittest.TestCase):
    def state(self):
        uid = 'a' * 16
        user = {'enabled': True, 'password': 'S' * 43, 'reset': 'b' * 16, 'quota': None, 'expires': None}
        return {'schema': 1, 'protocol': 'anytls', 'revision': 1, 'enabled': True, 'users': {uid: user},
                'config': {'inbounds': [{'type': 'anytls', 'users': [{'name': uid, 'password': user['password']}]}],
                           'experimental': {'v2ray_api': {}}}}

    def child(self):
        return subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_corrupt_desired_stops_real_process_before_next_run_iteration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self.state()
            atomic_json(root / 'usage.json', {'users': {}})
            atomic_json(root / 'desired.json', state)
            service = Supervisor(root)
            _, active = service.prepare(state)
            service.last_valid_state = state
            service.active = list(active)
            child = service.process = self.child()
            (root / 'desired.json').write_text('{synthetic-invalid')
            observations = []
            def next_iteration(_delay):
                observations.append(child.poll() is not None)
                service.stopping = True
            previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
            try:
                with patch.object(service, 'counters', return_value={}), \
                        patch.object(service, 'binary_version', return_value='synthetic'), \
                        patch('protocol_service.time', SimpleNamespace(time=time.time, monotonic=time.monotonic, sleep=next_iteration)):
                    service.run()
                self.assertEqual([True], observations, 'old unlimited credential process must stop before retry')
            finally:
                if child.poll() is None: child.kill()
                child.wait(timeout=5)
                for sig, handler in previous.items(): signal.signal(sig, handler)

    def test_invalid_restore_shape_stops_existing_process(self):
        for restore in ("invalid", {"id": "r", "users": []}, {"id": "r", "users": {"u": {"upload": -1, "download": 0}}}):
            with self.subTest(restore=type(restore).__name__), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                atomic_json(root / 'usage.json', {'users': {}})
                state = self.state()
                atomic_json(root / 'desired.json', state)
                service = Supervisor(root)
                child = service.process = self.child()
                state['restore_usage'] = restore
                atomic_json(root / 'desired.json', state)
                try:
                    with self.assertRaises((RuntimeError, ValueError, KeyError, TypeError)):
                        service.tick()
                    self.assertIsNotNone(child.poll(), 'invalid restore cannot retain old credential process')
                finally:
                    if child.poll() is None: child.kill()
                    child.wait(timeout=5)

    def test_quarantine_marker_is_enforced_by_every_native_adapter(self):
        for protocol in ('anytls', 'tuic', 'shadowtls', 'mieru', 'masque', 'snolc'):
            with self.subTest(protocol=protocol), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                factory = {'mieru': MieruSupervisor, 'masque': MasqueSupervisor, 'snolc': SnolcSupervisor}.get(protocol)
                service = factory(root) if factory else Supervisor(root, protocol=protocol)
                # No desired parsing is allowed while quarantined; marker content
                # is intentionally invalid to prove that presence is sufficient.
                (root / 'desired.json').write_text('{synthetic-invalid')
                (root / 'xray-sync.quarantine.json').write_text('{synthetic-invalid')
                child = service.process = self.child()
                try:
                    with patch.object(service, 'collect'), patch.object(service, 'binary_version', return_value='synthetic'):
                        try: service.tick()
                        except (RuntimeError, ValueError): pass
                    self.assertIsNotNone(child.poll(), 'quarantined target must terminate old process')
                    status = json.loads((root / 'status.json').read_text())
                    self.assertEqual('quarantined', status['phase'])
                    self.assertFalse(status['running'])
                    self.assertEqual('xray_sync_unavailable', status['error'])
                finally:
                    if child.poll() is None: child.kill()
                    child.wait(timeout=5)

    def test_snolc_bootstrap_does_not_require_or_reset_a_fake_zero_json_ledger(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            atomic_json(root / 'desired.json', {'users': {'a' * 16: {'quota': 100, 'reset': 'b' * 16}}})
            service = SnolcSupervisor(root)
            self.assertFalse((root / 'usage.json').exists())
            self.assertFalse(service.database().exists())
            admin = {'seq': 1, 'users': {'a' * 16: {'native': 3}}}
            atomic_json(root / 'admin.json', admin)
            with self.assertRaisesRegex(ValueError, '^missing_policy_database$'):
                SnolcSupervisor(root)
            self.assertEqual(admin, json.loads((root / 'admin.json').read_text()))
            self.assertFalse((root / 'usage.json').exists())


if __name__ == '__main__':
    unittest.main()
