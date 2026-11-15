"""Неудачный запуск и отказ отката не накапливают поколения конфигурации."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

spec = importlib.util.spec_from_file_location('protocol_service', Path(__file__).resolve().parents[1] / 'scripts/protocol_service.py')
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)


class GenerationFailureTest(unittest.TestCase):
    def test_failed_start_and_compensation_always_remove_candidate(self):
        for failure in ('rollback_start', 'rollback_stop', 'revoked'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                uid = 'a' * 16
                user = {'enabled': True, 'password': 'S' * 43, 'reset': 'b' * 16,
                        'quota': None, 'expires': None}
                config = {'inbounds': [{'type': 'anytls', 'users': [{'name': uid, 'password': user['password']}]}],
                          'experimental': {'v2ray_api': {}}}
                state = {'schema': 1, 'protocol': 'anytls', 'revision': 1, 'enabled': True,
                         'users': {uid: user}, 'config': config}
                service.atomic_json(root / 'usage.json', {'users': {}})
                service.atomic_json(root / 'desired.json', state)
                supervisor = service.Supervisor(root)
                old = root / 'generation-original'
                old.mkdir()
                previous = config if failure != 'revoked' else config | {
                    'inbounds': [{'type': 'anytls', 'users': [{'name': uid, 'password': 'T' * 43}]}]}
                service.atomic_json(old / 'config.json', previous)
                supervisor.current, supervisor.active = old, [uid]
                original = (old / 'config.json').read_bytes()
                calls = []
                def candidate(config, _state):
                    path = root / ('generation-' + uuid.uuid4().hex)
                    path.mkdir(mode=0o700)
                    service.atomic_json(path / 'config.json', config)
                    return path, 'synthetic-fingerprint'
                def start(path, _users):
                    calls.append(path)
                    raise RuntimeError('synthetic-start-failure')
                for _ in range(3):
                    with patch.object(supervisor, 'candidate', side_effect=candidate), \
                            patch.object(supervisor, 'start', side_effect=start), \
                            patch.object(supervisor, 'stop', side_effect=[None, RuntimeError('synthetic-stop-failure')] if failure == 'rollback_stop' else None):
                        with self.assertRaises(RuntimeError):
                            supervisor.tick()
                    self.assertEqual([old], list(root.glob('generation-*')))
                    self.assertEqual(original, (old / 'config.json').read_bytes())
                self.assertEqual(3 if failure == 'rollback_start' else 0, calls.count(old))


if __name__ == '__main__':
    unittest.main()
