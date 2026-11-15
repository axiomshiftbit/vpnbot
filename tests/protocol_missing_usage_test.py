"""Потерянный ledger не даёт повторно исчерпанную квоту; явный restore допустим."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from protocol_service import Supervisor, atomic_json
from masque_service import MasqueSupervisor
from mieru_service import MieruSupervisor


class MissingUsageTest(unittest.TestCase):
    def test_missing_existing_ledger_fails_closed_for_all_adapters(self):
        for kind in ('anytls', 'tuic', 'shadowtls', 'mieru', 'masque'):
            with self.subTest(protocol=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                uid = 'a' * 16
                state = {'users': {uid: {'quota': 100, 'reset': 'b' * 16}}}
                atomic_json(root / 'desired.json', state)
                atomic_json(root / 'usage.json', {'users': {uid: {'upload': 100, 'download': 0, 'reset': 'b' * 16}}})
                factory = (lambda: MasqueSupervisor(root)) if kind == 'masque' else (
                    (lambda: MieruSupervisor(root)) if kind == 'mieru' else (lambda: Supervisor(root, protocol=kind)))
                self.assertEqual(100, factory().usage['users'][uid]['upload'])
                (root / 'usage.json').unlink()
                with self.assertRaisesRegex(ValueError, '^missing_usage$'):
                    factory()
                self.assertFalse((root / 'usage.json').exists())

    def test_clean_empty_state_and_explicit_restore_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual({}, Supervisor(root).usage['users'])
            atomic_json(root / 'desired.json', {'users': {}})
            self.assertEqual({}, Supervisor(root).usage['users'])
            atomic_json(root / 'desired.json', {'users': {'a' * 16: {}},
                        'restore_usage': {'id': 'c' * 32, 'users': {'a' * 16: {'upload': 100, 'download': 0}}}})
            self.assertEqual({}, Supervisor(root).usage['users'])


if __name__ == '__main__':
    unittest.main()
