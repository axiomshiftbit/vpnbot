"""Startup after an interrupted user update never reuses stale EAP secrets."""
import errno
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import ipsec_credentials as credentials


class Credentials(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root/'psk').write_text('synthetic-psk\n')
        self.users = {'alice': {'pass': 'synthetic-a', 'disabled': True, 'pending': 'disable'},
                      'bob': {'pass': 'synthetic-b', 'disabled': False}}
        (self.root/'users_ikev2.json').write_text(json.dumps(self.users))
        (self.root/'secrets.conf').write_text('stale-derived-data')

    def rebuild(self): credentials.rebuild(self.root, self.root/'lock')

    def test_startup_applies_intent_before_daemon_start(self):
        self.rebuild()
        body = (self.root/'secrets.conf').read_text()
        self.assertNotIn('id = "alice"', body); self.assertIn('id = "bob"', body)
        self.assertEqual((self.root/'secrets.conf').stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads((self.root/'users_ikev2.json').read_text()), self.users)
        self.rebuild(); self.assertEqual((self.root/'secrets.conf').read_text(), body)

    def test_invalid_database_never_replaces_previous_derived_file(self):
        for value in ('{broken', '[1]', '{"alice":{"pass":"x"}}'):
            (self.root/'users_ikev2.json').write_text(value)
            with self.assertRaises(ValueError): self.rebuild()
            self.assertEqual((self.root/'secrets.conf').read_text(), 'stale-derived-data')

    def test_storage_failure_refuses_start_and_preserves_intent(self):
        with patch.object(credentials.os, 'replace', side_effect=OSError(errno.ENOSPC, 'synthetic')):
            with self.assertRaises(OSError): self.rebuild()
        self.assertEqual((self.root/'secrets.conf').read_text(), 'stale-derived-data')
        self.assertEqual(json.loads((self.root/'users_ikev2.json').read_text()), self.users)

    def test_pending_delete_cannot_be_rendered_even_with_inconsistent_disabled_flag(self):
        self.users['alice'].update(disabled=False, pending='delete')
        body = credentials.render(self.users, 'synthetic-psk')
        self.assertNotIn('id = "alice"', body); self.assertIn('id = "bob"', body)


if __name__ == '__main__': unittest.main()
