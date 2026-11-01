#!/usr/bin/env python3
"""Snapshots, hostile restores and crash recovery without production data."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import node_state as state

VALUE = {'schema': 1, 'options': dict(transport='reality', family=4, core='origin', domain='', mask='mask.example.test'),
         'identity': dict(uuid='11111111-1111-4111-8111-111111111111', private='A'*43, public='B'*43,
                          short_id='0123456789abcdef', path='0123456789abcdef'*2),
         'peers': [], 'images': {'xr': 'ghcr.io/axiomshiftbit/vpnbot-xr@sha256:'+'a'*64}, 'tls': {}}


class NodeState(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vpnbot-node-state-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/'state'
        self.store = state.Store(self.root)
        self.first = self.store.create(VALUE)
        self.store.activate(self.first)

    def test_roundtrip_into_clean_directory(self):
        data = state.encode(self.store.load())
        other = state.Store(Path(self.temp.name)/'restored')
        second = other.create(state.decode(data))
        other.activate(second)
        self.assertEqual(other.load(), VALUE)
        self.assertEqual((other.path(second)/'snapshot.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual(other.root.stat().st_mode & 0o777, 0o700)

    def test_confirm_preserves_previous(self):
        changed = copy.deepcopy(VALUE)
        changed['options']['family'] = 6
        second = self.store.create(changed)
        pending = self.store.begin(second)
        self.store.activate(second)
        self.store.confirm(pending['nonce'])
        self.assertIsNone(self.store.pending())
        self.assertEqual(self.store.read('previous.json'), self.first)
        self.assertEqual(self.store.load(), changed)

    def test_wrong_and_expired_confirmation_keep_rollback(self):
        second = self.store.create(VALUE)
        pending = self.store.begin(second)
        self.store.activate(second)
        with self.assertRaises(ValueError):
            self.store.confirm('wrong')
        with patch('node_state.time.time', return_value=pending['deadline']), self.assertRaises(ValueError):
            self.store.confirm(pending['nonce'])
        self.assertIsNotNone(self.store.pending())
        self.assertEqual(self.store.rollback(), self.first)

    def test_crash_before_and_after_pointer_recovers_old_generation(self):
        for activated in (False, True):
            second = self.store.create(VALUE)
            self.store.begin(second)
            if activated:
                self.store.activate(second)
            reopened = state.Store(self.root)
            reopened.rollback()
            self.assertEqual(reopened.current(), self.first)
            self.assertEqual(reopened.load(), VALUE)

    def test_concurrent_change_is_rejected_until_confirm(self):
        second = self.store.create(VALUE)
        self.store.begin(second)
        with self.assertRaises(ValueError):
            self.store.begin(second)

    def test_early_confirmation_does_not_commit_unapplied_generation(self):
        pending = self.store.begin(self.store.create(VALUE))
        with self.assertRaises(ValueError):
            self.store.confirm(pending['nonce'])

    def test_hostile_json_and_schema_rejected(self):
        for data in ('{"schema":1,"schema":2}', '{"x":NaN}', '['*2000, 'x'*65537):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                state.decode(data)
        for patch in ({'schema': True}, {'command': 'id'}, {'images': {'xr': 'busybox:latest'}},
                      {'tls': {'../../authorized_keys': ''}}, {'peers': {}}, {'tls': {'privkey.pem': ''}}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                state.snapshot(VALUE | patch)

    def test_no_restore_path_traversal(self):
        for name in ('../../etc', '/', 'a'*32+'/../x', 'a'*31):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.store.path(name)

    def test_symlink_and_hardlink_rejected(self):
        path = self.root/'current.json'
        path.unlink()
        path.symlink_to(self.root/'generations'/self.first/'snapshot.json')
        with self.assertRaises(ValueError):
            self.store.current()
        path.unlink()
        os.link(self.root/'generations'/self.first/'snapshot.json', path)
        with self.assertRaises(ValueError):
            self.store.current()

    def test_failed_atomic_replace_keeps_previous_bytes(self):
        before = (self.root/'current.json').read_bytes()
        with patch('node_state.os.replace', side_effect=OSError('fixture')), self.assertRaises(OSError):
            self.store.activate(self.first)
        self.assertEqual((self.root/'current.json').read_bytes(), before)
        self.assertEqual(list(self.root.glob('.current.json-*')), [])

    def test_backup_contains_peer_revocation_and_certificate_pair(self):
        value = copy.deepcopy(VALUE)
        value['peers'] = [dict(id='22222222-2222-4222-8222-222222222222', name='panel', enabled=False)]
        value['tls'] = {name: base64.b64encode(b'-----BEGIN FIXTURE-----\nfixture\n-----END FIXTURE-----\n').decode()
                        for name in ('fullchain.pem', 'privkey.pem')}
        self.assertEqual(state.snapshot(state.decode(state.encode(value))), value)

    def test_old_generations_bounded_without_losing_recovery(self):
        for _ in range(24):
            generation = self.store.create(VALUE)
            pending = self.store.begin(generation)
            self.store.activate(generation)
            self.store.confirm(pending['nonce'])
        previous, current = self.store.read('previous.json'), self.store.current()
        pending = self.store.begin(self.store.create(VALUE))
        # Validation failures also leave generations; they must not fill the disk.
        for _ in range(24):
            self.store.create(VALUE)
        self.assertLessEqual(len(list((self.root/'generations').iterdir())), 16)
        for generation in (previous, current, pending['after']):
            self.assertEqual(self.store.load(generation), VALUE)


if __name__ == '__main__':
    unittest.main()
