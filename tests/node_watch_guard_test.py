#!/usr/bin/env python3
"""The 15-second watch restores a missing node guard.

`systemctl restart nftables` with a broken /etc/nftables.conf flushes the
ruleset (ExecStop) and loads nothing: the running node was left without any
filtering until the next apply."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import node_manager as manager
import node_state as state
from node_runtime import Runtime
from node_state_test import VALUE
from node_config_test import HOST


class Backend:
    def __init__(self, running=True, loaded=True, rebuild=True, apply_fails=False):
        self.host, self.is_running, self.loaded = HOST, running, loaded
        self.applied, self.reloaded, self.restored = [], 0, 0
        self.rebuild, self.apply_fails = rebuild, apply_fails

    def running(self):
        return self.is_running

    def firewall_intact(self):
        return self.loaded

    def load_firewall(self, generation=None):
        if not self.rebuild:
            raise ValueError('route snapshot unavailable')
        self.reloaded += 1
        self.loaded = True

    def restore_guard(self):
        self.restored += 1
        self.loaded = True

    def apply(self, generation):
        self.applied.append(generation)
        if self.apply_fails:
            raise RuntimeError('docker unavailable')
        self.is_running = self.loaded = True


class WatchGuard(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vpnbot-watch-')
        self.addCleanup(self.temp.cleanup)
        self.store = state.Store(Path(self.temp.name)/'state')
        self.first = self.store.create(VALUE)
        self.store.activate(self.first)

    def watch(self, backend):
        manager.Manager(self.store, backend).watch()
        return backend

    def test_job_recovery_failure_still_repairs_the_guard(self):
        backend = Backend(running=True, loaded=False)
        reconciler = manager.Manager(self.store, backend)
        with patch.object(reconciler, 'recover_job', side_effect=ValueError('route unavailable')):
            with self.assertRaisesRegex(ValueError, 'route unavailable'):
                reconciler.watch()
        self.assertEqual(backend.reloaded, 1)

    def test_missing_guard_is_restored_while_containers_run(self):
        backend = self.watch(Backend(running=True, loaded=False))
        self.assertEqual(backend.reloaded, 1)
        self.assertEqual(backend.applied, [])

    def test_present_guard_is_not_touched(self):
        backend = self.watch(Backend(running=True, loaded=True))
        self.assertEqual((backend.reloaded, backend.applied), (0, []))

    def test_stopped_node_is_reapplied_with_its_guard(self):
        backend = self.watch(Backend(running=False, loaded=False))
        self.assertEqual(backend.applied, [self.first])
        self.assertEqual(backend.reloaded, 0)

    def test_guard_is_checked_when_containers_cannot_restart(self):
        # Audit 26.11.2026 (C03): a failed restart used to skip the guard check.
        backend = Backend(running=False, loaded=False, apply_fails=True)
        with self.assertRaises(RuntimeError):
            self.watch(backend)
        self.assertEqual(backend.reloaded, 1)

    def test_persisted_guard_is_loaded_when_it_cannot_be_rebuilt(self):
        backend = Backend(running=True, loaded=False, rebuild=False)
        with self.assertRaises(ValueError):
            self.watch(backend)
        self.assertEqual((backend.restored, backend.loaded), (1, True))

    def test_changed_rule_behind_the_table_name_is_detected(self):
        # Audit 26.11.2026 (C03): only the table name was checked.
        loaded = {'nftables': [{'metainfo': {'version': '1'}}, {'table': {'family': 'inet', 'name': 'vpnbot_node', 'handle': 1}},
                               {'chain': {'family': 'inet', 'table': 'vpnbot_node', 'name': 'input', 'handle': 2, 'policy': 'drop'}},
                               {'set': {'family': 'inet', 'table': 'vpnbot_node', 'name': 'acme_http', 'flags': ['timeout'],
                                        'elem': [{'elem': {'val': 80, 'expires': 500}}], 'handle': 3}},
                               {'rule': {'family': 'inet', 'table': 'vpnbot_node', 'chain': 'input', 'handle': 4,
                                         'expr': [{'counter': {'packets': 5, 'bytes': 9}}, {'drop': None}]}}]}
        runtime = Runtime.__new__(Runtime)
        runtime.store = self.store
        listing = lambda document: subprocess.CompletedProcess([], 0, __import__('json').dumps(document).encode(), b'')
        with patch('node_runtime.command', return_value=listing(loaded)):
            runtime.remember_guard()
            self.assertTrue(runtime.firewall_intact())
        # Counters, handles and the ACME window element change all the time.
        moved = __import__('copy').deepcopy(loaded)
        moved['nftables'][4]['rule']['expr'][0]['counter']['packets'] = 99
        moved['nftables'][3]['set'].pop('elem')
        with patch('node_runtime.command', return_value=listing(moved)):
            self.assertTrue(runtime.firewall_intact())
        changed = __import__('copy').deepcopy(loaded)
        changed['nftables'][4]['rule']['expr'][-1] = {'accept': None}
        with patch('node_runtime.command', return_value=listing(changed)):
            self.assertFalse(runtime.firewall_intact())
        policy = __import__('copy').deepcopy(loaded)
        policy['nftables'][2]['chain']['policy'] = 'accept'
        with patch('node_runtime.command', return_value=listing(policy)):
            self.assertFalse(runtime.firewall_intact())
        with patch('node_runtime.command', return_value=subprocess.CompletedProcess([], 1, b'', b'')):
            self.assertFalse(runtime.firewall_intact())

    def test_runtime_detects_the_guard_table(self):
        runtime = Runtime.__new__(Runtime)
        for output, expected in ((b'table inet vpnbot_node\n', True), (b'table inet filter\n', False), (b'', False)):
            reply = subprocess.CompletedProcess([], 0, output, b'')
            with self.subTest(output=output), patch('node_runtime.command', return_value=reply) as call:
                self.assertIs(runtime.firewall_loaded(), expected)
                self.assertEqual(call.call_args.args[0], ['nft', 'list', 'tables', 'inet'])


if __name__ == '__main__':
    unittest.main()
