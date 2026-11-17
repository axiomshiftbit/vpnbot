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
    def __init__(self, running=True, loaded=True):
        self.host, self.is_running, self.loaded = HOST, running, loaded
        self.applied, self.reloaded = [], 0

    def running(self):
        return self.is_running

    def firewall_loaded(self):
        return self.loaded

    def load_firewall(self, generation=None):
        self.reloaded += 1
        self.loaded = True

    def apply(self, generation):
        self.applied.append(generation)
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

    def test_runtime_detects_the_guard_table(self):
        runtime = Runtime.__new__(Runtime)
        for output, expected in ((b'table inet vpnbot_node\n', True), (b'table inet filter\n', False), (b'', False)):
            reply = subprocess.CompletedProcess([], 0, output, b'')
            with self.subTest(output=output), patch('node_runtime.command', return_value=reply) as call:
                self.assertIs(runtime.firewall_loaded(), expected)
                self.assertEqual(call.call_args.args[0], ['nft', 'list', 'tables', 'inet'])


if __name__ == '__main__':
    unittest.main()
