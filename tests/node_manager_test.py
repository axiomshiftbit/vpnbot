#!/usr/bin/env python3
"""Restricted RPC, transactional host failures and controller key separation."""
import copy
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import node_manager as manager
import node_state as state
from node_runtime import Runtime
from node_state_test import VALUE
from node_config_test import HOST


class Backend:
    def __init__(self):
        self.host = HOST
        self.fail_validate = False
        self.fail_apply = set()
        self.applied = []

    def validate(self, generation):
        if self.fail_validate:
            raise RuntimeError('synthetic validation failure')

    def apply(self, generation):
        if generation in self.fail_apply:
            raise RuntimeError('synthetic activation failure')
        self.applied.append(generation)

    def pull(self, image):
        pass

    def prune_images(self):
        self.pruned = getattr(self, 'pruned', 0) + 1
        return 0


class NodeManager(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vpnbot-manager-')
        self.addCleanup(self.temp.cleanup)
        self.store = state.Store(Path(self.temp.name)/'state')
        self.first = self.store.create(VALUE)
        self.store.activate(self.first)
        self.backend = Backend()
        self.manager = manager.Manager(self.store, self.backend)

    def test_unknown_rpc_fields_and_commands_rejected(self):
        for request in ({'action': 'shell', 'command': 'id'}, {'action': 'ping', 'args': []},
                        {'action': 'backup', 'path': '/etc/shadow'}, {}, [], {'action': []}):
            with self.subTest(request=request), self.assertRaises(ValueError):
                self.manager.rpc(request)
        self.assertEqual(self.manager.rpc({'action': 'ping'}), {'schema': 1})

    def test_backup_uses_last_confirmed_generation_during_apply(self):
        candidate = copy.deepcopy(VALUE)
        candidate['options']['family'] = 4
        candidate['options']['mask'] = 'changed.example.test'
        self.manager.apply(candidate)
        self.assertEqual(self.manager.rpc({'action': 'backup'}), VALUE)

    def test_unsafe_job_payloads_rejected_before_scheduling(self):
        for request in ({'operation': 'shell', 'value': 'id'}, {'operation': 'update', 'value': 'http://example.test'},
                        {'operation': 'restart', 'value': 'other-container'}, {'operation': 'restore', 'value': {}},
                        {'operation': 'configure', 'value': VALUE['options'] | {'command': 'id'}}):
            with self.subTest(request=request), self.assertRaises(ValueError):
                self.manager.submit(request)
        self.assertIsNone(self.store.read('job.json'))

    def test_failed_validation_never_changes_running_generation(self):
        self.backend.fail_validate = True
        with self.assertRaises(RuntimeError):
            self.manager.apply(VALUE)
        self.assertEqual(self.store.current(), self.first)
        self.assertIsNone(self.store.pending())
        self.assertEqual(self.backend.applied, [])

    def test_apply_error_restores_running_generation(self):
        original = self.backend.apply
        def apply(generation):
            if generation != self.first:
                raise RuntimeError('synthetic activation failure')
            return original(generation)
        self.backend.apply = apply
        with self.assertRaises(RuntimeError):
            self.manager.apply(VALUE)
        self.assertEqual(self.backend.applied, [self.first])
        self.assertEqual(self.store.current(), self.first)
        self.assertIsNone(self.store.pending())

    def test_failed_rollback_remains_pending_for_boot_recovery(self):
        with patch.object(self.backend, 'apply', side_effect=RuntimeError('fixture')), self.assertRaises(RuntimeError):
            self.manager.apply(VALUE)
        self.assertIsNotNone(self.store.pending())
        self.manager.recover()
        self.assertIsNone(self.store.pending())
        self.assertEqual(self.store.current(), self.first)

    def test_controller_rotation_does_not_rotate_panel(self):
        value = copy.deepcopy(VALUE)
        peer = dict(id='22222222-2222-4222-8222-222222222222', name='panel', enabled=True)
        value['peers'] = [peer]
        self.store.activate(self.store.create(value))
        self.manager.execute({'operation': 'rotate', 'value': 'controller'})
        self.assertEqual(self.store.load()['peers'], [peer])
        self.assertNotEqual(self.store.load()['identity']['uuid'], VALUE['identity']['uuid'])

    def test_revoked_profile_cannot_be_exported(self):
        value = copy.deepcopy(VALUE)
        peer = dict(id='22222222-2222-4222-8222-222222222222', name='panel', enabled=False)
        value['peers'] = [peer]
        self.store.activate(self.store.create(value))
        with self.assertRaises(ValueError):
            self.manager.rpc({'action': 'profile', 'peer': peer['id']})

    def test_external_profile_requires_confirmed_node_state(self):
        value = copy.deepcopy(VALUE)
        peer = dict(id='22222222-2222-4222-8222-222222222222', name='panel', enabled=True)
        value['peers'] = [peer]
        pending = self.manager.apply(value)
        self.assertIn('link', self.manager.rpc({'action': 'profile', 'peer': None}))
        with self.assertRaises(ValueError):
            self.manager.rpc({'action': 'profile', 'peer': peer['id']})
        self.store.confirm(pending['pending']['nonce'])
        self.assertIn('link', self.manager.rpc({'action': 'profile', 'peer': peer['id']}))

    def test_rollback_without_previous_is_an_error(self):
        with self.assertRaises(ValueError):
            self.manager.execute({'operation': 'rollback', 'value': None})

    def test_busy_job_cannot_be_replaced(self):
        with patch('node_manager.command'):
            result = self.manager.submit({'operation': 'restart', 'value': None})
            with self.assertRaises(ValueError):
                self.manager.submit({'operation': 'rotate', 'value': 'controller'})
        self.assertEqual(self.manager.rpc({'action': 'job', 'id': result['job']})['state'], 'queued')
        self.assertEqual(self.manager.rpc({'action': 'job', 'id': '0'*32}), {'state': 'missing'})
        with self.assertRaises(ValueError):
            self.manager.rpc({'action': 'job', 'id': '../invalid'})

    def test_stale_controller_generation_cannot_overwrite_new_state(self):
        request = {'operation': 'configure', 'value': VALUE['options'], 'generation': self.first}
        with patch('node_manager.command'):
            self.manager.submit(request)
        newer = self.store.create(VALUE)
        self.store.activate(newer)
        self.manager.worker()
        self.assertEqual(self.store.current(), newer)
        self.assertEqual(self.store.read('job.json')['state'], 'failed')
        self.assertEqual(self.backend.applied, [])
        with self.assertRaises(ValueError):
            self.manager.submit(request)

    def test_worker_failure_is_private_and_recoverable(self):
        with patch('node_manager.command'):
            self.manager.submit({'operation': 'restart', 'value': None})
        with patch.object(self.manager, 'execute', side_effect=RuntimeError('DO-NOT-LOG-fixture')):
            self.manager.worker()
        job = self.store.read('job.json')
        self.assertEqual(job['state'], 'failed')
        self.assertNotIn('DO-NOT-LOG', str(job))
        self.assertFalse((self.store.root/'request.json').exists())

    def test_container_runtime_has_no_extra_privileges_or_secret_mounts(self):
        runtime = Runtime(self.store, HOST)
        args = runtime.docker_arguments(self.first)
        self.assertIn('GODEBUG=multipathtcp=0', args)
        self.assertEqual(args[args.index('--cap-drop')+1], 'ALL')
        self.assertNotIn('--privileged', args)
        self.assertNotIn('--restart', args)
        self.assertIn('995:995', args)
        self.assertEqual(args.count('--mount'), 1)
        self.assertNotIn('docker.sock', str(args))
        self.assertNotIn('/ssh', str(args))

    def test_amnezia_runtime_keeps_mptcp_disabled(self):
        runtime = Runtime(self.store, HOST | {'awg_uid': 994})
        args = runtime.amnezia_arguments(self.first)
        self.assertIn('GODEBUG=multipathtcp=0', args)
        self.assertEqual(args[args.index('--cap-drop')+1], 'ALL')
        self.assertEqual(args[args.index('--user')+1], '994:995')

    def test_dead_worker_clears_job_and_recovers_transaction(self):
        with patch('node_manager.command'):
            self.manager.submit({'operation': 'restart', 'value': None})
        self.manager.apply(VALUE)
        job = self.store.read('job.json')
        job.update(state='running', time=0)
        state.atomic(self.store.root/'job.json', state.encode(job))
        with patch('node_manager.command', return_value=SimpleNamespace(stdout=b'failed\n')):
            self.manager.recover_job()
        self.assertEqual(self.store.read('job.json')['state'], 'failed')
        self.assertEqual(self.store.current(), self.first)
        self.assertIsNone(self.store.pending())
        self.assertFalse((self.store.root/'request.json').exists())

    def test_scheduled_or_active_worker_is_not_cancelled(self):
        with patch('node_manager.command') as command:
            self.manager.submit({'operation': 'restart', 'value': None})
            command.reset_mock()
            self.manager.recover_job()
            command.assert_not_called()
        job = self.store.read('job.json')
        job.update(state='running', time=0)
        state.atomic(self.store.root/'job.json', state.encode(job))
        with patch('node_manager.command', return_value=SimpleNamespace(stdout=b'activating\n')):
            self.manager.recover_job()
        self.assertEqual(self.store.read('job.json')['state'], 'running')


if __name__ == '__main__':
    unittest.main()
