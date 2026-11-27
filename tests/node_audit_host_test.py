#!/usr/bin/env python3
"""Audit 26.11.2026: node installer, guard and transport, nftables helpers.

Each test fails on the code before the fix (ac228da) and passes after it."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
sys.path.insert(0, str(ROOT/'app'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ipv6_egress
import nft_host_setup
import node_cover
import node_install
import node_policy
import node_runtime
import node_setup as setup
import node_ssh as transport
from node_config_test import HOST, KEYS
import node_setup_test



def done(stdout=b'', returncode=0, stderr=b''):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class Runtime(unittest.TestCase):
    def runtime(self, host=HOST):
        runtime = node_runtime.Runtime.__new__(node_runtime.Runtime)
        runtime.host, runtime.store, runtime.guard = dict(host), MagicMock(), Path('/nonexistent/guard.nft')
        return runtime

    def test_b04_unreachable_docker_is_not_a_stopped_node(self):
        runtime = self.runtime()
        down = done(b'', 1, b'failed to connect to the docker API at unix:///var/run/docker.sock')
        with patch.object(node_runtime, 'command', return_value=down):
            self.assertIsNone(runtime.container(), 'status keeps reporting a missing container')
            with self.assertRaises(node_runtime.HostOperationError):
                runtime.stop()
        missing = done(b'', 1, b'Error: No such object: vpnbot-node-xray')
        with patch.object(node_runtime, 'command', return_value=missing):
            runtime.stop()

    def test_c04_failed_route_read_stops_instead_of_dropping_the_segment(self):
        runtime = self.runtime()
        with patch.object(node_runtime, 'command', return_value=done(b'', 2, b'')):
            with self.assertRaises(ValueError):
                runtime.routed_host()
        # A family the node does not use may be missing in the kernel.
        with patch.object(node_runtime, 'command', side_effect=lambda args, **kw: done(b'[]', 0) if args[2] == '-4' else done(b'', 2)):
            self.assertEqual(self.runtime(dict(HOST, public6='')).routed_host()['onlink'], [])

    def test_h03_acme_window_is_read_back_after_closing(self):
        runtime = self.runtime()
        calls = []
        open_set = {'nftables': [{'set': {'name': 'acme_http', 'elem': [80]}}]}
        def command(args, **kwargs):
            calls.append(args[:3])
            if args[:3] == ['nft', '-j', 'list']:
                return done(json.dumps(open_set).encode())
            return done(b'', 1)
        with patch.object(node_runtime, 'command', side_effect=command), self.assertRaises(RuntimeError):
            runtime.close_acme()
        self.assertIn(['nft', 'flush', 'set'], calls, 'a failed delete is followed by flushing the set')
        closed = {'nftables': [{'set': {'name': 'acme_http'}}]}
        with patch.object(node_runtime, 'command', side_effect=lambda args, **kw: done(json.dumps(closed).encode())):
            runtime.close_acme()

    def test_h07_tls_mask_probe_excludes_the_local_segment(self):
        runtime = self.runtime()
        runtime.store.load.return_value = {'options': {'cover': False, 'transport': 'reality', 'mask': 'mask.example.test', 'family': 4}}
        neighbour = '11.77.0.9'
        with patch.object(runtime, 'routed_host', return_value=dict(HOST, onlink=['11.77.0.0/24'])), \
                patch.object(node_runtime.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', (neighbour, 443))]), \
                patch.object(node_runtime.config, 'public_ip', side_effect=lambda ip: ip), \
                patch.object(runtime, 'probe_tls') as probe:
            with self.assertRaisesRegex(ValueError, 'not public'):
                runtime.tls_probe()
            probe.assert_not_called()


class Setup(unittest.TestCase):
    def install(self, root, backend_stop=None, fail=ValueError('nftables service is not active and enabled'), existing=False, on_apply=None, on_start=None, remove_fails=False):
        account = SimpleNamespace(pw_uid=59999, pw_gid=59999)
        calls, order = [], []
        def command(args, **kwargs):
            calls.append(args)
            if on_start and args[:2] == ['systemctl', 'start']:
                on_start()
            if remove_fails and args[:3] == ['nft', 'delete', 'table']:
                return done(returncode=1)
            if args[:3] == ['nft', 'list', 'table']:
                return SimpleNamespace(stdout=b'', returncode=0 if existing else 1)
            if args[:2] == ['nft', '-f']:
                order.append(('load', (root/'guard.nft').exists()))
            return SimpleNamespace(stdout=b'', returncode=0)
        configure = MagicMock(side_effect=lambda **kw: order.append(('service', (root/'guard.nft').exists())))
        patches = [patch.object(setup, 'ROOT', root), patch.object(setup.install, 'ETC', root),
                   patch.object(setup, 'preflight'), patch.object(setup.install, 'accounts', return_value=account),
                   patch.object(setup, 'prepare_docker', return_value=False), patch.object(setup, 'disable_forwarding'),
                   patch.object(setup.pwd, 'getpwnam', side_effect=lambda name: SimpleNamespace(pw_uid=59998 if name == setup.install.COVER else 59997)),
                   patch.object(setup.install, 'install_code'), patch.object(setup.install, 'install_ssh', return_value={'fixture': 1}),
                   patch.object(setup.install, 'restore_ssh'),
                   patch.object(setup.image_bundle, 'read', return_value={'images': {'xr': 'fixture'}}),
                   patch.object(setup, 'command', side_effect=command), patch.object(setup.nft_host_setup, 'configure', configure),
                   patch.object(setup, 'Runtime'), patch.object(setup.state, 'Store'), patch.object(setup, 'drop_stale_docker_rules'),
                   patch.object(setup, 'verify_firewall', side_effect=fail)]
        for item in patches:
            item.start()
        try:
            store = setup.state.Store.return_value
            store.current.return_value = None
            store.root = root
            store.activate.side_effect = lambda generation: (root/'current.json').write_text('fixture')
            backend = setup.Runtime.return_value
            backend.identity.return_value = {}
            backend.routed_host.return_value = setup.config.deployment(HOST)
            backend.transaction.side_effect = lambda rules: rules
            backend.guard = root/'guard.nft'
            if on_apply:
                backend.apply.side_effect = on_apply
            if backend_stop is not None:
                backend.stop.side_effect = backend_stop
            try:
                setup.setup(self.enrollment(), root, bundle=root/'bundle.json')
            except BaseException as error:
                return error, backend, order, calls
            return None, backend, order, calls
        finally:
            for item in reversed(patches):
                item.stop()

    def enrollment(self):
        probe = node_setup_test.NodeSetup('test_public_enrollment')
        probe.setUp()
        return copy.deepcopy(probe.value)

    def test_partial_activation_identifies_its_generation_before_listeners_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seen = []
            self.install(root, on_apply=lambda generation: seen.append((root/'current.json').is_file()))
            self.assertEqual(seen, [True])

    def test_other_installer_cannot_enter_during_service_handoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            observed = []
            def try_again():
                error, backend, _order, _calls = self.install(root)
                observed.append((isinstance(error, BlockingIOError), backend.apply.called))
            self.install(root, on_start=try_again)
            self.assertEqual(observed, [(True, False)])

    def test_successful_cleanup_releases_table_ownership(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.install(root)
            error, _, order, _ = self.install(root, existing=True)
            self.assertIn('без её состояния', str(error))
            self.assertEqual(order, [])

    def test_retry_refuses_table_predating_installation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for attempt in range(2):
                with self.subTest(attempt=attempt):
                    error, _, order, calls = self.install(root, existing=True)
                    self.assertIn('без её состояния', str(error))
                    self.assertEqual(order, [])
                    self.assertNotIn(['nft', 'delete', 'table', 'inet', 'vpnbot_node'], calls)

    def test_c01_guard_is_on_disk_before_nftables_service_may_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            error, backend, order, _ = self.install(Path(tmp))
            self.assertIsInstance(error, ValueError)
            self.assertEqual(order[:2], [('load', True), ('service', True)])

    def test_b04_rollback_keeps_the_guard_when_docker_cannot_confirm_the_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            error, backend, _, calls = self.install(root, backend_stop=node_runtime.HostOperationError('docker', 1))
            self.assertIsInstance(error, ValueError)
            self.assertTrue((root/'guard.nft').exists(), 'the restrictive guard stays for recovery')
            self.assertTrue((root/'current.json').exists(), 'the state stays for recovery')
            self.assertNotIn(['nft', 'delete', 'table', 'inet', 'vpnbot_node'], calls)
            self.assertTrue((root/setup.SETUP_MARK).exists(), 'a later attempt recognises this one')

    def test_c10_interrupt_rolls_back_and_the_next_attempt_resumes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            error, backend, _, calls = self.install(root, fail=KeyboardInterrupt(), remove_fails=True)
            self.assertIsInstance(error, KeyboardInterrupt)
            backend.stop.assert_called_once_with()
            self.assertIn(['nft', 'delete', 'table', 'inet', 'vpnbot_node'], calls)
            self.assertTrue((root/setup.SETUP_MARK).exists(), 'the attempt stays recognisable')
            # Rules of the interrupted attempt (kernel kept them) are this installer's own.
            error, *_ = self.install(root, fail=None, existing=True)
            self.assertNotIn('без её состояния', str(error))

    def test_c10_own_accounts_are_taken_back_after_an_interruption(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mark = root/'setup.json'
            mark.write_bytes(node_install.state.encode({'schema': 1, 'accounts': [node_install.CONTROL]}))
            existing = {node_install.CONTROL: SimpleNamespace(pw_uid=990, pw_gid=990, pw_shell='/bin/sh')}
            created = []
            def getpwnam(name):
                if name in existing:
                    return existing[name]
                raise KeyError(name)
            def command(args, **kwargs):
                if args[0] == 'useradd':
                    created.append(args[-1])
                    existing[args[-1]] = SimpleNamespace(pw_uid=991, pw_gid=991, pw_shell=args[-2])
                return done()
            with patch.object(node_install, 'ETC', root), patch.object(node_install.pwd, 'getpwnam', side_effect=getpwnam), \
                    patch.object(node_install, 'command', side_effect=command), patch.object(node_install.state, 'trusted'), \
                    patch.object(node_install.Path, 'mkdir'):
                node_install.accounts(mark)
            self.assertEqual(sorted(created), sorted({node_install.CORE, node_install.COVER, node_install.AWG}))
            self.assertEqual(set(json.loads(mark.read_bytes())['accounts']),
                             {node_install.CONTROL, node_install.CORE, node_install.COVER, node_install.AWG})
            existing[node_install.CORE] = SimpleNamespace(pw_uid=992, pw_gid=992, pw_shell='/usr/sbin/nologin')
            with patch.object(node_install, 'ETC', root), patch.object(node_install.pwd, 'getpwnam', side_effect=getpwnam), \
                    self.assertRaisesRegex(ValueError, 'already in use'):
                node_install.accounts(None)

    def test_c12_control_account_uses_only_the_controller_key_file(self):
        text = node_install.ssh_configuration('')
        for line in ('AuthorizedKeysFile /etc/vpnbot-node/controller.pub', 'AuthorizedKeysCommand none', 'PubkeyAcceptedAlgorithms ssh-ed25519'):
            self.assertIn('    ' + line, text)
        source = (ROOT/'scripts/node_install.py').read_text()
        for line in ('authorizedkeyscommand none', 'pubkeyacceptedalgorithms ssh-ed25519', 'authorizedkeysfile /etc/vpnbot-node/controller.pub'):
            self.assertIn("'" + line + "'", source, 'the effective policy is read back per source address')


class Delta(unittest.TestCase):
    def doc(self, *items):
        return {'nftables': list(items)}

    def test_c02_stale_docker_table_gets_the_profile_chains(self):
        template = self.doc({'table': {'family': 'ip', 'name': 'filter'}},
                            {'chain': {'family': 'ip', 'table': 'filter', 'name': 'input', 'type': 'filter', 'hook': 'input', 'prio': 0, 'policy': 'drop'}},
                            {'rule': {'family': 'ip', 'table': 'filter', 'chain': 'input', 'expr': [{'match': {'op': '==', 'left': {'meta': {'key': 'iifname'}}, 'right': 'eth0'}}, {'drop': None}]}})
        rendered = copy.deepcopy(template)
        rendered['nftables'][2]['rule']['expr'][0]['match']['right'] = 'ens3'
        docker = self.doc({'table': {'family': 'ip', 'name': 'filter'}},
                          {'chain': {'family': 'ip', 'table': 'filter', 'name': 'DOCKER-USER'}},
                          {'chain': {'family': 'ip', 'table': 'filter', 'name': 'FORWARD', 'type': 'filter', 'hook': 'forward', 'prio': 0, 'policy': 'drop'}})
        change, rollback = nft_host_setup.delta(template, rendered, docker)
        added = [c['add'] for c in change['nftables'] if 'add' in c]
        self.assertIn('chain', added[0])
        self.assertEqual(added[1]['rule']['expr'][0]['match']['right'], 'ens3')
        self.assertFalse(any('table' in a for a in added), 'the leftover table is kept, not re-created')
        self.assertIn({'delete': {'chain': {'family': 'ip', 'table': 'filter', 'name': 'input'}}}, rollback['nftables'])
        # A table that has the profile's chains is still compared rule by rule.
        live = copy.deepcopy(template)
        change, _ = nft_host_setup.delta(template, rendered, live)
        self.assertEqual(change['nftables'][0], {'flush': {'chain': {'family': 'ip', 'table': 'filter', 'name': 'input'}}})


class Transport(unittest.TestCase):
    def client(self, tmp):
        return transport.Client('aabbccdd', Path(tmp)/'nodes')

    def snapshot(self, marker):
        return {'schema': 1, 'options': {'marker': marker}, 'identity': {}, 'peers': [], 'images': {}, 'tls': {}}

    def test_c19_upload_waits_beside_the_confirmed_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = self.client(tmp)
            transport.atomic(client.directory/'snapshot.json', transport.encode(self.snapshot('confirmed')))
            client.store(self.snapshot('uploaded'))
            self.assertEqual(client.saved()['snapshot']['options']['marker'], 'confirmed', 'backups keep the confirmed copy')
            self.assertEqual(client.saved(True)['snapshot']['options']['marker'], 'uploaded', 'a restore offers the upload')
            client.clear_import()
            self.assertEqual(client.saved(True)['snapshot']['options']['marker'], 'confirmed')

    def test_c24_retired_archive_stays_within_the_backup_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'retired'
            root.mkdir(mode=0o700)
            for n in range(transport.RETIRED_MAX):
                entry = root/('%032x' % n)
                entry.mkdir(mode=0o700)
                for name in ('key', 'key.pub'):
                    (entry/name).write_text('x')
                os.utime(entry, (1000+n, 1000+n))
            current = root/('f'*32)
            current.mkdir(mode=0o700)
            staging = Path(tmp)/'staging'
            staging.mkdir(mode=0o700)
            ages = transport.Client._retired_ages(root, staging)
            transport.Client._trim_retired(current, staging, ages)
            names = sorted(p.name for p in root.iterdir())
            self.assertEqual(len(names), transport.RETIRED_MAX)
            self.assertNotIn('%032x' % 0, names, 'the longest unused key makes room')


class Policy(unittest.TestCase):
    def test_c16_digest_does_not_depend_on_the_field_order(self):
        ip_first = {'block': {'ip': ['192.0.2.0/24'], 'domain': ['full:a.example']}}
        sorted_ = json.loads(json.dumps(ip_first, sort_keys=True))
        self.assertEqual(node_policy.routes_digest(ip_first), node_policy.routes_digest(sorted_))
        # PHP sends the sorted order: the same digest as json_encode there.
        import hashlib
        php = '{"block":{"domain":["full:a.example"],"ip":["192.0.2.0\\/24"]}}'.replace('\\/', '/')
        self.assertEqual(node_policy.routes_digest(ip_first), hashlib.sha256(php.encode()).hexdigest())


class Cover(unittest.TestCase):
    def test_c22_tunnel_location_has_no_site_body_limit(self):
        for transport_name in ('grpc', 'xhttp', 'trojan-grpc'):
            conf = node_cover.nginx({'domain': 'node.example.test', 'transport': transport_name, 'cover': True}, {'path': 'p'*32}, False)
            location = conf[conf.index('location /'+'p'*32):]
            location = location[:location.index(' }')]
            with self.subTest(transport=transport_name):
                self.assertIn('client_max_body_size 0;', location)
                self.assertIn('client_body_timeout 3600s;', location)
            self.assertIn(' client_max_body_size 2m;', conf, 'the site itself keeps its limit')


class Ipv6(unittest.TestCase):
    def rule(self, *expr):
        return list(expr)

    def match(self, key, value, protocol=None):
        left = {'meta': {'key': key}} if protocol is None else {'payload': {'protocol': 'ip6', 'field': key}}
        return {'match': {'op': '==', 'left': left, 'right': value}}

    def test_c23_empty_forward_is_not_ready(self):
        with self.assertRaisesRegex(ValueError, 'forward'):
            ipv6_egress.check_forward([], 'eth0')
        egress = self.rule(self.match('iifname', 'br-vpnbot6'), self.match('oifname', 'eth0'),
                           self.match('saddr', ipv6_egress.SOURCE, 'ip6'), {'counter': None}, {'accept': None})
        reply = self.rule(self.match('iifname', 'eth0'), self.match('oifname', 'br-vpnbot6'), self.match('daddr', ipv6_egress.SOURCE, 'ip6'),
                          {'match': {'op': 'in', 'left': {'ct': {'key': 'state'}}, 'right': 'established'}}, {'accept': None})
        ipv6_egress.check_forward([egress, reply], 'eth0')
        with self.assertRaises(ValueError):
            ipv6_egress.check_forward([[{'counter': None}, {'drop': None}], egress, reply], 'eth0')
        with self.assertRaises(ValueError):
            ipv6_egress.check_forward([egress, reply], 'ens3')


if __name__ == '__main__':
    unittest.main()
