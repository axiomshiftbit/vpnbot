#!/usr/bin/env python3
"""The node's own WAN segment is a local network: closed to VPN clients."""
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import node_config
import node_runtime
import node_setup

OPTIONS = dict(transport='reality', family=4, core='origin', domain='', mask='www.example.test')
HOST = dict(public4='11.77.0.4', public6='2606:4700:10::4', sources=['11.77.0.2'], admins=['11.77.0.2'],
            routers=[], ssh_ports=[22], interface='eth0', uid=995, gid=995)
KEYS = dict(uuid='11111111-1111-4111-8111-111111111111', private='A'*43, public='B'*43,
            short_id='a1b2c3d4a1b2c3d4', path='0123456789abcdef'*2)
ROUTES = {
    '-4': [{'dst': 'default', 'gateway': '11.77.0.200', 'flags': ['onlink']}, {'dst': '11.77.0.0/24', 'scope': 'link'},
           {'dst': '11.77.0.0/8', 'scope': 'link'}, {'dst': '10.9.0.0/24', 'gateway': '10.9.0.1'}],
    '-6': [{'dst': '2606:4700:10::/44'}, {'dst': 'fe80::/64'}, {'dst': 'default', 'gateway': '2606:4700:10::1'},
           {'dst': 'default', 'gateway': 'fe80::1'}],
}


def fake_routes(args, **_):
    return SimpleNamespace(returncode=0, stdout=json.dumps(ROUTES[args[2]]).encode())


class OnLink(unittest.TestCase):
    def routed(self):
        with patch.object(node_runtime, 'command', fake_routes):
            return node_runtime.Runtime(None, HOST).routed_host()

    def test_one_route_snapshot_feeds_validation_and_activation(self):
        from node_state_test import VALUE
        store = MagicMock()
        store.load.return_value = VALUE
        store.path.return_value = Path('/unused')
        runtime = node_runtime.Runtime(store, HOST)
        routes = self.routed()
        def command(args, **kwargs):
            return SimpleNamespace(stdout=b'', stderr=b'', returncode=1 if 'list' in args else 0)
        with patch.object(runtime, 'routed_host', side_effect=[routes, dict(routes, onlink=[]), routes]) as read, \
                patch.object(runtime, 'write_runtime'), patch.object(runtime, 'docker_arguments', return_value=[]), \
                patch.object(runtime, 'container'), patch.object(runtime, 'remember_guard'), \
                patch.object(runtime, 'stop', side_effect=RuntimeError('end of test')), \
                patch.object(node_runtime.state, 'atomic'), patch.object(node_runtime, 'command', side_effect=command), \
                patch.object(node_config, 'core_config', wraps=node_config.core_config) as core, \
                patch.object(node_config, 'firewall', wraps=node_config.firewall) as firewall:
            runtime.validate('a' * 32)
            with self.assertRaisesRegex(RuntimeError, 'end of test'):
                runtime.apply('a' * 32)
        self.assertEqual(read.call_count, 1)
        self.assertEqual(core.call_args.args[1], routes)
        self.assertTrue(all(call.args[1] == routes for call in firewall.call_args_list))

    def test_routes_become_local_networks(self):
        self.assertEqual(sorted(self.routed()['onlink']),
                         sorted(['11.77.0.0/24', '11.77.0.200/32', '2606:4700:10::/44', '2606:4700:10::1/128']))

    def test_too_short_prefix_and_private_routes_are_ignored(self):
        onlink = self.routed()['onlink']
        self.assertFalse([net for net in onlink if net.endswith('/8')])
        self.assertFalse([net for net in onlink if net.startswith(('10.', 'fe80'))])

    def test_route_failure_stops_instead_of_dropping_the_segment(self):
        # Audit 26.11.2026 (C04): an empty answer for a used family silently dropped the
        # neighbours and the gateway from both the Xray and the nft blocks.
        with patch.object(node_runtime, 'command', lambda *_, **__: SimpleNamespace(returncode=1, stdout=b'')):
            with self.assertRaisesRegex(ValueError, 'route snapshot unavailable'):
                node_runtime.Runtime(None, HOST).routed_host()
        # A family without a public address of the node may be absent in the kernel.
        reply = lambda args, **_: SimpleNamespace(returncode=1 if args[2] == '-6' else 0, stdout=b'[]')
        with patch.object(node_runtime, 'command', reply):
            self.assertEqual(node_runtime.Runtime(None, HOST | {'public6': ''}).routed_host()['onlink'], [])

    def test_both_layers_deny_the_segment_and_keep_real_internet(self):
        host = self.routed()
        for family in (4, 6):
            options = OPTIONS | {'family': family}
            rules = node_config.firewall(options, host)
            self.assertIn('11.77.0.0/24', rules)
            self.assertIn('2606:4700:10::/44', rules)
            # Overlaps inside one anonymous set are rejected by nft.
            self.assertNotIn(', 11.77.0.4,', rules)
            self.assertNotIn('11.77.0.200', rules)
            final = node_config.core_config(options, host, KEYS)['outbounds'][0]['settings']['finalRules']
            self.assertIn('11.77.0.0/24', final[0]['ip'])
            self.assertIn('2606:4700:10::/44', final[0]['ip'])
            self.assertEqual(final[1]['action'], 'allow')

    def test_remote_settings_and_backups_cannot_supply_it(self):
        with self.assertRaises(ValueError):
            node_config.settings(OPTIONS | {'onlink': ['0.0.0.0/0']})
        with self.assertRaises(ValueError):
            node_config.deployment(HOST | {'onlink': ['not-a-network']})


class Fingerprints(unittest.TestCase):
    def test_no_h2_samples_are_refused_for_h2_transports(self):
        for transport in ('grpc', 'xhttp'):
            for fingerprint in ('android', '360'):
                with self.assertRaises(ValueError):
                    node_config.settings(OPTIONS | {'transport': transport, 'domain': 'n.example.test',
                                                    'xray': {'fingerprint': fingerprint}})
        for fingerprint in ('android', '360'):
            node_config.settings(OPTIONS | {'transport': 'ws', 'domain': 'n.example.test', 'xray': {'fingerprint': fingerprint}})


class PeerNames(unittest.TestCase):
    def peer(self, number, name):
        return dict(id=f'22222222-2222-4222-8222-22222222222{number}', name=name, enabled=True)

    def test_names_the_core_would_reject_are_refused(self):
        for names in (['controller'], ['Controller'], ['panel', 'Panel'], ['a1', 'a1']):
            with self.subTest(names=names), self.assertRaises(ValueError):
                node_config.peers([self.peer(i, n) for i, n in enumerate(names)])
        self.assertEqual(len(node_config.peers([self.peer(0, 'panel'), self.peer(1, 'panel-2')])), 2)


class Preflight(unittest.TestCase):
    def test_amnezia_helper_is_not_a_foreign_container(self):
        answers = {'ps': b'{"Names":"vpnbot-node-amnezia"}\n', 'inspect': b'1\n'}

        def command(args, **_):
            if args[0] == 'docker':
                return SimpleNamespace(stdout=answers[args[1]])
            if args[0] == 'ip':
                return SimpleNamespace(stdout=json.dumps([{'addr_info': [{'local': HOST['public4']}]}]).encode())
            if args[0] == 'sshd':
                return SimpleNamespace(stdout=b'port 22\n')
            return SimpleNamespace(stdout=b'')
        with patch.object(node_setup, 'command', command), patch.dict('os.environ', {'SSH_CONNECTION': ''}), \
                patch.object(node_setup, 'docker_firewall_disabled'):
            node_setup.preflight({'deployment': HOST | {'public6': '', 'ssh_networks': []}})


if __name__ == '__main__':
    unittest.main()
