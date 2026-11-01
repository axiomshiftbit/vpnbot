#!/usr/bin/env python3
"""The node's own WAN segment is a local network: closed to VPN clients."""
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

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

    def test_routes_become_local_networks(self):
        self.assertEqual(sorted(self.routed()['onlink']),
                         sorted(['11.77.0.0/24', '11.77.0.200/32', '2606:4700:10::/44', '2606:4700:10::1/128']))

    def test_too_short_prefix_and_private_routes_are_ignored(self):
        onlink = self.routed()['onlink']
        self.assertFalse([net for net in onlink if net.endswith('/8')])
        self.assertFalse([net for net in onlink if net.startswith(('10.', 'fe80'))])

    def test_route_failure_keeps_the_fixed_ranges(self):
        with patch.object(node_runtime, 'command', lambda *_, **__: SimpleNamespace(returncode=1, stdout=b'')):
            self.assertEqual(node_runtime.Runtime(None, HOST).routed_host()['onlink'], [])

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
        with patch.object(node_setup, 'command', command), patch.dict('os.environ', {'SSH_CONNECTION': ''}):
            node_setup.preflight({'deployment': HOST | {'public6': '', 'ssh_networks': []}})


if __name__ == '__main__':
    unittest.main()
