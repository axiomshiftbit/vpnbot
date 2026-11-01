#!/usr/bin/env python3
"""Standalone node: hostile inputs and transport/egress contracts."""
import base64
import copy
import json
import importlib.util
from pathlib import Path
import unittest
import sys
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
spec = importlib.util.spec_from_file_location('node_config', Path(__file__).resolve().parents[1] / 'scripts/node_config.py')
node = importlib.util.module_from_spec(spec)
spec.loader.exec_module(node)

OPTIONS = dict(transport='reality', family=6, core='origin', domain='', mask='www.example.test')
HOST = dict(public4='11.77.0.4', public6='2606:4700:4700::1111', sources=['11.77.0.2'],
            admins=['11.77.0.3'], routers=['fe80::1'], ssh_ports=[22], interface='eth0', uid=995, gid=995)
KEYS = dict(uuid='11111111-1111-4111-8111-111111111111', private='A'*43, public='B'*43,
            short_id='a1b2c3d4a1b2c3d4', path='0123456789abcdef'*2)


class NodeConfig(unittest.TestCase):
    def test_four_transports_keep_tls_and_identity(self):
        for transport in node.TRANSPORTS:
            with self.subTest(transport=transport):
                options = OPTIONS | {'transport': transport, 'domain': 'node.example.test'}
                config = node.core_config(options, HOST, KEYS)
                inbound = config['inbounds'][0]
                self.assertEqual(inbound['settings']['clients'][0]['id'], KEYS['uuid'])
                self.assertEqual(inbound['port'], 8443)
                self.assertEqual(inbound['streamSettings']['security'], 'reality' if transport == 'reality' else 'tls')
                self.assertNotIn('api', config)
                link = urlsplit(node.client_link(options, HOST, KEYS))
                query = parse_qs(link.query)
                self.assertEqual(link.port, 443)
                self.assertEqual(query['type'], ['tcp' if transport == 'reality' else transport])
                self.assertNotIn(KEYS['private'], link.geturl())
                self.assertEqual(query['sni'], [options['mask'] if transport == 'reality' else options['domain']])

    def test_no_unencrypted_tls_transports(self):
        for transport in ('ws', 'grpc', 'xhttp'):
            with self.subTest(transport=transport), self.assertRaises(ValueError):
                node.core_config(OPTIONS | {'transport': transport}, HOST, KEYS)

    def test_config_is_deterministic_and_does_not_mutate_inputs(self):
        before = copy.deepcopy([OPTIONS, HOST, KEYS])
        self.assertEqual(node.core_config(OPTIONS, HOST, KEYS), node.core_config(OPTIONS, HOST, KEYS))
        self.assertEqual(before, [OPTIONS, HOST, KEYS])

    def test_strict_egress_has_no_other_family_fallback(self):
        for family in (4, 6):
            out = node.core_config(OPTIONS | {'family': family}, HOST, KEYS)['outbounds'][0]
            self.assertEqual(out['sendThrough'], HOST['public'+str(family)])
            self.assertEqual(out['settings']['domainStrategy'], 'ForceIPv'+str(family))
            self.assertIn('::/0' if family == 4 else '0.0.0.0/0', out['settings']['finalRules'][0]['ip'])
            self.assertIn(HOST['public6'], out['settings']['finalRules'][0]['ip'])
        with self.assertRaises(ValueError):
            node.core_config(OPTIONS, HOST | {'public6': ''}, KEYS)

    def test_public_addresses_reject_private_special_and_injection(self):
        for ip in ('127.0.0.1', '10.0.0.1', '100.64.0.1', '169.254.169.254', '224.0.0.1',
                   '::1', 'fc00::1', 'fe80::1', 'ff0e::1', '2001:db8::1', '64:ff9b::808:808',
                   '2606:4700::1%eth0', '11.77.0.2/32', '11.77.0.2;accept', None):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                node.public_ip(ip)

    def test_deployment_rejects_unsafe_acl_identity_interface_and_ports(self):
        for patch in ({'sources': []}, {'admins': []}, {'sources': ['0.0.0.0/0']},
                      {'interface': 'eth0" accept'}, {'uid': 0}, {'gid': True},
                      {'ssh_ports': [443]}, {'ssh_ports': [80]}, {'routers': ['2606:4700::1']},
                      {'routers': ['fe80::1%eth0']}, {'extra': 'command'}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                node.deployment(HOST | patch)

    def test_remote_settings_never_accept_core_json_or_shell(self):
        for patch in ({'transport': 'http'}, {'transport': None}, {'core': []},
                      {'core': '/bin/sh'}, {'family': True}, {'family': '6'},
                      {'mask': 'localhost'}, {'mask': '11.77.0.2'}, {'domain': 'x;reboot'},
                      {'command': 'reboot'}, {'inbounds': []}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                node.settings(OPTIONS | patch)

    def test_external_credentials_are_separate_and_revocable(self):
        peer = dict(id='22222222-2222-4222-8222-222222222222', name='panel', enabled=True)
        clients = node.core_config(OPTIONS, HOST, KEYS, [peer])['inbounds'][0]['settings']['clients']
        self.assertEqual(len(clients), 2)
        self.assertEqual(clients[1]['id'], peer['id'])
        clients = node.core_config(OPTIONS, HOST, KEYS, [peer | {'enabled': False}])['inbounds'][0]['settings']['clients']
        self.assertEqual(len(clients), 1)
        for peers in ([peer, peer], [peer | {'id': KEYS['uuid']}], [peer | {'enabled': 'yes'}], [peer | {'name': '../bad'}]):
            with self.subTest(peers=peers), self.assertRaises(ValueError):
                node.core_config(OPTIONS, HOST, KEYS, peers)

    def test_ipv6_only_node_exports_bracketed_endpoint(self):
        link = urlsplit(node.client_link(OPTIONS, HOST | {'public4': ''}, KEYS))
        self.assertEqual(link.hostname, HOST['public6'])
        self.assertEqual(link.port, 443)

    def test_panel_exports_preserve_peer_identity_and_transport(self):
        peer = dict(id='22222222-2222-4222-8222-222222222222', name='panel', enabled=True)
        for transport in node.TRANSPORTS:
            options = OPTIONS | {'transport': transport, 'domain': 'node.example.test'}
            exported = node.export_profile(options, HOST, KEYS, peer)
            self.assertEqual(base64.b64decode(exported['subscription']).decode(), exported['link']+'\n')
            self.assertEqual(exported['outbound']['settings']['id'], peer['id'])
            self.assertEqual(exported['outbound']['settings']['port'], 443)
            self.assertNotIn(KEYS['private'], json.dumps(exported))
            self.assertNotIn(KEYS['uuid'], json.dumps(exported))
            self.assertNotIn('allowInsecure', json.dumps(exported))
        with self.assertRaises(ValueError):
            node.export_profile(OPTIONS, HOST, KEYS, peer | {'enabled': False})

    def test_ipv6_connection_is_independent_from_egress_and_has_no_fallback(self):
        for connection in (4, 6):
            for egress in (4, 6):
                options = OPTIONS | {'connect_family': connection, 'family': egress}
                exported = node.export_profile(options, HOST, KEYS)
                self.assertEqual(urlsplit(exported['link']).hostname, HOST['public'+str(connection)])
                self.assertEqual(exported['outbound']['settings']['address'], HOST['public'+str(connection)])
                self.assertEqual(node.core_config(options, HOST, KEYS)['outbounds'][0]['sendThrough'], HOST['public'+str(egress)])
        with self.assertRaises(ValueError):
            node.export_profile(OPTIONS | {'connect_family': 6}, HOST | {'public6': ''}, KEYS)
        for family in (True, '6', 7):
            with self.assertRaises(ValueError):
                node.settings(OPTIONS | {'connect_family': family})

    def test_firewall_acl_dnat_window_and_core_owner(self):
        rules = node.firewall(OPTIONS, HOST)
        for fragment in ('priority -110', 'redirect to :8443', 'ct original proto-dst 443',
                         'ct original proto-dst @acme_http', 'timeout 10m', 'meta skuid 995',
                         'policy drop', 'ip6 saddr @ipv6_routers', 'node_syn4', 'node_syn6'):
            self.assertIn(fragment, rules)
        self.assertNotIn('flush ruleset', rules)
        self.assertNotIn('elements = { 80 }', rules)
        self.assertIn('ip6 daddr 2000::/3', rules)
        self.assertNotIn('oifname "eth0" ip daddr 0.0.0.0/0', rules)


if __name__ == '__main__':
    unittest.main()
