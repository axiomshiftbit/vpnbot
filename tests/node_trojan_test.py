#!/usr/bin/env python3
"""Trojan-gRPC on the node: same shape as the main bot, no VLESS leftovers."""
from pathlib import Path
import sys
import unittest
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import node_config as node
import node_cover

OPTIONS = dict(transport='trojan-grpc', family=4, core='origin', domain='node.example.test', mask='www.example.test')
HOST = dict(public4='11.77.0.4', public6='', sources=['11.77.0.2'], admins=['11.77.0.3'],
            routers=[], ssh_ports=[22], interface='eth0', uid=995, gid=995, cover_uid=996)
KEYS = dict(uuid='11111111-1111-4111-8111-111111111111', private='A'*43, public='B'*43,
            short_id='a1b2c3d4a1b2c3d4', path='0123456789abcdef'*2)
PEER = dict(id='22222222-2222-4222-8222-222222222222', name='panel', enabled=True)


class Trojan(unittest.TestCase):
    def test_inbound_uses_passwords_only(self):
        inbound = node.core_config(OPTIONS, HOST, KEYS, [PEER])['inbounds'][0]
        self.assertEqual(inbound['protocol'], 'trojan')
        self.assertNotIn('decryption', inbound['settings'])
        self.assertEqual([c['password'] for c in inbound['settings']['clients']], [KEYS['uuid'], PEER['id']])
        self.assertFalse([c for c in inbound['settings']['clients'] if 'id' in c or 'flow' in c])
        stream = inbound['streamSettings']
        self.assertEqual((stream['network'], stream['security']), ('grpc', 'tls'))
        self.assertEqual(stream['grpcSettings'], {'serviceName': KEYS['path']})

    def test_link_matches_the_main_bot_parser_contract(self):
        link = urlsplit(node.client_link(OPTIONS, HOST, KEYS))
        query = parse_qs(link.query)
        self.assertEqual((link.scheme, link.username, link.port), ('trojan', KEYS['uuid'], 443))
        self.assertEqual((query['type'], query['security'], query['serviceName']), (['grpc'], ['tls'], [KEYS['path']]))
        self.assertNotIn('encryption', query)
        self.assertNotIn('flow', query)

    def test_outbound_and_peer_export(self):
        exported = node.export_profile(OPTIONS, HOST, KEYS, PEER)
        out = exported['outbound']
        self.assertEqual(out['protocol'], 'trojan')
        self.assertEqual(out['settings']['password'], PEER['id'])
        self.assertNotIn('id', out['settings'])
        self.assertNotIn('encryption', out['settings'])
        self.assertIn(PEER['id'], exported['link'])
        self.assertNotIn(KEYS['uuid'], exported['link'])

    def test_vless_encryption_and_no_h2_fingerprints_are_refused(self):
        with self.assertRaises(ValueError):
            node.settings(OPTIONS | {'xray': {'encryption': {'auth': 'x25519', 'mode': 'native'}}})
        for fingerprint in ('android', '360'):
            with self.assertRaises(ValueError):
                node.settings(OPTIONS | {'xray': {'fingerprint': fingerprint}})

    def test_domain_is_required_and_cover_is_routed_over_grpc(self):
        with self.assertRaises(ValueError):
            node.settings(OPTIONS | {'domain': ''})
        cover = OPTIONS | {'cover': True}
        config = node.core_config(cover, HOST, KEYS)
        self.assertEqual((config['inbounds'][0]['listen'], config['inbounds'][0]['port']), ('127.0.0.1', 9444))
        self.assertEqual(config['inbounds'][0]['streamSettings']['security'], 'none')
        self.assertIn('location /'+KEYS['path']+' {', node_cover.nginx(cover, KEYS, False))
        self.assertIn('grpc_pass grpc://127.0.0.1:9444;', node_cover.nginx(cover, KEYS, False))

    def test_other_transports_keep_vless(self):
        for transport in ('reality', 'ws', 'grpc', 'xhttp'):
            inbound = node.core_config(OPTIONS | {'transport': transport}, HOST, KEYS)['inbounds'][0]
            self.assertEqual(inbound['protocol'], 'vless')
            self.assertEqual(inbound['settings']['decryption'], 'none')


if __name__ == '__main__':
    unittest.main()
