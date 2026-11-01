#!/usr/bin/env python3
import base64
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import node_config as c
import node_wg as wg
from node_config_test import HOST, KEYS, OPTIONS

class NodeWireGuard(unittest.TestCase):
    def setUp(self):
        self.keys = KEYS | {'wireguard': {name: base64.b64encode(bytes([n])*32).decode() for n, name in enumerate(
            ['server_private', 'server_public', 'client_private', 'client_public', 'psk'], 1)}}
        self.options = OPTIONS | {'wireguard': {'enabled': True, 'active': True, 'mtu': 1280}}

    def test_closed_schema(self):
        for value in ({'active': True}, {'enabled': 1}, {'enabled': True, 'mtu': 1500}, {'command': 'id'}):
            with self.assertRaises(ValueError): wg.settings(value)
        for value in ('a'*44, base64.b64encode(b'\0'*32).decode(), 'x'*43):
            with self.assertRaises(ValueError): wg.key(value)

    def test_profiles_keep_server_secret_local_and_external_peers_on_vless(self):
        profile = c.export_profile(self.options, HOST, self.keys)
        self.assertEqual(profile['channel'], 'wireguard')
        self.assertEqual(profile['outbound']['settings']['secretKey'], self.keys['wireguard']['client_private'])
        self.assertNotIn(self.keys['wireguard']['server_private'], str(profile))
        peer = dict(id='22222222-2222-4222-8222-222222222222', name='panel', enabled=True)
        external = c.export_profile(self.options, HOST, self.keys, peer)
        self.assertEqual(external['outbound']['protocol'], 'vless')
        self.assertNotIn('wireguard', str(external))

    def test_node_ingress_uses_regular_egress_and_torrent_guards(self):
        options = self.options | {'xray': {'block_torrent': True}}
        core = c.core_config(options, HOST, self.keys)
        self.assertEqual(core['inbounds'][1]['settings']['peers'][0]['allowedIPs'], wg.ADDRESSES)
        self.assertEqual(core['outbounds'][0]['settings']['finalRules'], c.core_config(OPTIONS, HOST, KEYS)['outbounds'][0]['settings']['finalRules'])
        self.assertIn('node-wg4', core['routing']['rules'][0]['inboundTag'])
        self.assertIn('node-wg6', core['routing']['rules'][0]['inboundTag'])
        self.assertEqual([item['listen'] for item in core['inbounds'][1:]], [HOST['public4'], HOST['public6']])
        self.assertTrue(core['inbounds'][1]['sniffing']['enabled'])

    def test_transport_and_egress_families_independent(self):
        for family in (4, 6):
            for connection in (4, 6):
                value = c.export_profile(self.options | {'family': family, 'connect_family': connection}, HOST, self.keys)['outbound']['settings']
                self.assertEqual(value['address'], [wg.ADDRESSES[family == 6]])
                self.assertEqual('[' in value['peers'][0]['endpoint'], connection == 6)
                self.assertEqual(':' in value['remoteDNS'][0], family == 6)

    def test_disabled_backup_has_no_listener_or_firewall_opening(self):
        self.assertEqual(len(c.core_config(OPTIONS, HOST, KEYS)['inbounds']), 1)
        self.assertNotIn('51820', c.firewall(OPTIONS, HOST))
        self.assertIn('udp dport 51820 dnat ip to '+HOST['public4']+':51830', c.firewall(self.options, HOST))
        self.assertIn('udp dport 51820 dnat ip6 to ['+HOST['public6']+']:51830', c.firewall(self.options, HOST))

if __name__ == '__main__': unittest.main()
