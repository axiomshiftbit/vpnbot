#!/usr/bin/env python3
"""Advanced VLESS options must remain paired, bounded and core-compatible."""
import base64
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import node_config as config
import node_xray as xray
from node_config_test import HOST, KEYS, OPTIONS


def raw(length):
    return base64.urlsafe_b64encode(b'x'*length).decode().rstrip('=')


def encryption(auth):
    lengths = {'x25519': (32, 32), 'mlkem768': (64, 1184)}[auth]
    return dict(auth=auth, decryption='mlkem768x25519plus.native.600s.'+raw(lengths[0]),
                encryption='mlkem768x25519plus.native.0rtt.'+raw(lengths[1]))


class NodeXray(unittest.TestCase):
    def test_all_bundled_core_choices(self):
        for core in ('origin', 'origin2', 'origin3', 'fork'):
            self.assertEqual(config.settings(OPTIONS | {'core': core})['core'], core)

    def test_every_encryption_mode_paired_on_server_link_and_json(self):
        from urllib.parse import parse_qs, urlsplit
        for auth in ('x25519', 'mlkem768'):
            for mode in ('native', 'xorpub', 'random'):
                options = OPTIONS | {'xray': {'encryption': {'auth': auth, 'mode': mode}}}
                keys = KEYS | {'encryption': encryption(auth)}
                server = config.core_config(options, HOST, keys)
                exported = config.export_profile(options, HOST, keys)
                expected = encryption(auth)['encryption'].replace('.native.', '.'+mode+'.')
                self.assertEqual(exported['outbound']['settings']['encryption'], expected)
                self.assertEqual(parse_qs(urlsplit(exported['link']).query)['encryption'], [expected])
                self.assertEqual(server['inbounds'][0]['settings']['decryption'],
                                 encryption(auth)['decryption'].replace('.native.', '.'+mode+'.'))
                self.assertNotIn(keys['encryption']['decryption'], str(exported))

    def test_missing_or_wrong_encryption_keys_fail_closed(self):
        options = OPTIONS | {'xray': {'encryption': {'auth': 'mlkem768'}}}
        for keys in (KEYS, KEYS | {'encryption': encryption('x25519')}):
            with self.assertRaises(ValueError):
                config.core_config(options, HOST, keys)
            with self.assertRaises(ValueError):
                config.export_profile(options, HOST, keys)

    def test_mldsa_seed_server_only_verify_exported(self):
        options = OPTIONS | {'xray': {'reality': {'mldsa': True}}}
        keys = KEYS | {'mldsa': {'seed': raw(32), 'verify': raw(1952)}}
        server = config.core_config(options, HOST, keys)
        exported = config.export_profile(options, HOST, keys)
        self.assertEqual(server['inbounds'][0]['streamSettings']['realitySettings']['mldsa65Seed'], raw(32))
        self.assertEqual(exported['outbound']['streamSettings']['realitySettings']['mldsa65Verify'], raw(1952))
        self.assertNotIn('mldsa65Seed', str(exported))
        self.assertNotIn('privateKey', str(exported))

    def test_smux_and_halfclose_core_protocol_compatibility(self):
        for options in (OPTIONS | {'xray': {'smux': {'enabled': True}}},
                        OPTIONS | {'core': 'fork', 'xray': {'smux': {'enabled': True, 'protocol': 'h2mux', 'half_close': 'require'}}}):
            with self.assertRaises(ValueError):
                config.settings(options)
        options = OPTIONS | {'core': 'fork', 'xray': {'smux': {'enabled': True, 'half_close': 'require'}}}
        outbound = config.client_outbound(options, HOST, KEYS)
        self.assertEqual(outbound['smux']['logicalHalfClose'], 'require')
        self.assertEqual(outbound['smux']['maxConnections'], 3)

    def test_smux_capacity_modes_are_mutually_exclusive(self):
        options = OPTIONS | {'core': 'fork', 'xray': {'smux': {'enabled': True, 'max_streams': 16}}}
        smux = config.client_outbound(options, HOST, KEYS)['smux']
        self.assertEqual((smux['maxConnections'], smux['minStreams'], smux['maxStreams']), (0, 0, 16))

    def test_h2mux_frame_and_brutal_on_server(self):
        options = OPTIONS | {'core': 'fork', 'xray': {'smux': {'enabled': True, 'protocol': 'h2mux',
                  'h2mux_frame': 32768, 'brutal': {'enabled': True, 'up': '20 Mbps', 'down': '30 Mbps'}}}}
        server = config.core_config(options, HOST, KEYS)['inbounds'][0]['smux']
        self.assertEqual(server['h2muxMaxReadFrameSize'], 32768)
        self.assertEqual(server['brutal-opts']['up'], '20 Mbps')

    def test_arbitrary_config_and_unsafe_values_rejected(self):
        for value in ({'outbounds': []}, {'smux': {'h2mux_frame': 10}}, {'smux': {'max_streams': -1}},
                      {'smux': {'brutal': {'up': '999999999999 Gbps'}}}, {'reality': {'dest': '127.0.0.1:22'}},
                      {'tls': {'allowInsecure': True}}, {'fingerprint': 'invalid'}, {'encryption': {'auth': 'unknown'}}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                config.settings(OPTIONS | {'xray': value})

    def test_xhttp_mux_requires_fork_and_emits_keepalive(self):
        options = OPTIONS | {'transport': 'xhttp', 'domain': 'node.example.test', 'core': 'fork',
                             'xray': {'xhttp': {'mux': True}}}
        client = config.client_outbound(options, HOST, KEYS)
        self.assertEqual(client['mux']['xudpProxyUDP443'], 'allow')
        server = config.core_config(options, HOST, KEYS)
        self.assertIn('muxKeepAliveSecs', server['inbounds'][0]['streamSettings']['xhttpSettings']['extra'])
        with self.assertRaises(ValueError):
            config.settings(options | {'core': 'origin'})

    def test_dpi_client_and_server_are_independent(self):
        options = OPTIONS | {'xray': {'dpi': {'fragment': {'enabled': True, 'length': '40-60'}}}}
        server = config.core_config(options, HOST, KEYS)
        client = config.client_outbound(options, HOST, KEYS)
        self.assertNotIn('finalmask', server['inbounds'][0]['streamSettings'])
        self.assertEqual(client['streamSettings']['finalmask']['tcp'][0]['settings']['length'], '40-60')
        options['xray']['finalmask'] = {'fragment': {'enabled': True, 'length': '100-200'}}
        server = config.core_config(options, HOST, KEYS)
        self.assertEqual(server['inbounds'][0]['streamSettings']['finalmask']['tcp'][0]['settings']['length'], '100-200')

    def test_torrent_requires_sniffing_and_preserves_private_guard(self):
        options = OPTIONS | {'xray': {'block_torrent': True}}
        server = config.core_config(options, HOST, KEYS)
        self.assertEqual(server['routing']['rules'][0]['protocol'], ['bittorrent'])
        self.assertIn('127.0.0.0/8', server['outbounds'][0]['settings']['finalRules'][0]['ip'])
        for sniffing in ({'enabled': False}, {'metadataOnly': True}):
            with self.assertRaises(ValueError):
                config.settings(OPTIONS | {'xray': {'block_torrent': True, 'sniffing': sniffing}})

    def test_bounded_noise_expressions_and_packet_sizes(self):
        options = OPTIONS | {'xray': {'finalmask': {'noise': {'enabled': True, 'list': [
            {'type': 'exp', 'packet': '<b 0d0a><t><c><n><rc 20-40><rd 4-8>', 'delay': '1-3'}]}}}}
        config.core_config(options, HOST, KEYS)
        with self.assertRaises(ValueError):
            config.settings(options | {'core': 'origin3'})
        for packet in ('<exec id>', '<r 1400><r 1>', 'text<t>', '<b a>', '<r 20-1>'):
            options['xray']['finalmask']['noise']['list'][0]['packet'] = packet
            with self.subTest(packet=packet), self.assertRaises(ValueError):
                config.settings(options)

    def test_snapshot_preserves_advanced_options_and_crypto(self):
        import node_state
        from node_state_test import VALUE
        value = copy.deepcopy(VALUE)
        value['options']['xray'] = {'smux': {'enabled': True}, 'encryption': {'auth': 'mlkem768'}}
        value['options']['core'] = 'fork'
        value['identity']['encryption'] = encryption('mlkem768')
        saved = node_state.snapshot(value)
        self.assertEqual(node_state.snapshot(node_state.decode(node_state.encode(saved))), saved)
        self.assertTrue(saved['options']['xray']['smux']['enabled'])


if __name__ == '__main__':
    unittest.main()
