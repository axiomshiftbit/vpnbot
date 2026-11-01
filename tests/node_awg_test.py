#!/usr/bin/env python3
import base64
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import node_awg as awg


class Amnezia(unittest.TestCase):
    def setUp(self):
        pairs = iter((b'p', b'r'))
        self.keys = awg.generate(lambda: dict(private=base64.urlsafe_b64encode(next(pairs)*32).decode().rstrip('='),
                                             public=base64.urlsafe_b64encode(b'q'*32).decode().rstrip('=')))
        self.value = awg.profile({'enabled': True, 'active': True}, '1.1.1.1', self.keys)

    def test_generated_profiles_are_bounded_and_valid(self):
        for _ in range(50):
            self.setUp()
            self.assertTrue(awg.identity(self.keys) == self.keys, 'generated identity is valid')
            self.assertTrue(awg.validate_client(self.value) == self.value, 'generated client is valid')

    def test_only_fixed_vless_targets_and_loopback_listeners(self):
        server = awg.server({'enabled': True}, self.keys)
        client = awg.client(self.value, 7)
        self.assertIn('Target = 127.0.0.1:8443\n', server)
        self.assertIn('AllowedIPs = 10.77.78.2/32\n', server)
        self.assertIn('BindAddress = 127.0.0.1:10927\n', client)
        self.assertIn('Target = 10.77.78.1:443\n', client)
        self.assertNotIn('[Socks5]', client+server)
        self.assertTrue(self.keys['server_private'] not in client, 'client never contains server private identity')

    def test_unsafe_endpoints_and_arbitrary_ini_rejected(self):
        for address in ('127.0.0.1', '::1', '192.168.0.1', '100.64.0.1', '64:ff9b::101:101', '2002::1', 'ff02::1', 'example.com', '1.1.1.1\nPostUp = id'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                awg.client(self.value | {'endpoint': address}, 0)
        for key, value in [('private', 'bad\nPostUp = id'), ('port', True), ('mtu', 1279), ('PostUp', 'id')]:
            with self.subTest(field=key), self.assertRaises(ValueError):
                awg.client(self.value | {key: value}, 0)

    def test_padding_header_nonce_and_timing_validation(self):
        for name, value in [('S1', 11), ('H2', self.keys['parameters']['H1']), ('RekeyAfterTime', '200-250'),
                            ('Jmin', True), ('HeaderProtectionKey', base64.b64encode(b'\0'*32).decode())]:
            copy_value = copy.deepcopy(self.value)
            copy_value['parameters'][name] = value
            with self.subTest(field=name), self.assertRaises(ValueError):
                awg.client(copy_value, 0)

    def test_ipv6_endpoint_is_unambiguous(self):
        self.assertIn('Endpoint = [2606:4700:4700::1111]:51821\n', awg.client(self.value | {'endpoint': '2606:4700:4700::1111'}, 0))
        for index in (-1, 8, True, '0'):
            with self.assertRaises(ValueError):
                awg.client(self.value, index)

    def test_cookie_dos_defense_remains_enabled(self):
        # AWG 3.1 receive.go skips both MAC2 cookies and the handshake rate
        # limiter when DisableCookies is on. Keep those upstream defenses.
        for value in (awg.server({'enabled': True}, self.keys), awg.client(self.value, 0)):
            self.assertTrue('DisableCookies = off\n' in value, 'cookie and handshake rate defenses must stay enabled')


if __name__ == '__main__':
    unittest.main()
