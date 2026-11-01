#!/usr/bin/env python3
"""Own-domain password cover, transport separation and exact egress exceptions."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import node_config as config
import node_cover as cover
from node_config_test import HOST, KEYS, OPTIONS


class NodeCover(unittest.TestCase):
    def test_password_hash_cost_is_bounded(self):
        for cost in ('00', '03', '13', '31', '99'):
            with self.subTest(cost=cost), self.assertRaises(ValueError):
                cover.password_hash('$2y$'+cost+'$'+'a'*53)
        for cost in ('04', '10', '12'):
            self.assertEqual(cover.password_hash('$2y$'+cost+'$'+'a'*53), '$2y$'+cost+'$'+'a'*53)

    def setUp(self):
        self.host = HOST | {'cover_uid': 997}
        self.options = OPTIONS | {'cover': True, 'domain': 'node.example.test'}

    def test_own_domain_reality_and_clients_agree(self):
        options = config.settings(self.options)
        server = config.core_config(options, self.host, KEYS)['inbounds'][0]
        client = config.client_outbound(options, self.host, KEYS)
        self.assertEqual(server['streamSettings']['realitySettings']['dest'], '127.0.0.1:9443')
        self.assertEqual(server['streamSettings']['realitySettings']['serverNames'], ['node.example.test'])
        self.assertEqual(client['streamSettings']['realitySettings']['serverName'], 'node.example.test')

    def test_tls_core_private_and_client_still_tls(self):
        for transport in ('ws', 'grpc', 'xhttp'):
            options = self.options | {'transport': transport}
            server = config.core_config(options, self.host, KEYS)['inbounds'][0]
            client = config.client_outbound(options, self.host, KEYS)
            self.assertEqual((server['listen'], server['port']), ('127.0.0.1', 9444))
            self.assertEqual(server['streamSettings']['security'], 'none')
            self.assertNotIn('tlsSettings', server['streamSettings'])
            self.assertEqual(client['streamSettings']['security'], 'tls')

    def test_cover_requires_domain_and_separate_uid(self):
        with self.assertRaises(ValueError):
            config.settings(self.options | {'domain': ''})
        with self.assertRaises(ValueError):
            config.core_config(self.options, HOST, KEYS)
        with self.assertRaises(ValueError):
            config.deployment(HOST | {'cover_uid': HOST['uid']})

    def test_core_private_acl_is_not_disabled_for_cover(self):
        server = config.core_config(self.options, self.host, KEYS)
        self.assertIn('127.0.0.0/8', server['outbounds'][0]['settings']['finalRules'][0]['ip'])
        rules = config.firewall(self.options, self.host)
        self.assertIn('ip daddr 127.0.0.1 tcp dport 9443 accept', rules)
        self.assertIn('meta skuid 997 oifname "lo" ip daddr 127.0.0.1 tcp dport 9444 accept', rules)
        self.assertIn('meta skuid 997 counter drop', rules)
        disabled = config.firewall(OPTIONS, self.host)
        self.assertNotIn('tcp dport 9443 accept', disabled)

    def test_basic_auth_and_private_files_are_guarded(self):
        for transport in config.TRANSPORTS:
            text = cover.nginx(config.settings(self.options | {'transport': transport}), KEYS, True)
            self.assertIn('auth_basic "Restricted Content"', text)
            self.assertIn('auth_basic_user_file /node/htpasswd', text)
            self.assertIn('location ~ /\\.', text)
            self.assertNotIn('proxy_pass http://php', text)
            self.assertNotIn('/ssh', text)
            self.assertNotIn('privateKey', text)
            if transport == 'reality':
                self.assertIn('listen 127.0.0.1:9443 ssl;', text)
                self.assertNotIn('listen 0.0.0.0:', text)
            else:
                self.assertIn('listen [::]:8443 ssl ipv6only=on;', text)


if __name__ == '__main__':
    unittest.main()
