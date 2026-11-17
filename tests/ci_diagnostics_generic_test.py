#!/usr/bin/env python3
"""Encrypted diagnostics also mask generic credentials of the disposable stand.

Known token formats were redacted before; arbitrary passwords, WireGuard and
Reality private keys and secret command-line arguments were packed (still
encrypted, synthetic, one-time). They are masked now, while ordinary result
fields stay readable for diagnosis. Values are built from parts.
"""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import ci_diagnostics as diag

V = b'synthetic' + b'-secret-' + b'7f3a9c'          # the value that must disappear
KEY = b'kO7yq' + b'2N0a' * 9 + b'Qe8='              # WireGuard-like base64 key


class GenericRedactionTest(unittest.TestCase):
    def masked(self, data):
        counts = {}
        out = diag.redact(data, counts, [])
        return out, counts

    def test_generic_credentials_are_masked(self):
        cases = {
            'json password': b'{"name":"alice","password":"' + V + b'","passed":true}',
            'json passwd': b'{"auth_passwd": "' + V + b'"}',
            'json secret': b'{"client_secret":"' + V + b'"}',
            'json private key': b'{"privateKey":"' + V + b'","shortIds":[]}',
            'json psk': b'{"psk":"' + V + b'"}',
            'key=value': b'login ok password=' + V + b' user=bob',
            'key: value': b'Password: ' + V + b'\n',
            'wireguard private': b'[Interface]\nPrivateKey = ' + KEY + b'\nAddress = 10.8.0.2/32\n',
            'wireguard preshared': b'[Peer]\nPresharedKey = ' + KEY + b'\n',
            'cli --password': b'/usr/bin/tool --password ' + V + b' --port 443',
            'cli --passwd=': b'/usr/bin/tool --passwd=' + V,
            'cli --secret': b'proxy --secret ' + V,
            'shell export': b'export AUTH_PASSWORD="' + V + b'"',
        }
        for name, data in cases.items():
            with self.subTest(name):
                out, counts = self.masked(b'before ' + data + b' after')
                self.assertNotIn(V, out)
                self.assertNotIn(KEY, out)
                self.assertTrue(counts)
                self.assertIn(b'before', out); self.assertIn(b'after', out)

    def test_result_fields_stay_readable(self):
        data = (b'{"name":"wrong-password-rejected","passed":true,"total":3,"checks":7}\n'
                b'PASS server_rejects_wrong_password\nFAIL tls-certificate-password-handshake\n'
                b'DIAGNOSTIC TCP curl code 52\npassword-mode installations only\n')
        out, counts = self.masked(data)
        self.assertEqual(out, data)
        self.assertEqual(counts, {})

    def test_key_names_survive_for_diagnosis(self):
        out, _ = self.masked(b'{"password":"' + V + b'"}\nPrivateKey = ' + KEY + b'\n')
        self.assertIn(b'"password":"[REDACTED:', out)
        self.assertIn(b'PrivateKey = [REDACTED:', out)


if __name__ == '__main__':
    unittest.main()
