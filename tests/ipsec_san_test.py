"""SAN-проверки настоящим OpenSSL; только новая синтетическая PKI, без вывода ключа."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('openssl'), 'нужен openssl')
class IpsecSanTest(unittest.TestCase):
    def test_exact_ip_and_dns_sans(self):
        source = (ROOT / 'scripts/start_ipsec.sh').read_text()
        start = source.index('SAN_OK=0\n')
        block = source[start:source.index('\nif [ "$SAN_OK" != "1" ]', start)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for sans, probes in [
                ('IP:192.0.2.10,DNS:vpn.example.test.extra',
                 [('192.0.2.1', 'vpn.example.test', False), ('192.0.2.10', 'vpn.example.test.extra', True)]),
                ('IP:192.0.2.1,DNS:vpn.example.test,DNS:other.example.test',
                 [('192.0.2.1', 'vpn.example.test', True), ('192.0.2.1', 'VPN.EXAMPLE.TEST', True),
                  ('192.0.2.1', 'vpnXexampleXtest', False), ('192.0.2.1', 'missing.example.test', False),
                  ('192.0.2.1', '', True)]),
                ('IP:192.0.2.1', [('192.0.2.1', 'vpn.example.test', False)]),
                ('IP:192.0.2.1,DNS:*.example.test', [('192.0.2.1', 'vpn.example.test', False)]),
            ]:
                generated = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-days', '1', '-subj', '/CN=vpn.example.test', '-addext', 'subjectAltName=' + sans,
                    '-keyout', str(root / 'server.key'), '-out', str(root / 'server.crt')],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
                self.assertEqual(generated.returncode, 0, 'synthetic certificate generation failed')
                for ip, domain, expected in probes:
                    with self.subTest(sans=sans, ip=ip, domain=domain):
                        result = subprocess.run(['sh', '-c', block + '\nprintf "%s" "$SAN_OK"'],
                            env=os.environ | {'PKI': directory, 'IP': ip, 'DOMAIN': domain},
                            capture_output=True, text=True, timeout=5)
                        self.assertEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, '1' if expected else '0')


if __name__ == '__main__':
    unittest.main()
