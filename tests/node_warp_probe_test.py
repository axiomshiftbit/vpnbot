"""The WARP probe verifies Cloudflare's certificate and refuses protocols older than TLS 1.2."""
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import warnings
from unittest.mock import Mock, patch
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import node_warp_probe  # noqa: E402


class WarpTrace(unittest.TestCase):
    def test_only_well_formed_trace_fields_are_reported(self):
        body = (b'fl=1\nh=www.cloudflare.com\nip=203.0.113.9\nts=1\ncolo=FRA\nloc=FI\nwarp=plus\n'
                b'gateway=off\nuag=<script>\n')
        self.assertEqual(node_warp_probe.trace_fields(body), {'ip': '203.0.113.9', 'colo': 'FRA', 'loc': 'FI', 'warp': 'plus'})
        self.assertEqual(node_warp_probe.trace_fields(b'ip=1.2.3.4 <b>\ncolo=fra\nwarp=yes\n'), {})


class WarpProbeTls(unittest.TestCase):
    def test_context(self):
        context = node_warp_probe.tls_context()
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_floor_is_explicit_even_when_library_defaults_change(self):
        context = Mock()
        with patch.object(ssl, 'create_default_context', return_value=context):
            self.assertIs(node_warp_probe.tls_context(), context)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_negotiation_and_certificate_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            cert, key = Path(temp)/'cert.pem', Path(temp)/'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-subj', '/CN=probe.test', '-addext', 'subjectAltName=DNS:probe.test',
                            '-keyout', key, '-out', cert], check=True, capture_output=True)

            def negotiate(version, name='probe.test', trust=True):
                server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                server.load_cert_chain(cert, key)
                if version < ssl.TLSVersion.TLSv1_2:
                    # Only the socketpair peer offers the obsolete protocol. Keep the product client intact.
                    server.set_ciphers('DEFAULT:@SECLEVEL=0')
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', DeprecationWarning)
                    server.minimum_version = server.maximum_version = version
                client = node_warp_probe.tls_context()
                if trust:
                    client.load_verify_locations(cafile=str(cert))
                local, peer = socket.socketpair()
                local.settimeout(3)
                peer.settimeout(3)

                def answer():
                    try:
                        with server.wrap_socket(peer, server_side=True) as connected:
                            connected.sendall(b'x')
                    except ssl.SSLError:
                        pass

                with local, peer:
                    thread = threading.Thread(target=answer)
                    thread.start()
                    try:
                        with client.wrap_socket(local, server_hostname=name) as connected:
                            self.assertEqual(connected.recv(1), b'x')
                            return connected.version()
                    finally:
                        thread.join(4)
                        self.assertFalse(thread.is_alive())

            for version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
                with self.subTest(version=version), self.assertRaises(ssl.SSLError):
                    negotiate(version)
            self.assertEqual(negotiate(ssl.TLSVersion.TLSv1_2), 'TLSv1.2')
            self.assertEqual(negotiate(ssl.TLSVersion.TLSv1_3), 'TLSv1.3')
            with self.assertRaises(ssl.SSLCertVerificationError):
                negotiate(ssl.TLSVersion.TLSv1_2, name='other.test')
            with self.assertRaises(ssl.SSLCertVerificationError):
                negotiate(ssl.TLSVersion.TLSv1_3, trust=False)


if __name__ == '__main__':
    unittest.main()
