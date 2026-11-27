#!/usr/bin/env python3
import copy
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch, Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from node_runtime import Runtime
from node_config_test import HOST, OPTIONS

class NodeTlsProbe(unittest.TestCase):
    def runtime(self, options=None):
        runtime = Runtime(Mock(load=lambda:{'options':OPTIONS | {'family':4,'cover':False} | (options or {})}), HOST)
        # The probe denies the WAN segment like ordinary traffic (audit 26.11.2026, H07).
        runtime.routed_host = lambda: dict(runtime.host, onlink=[])
        return runtime

    def test_resolved_private_mixed_own_and_mapped_addresses_cannot_be_probed(self):
        for address in ('127.0.0.1','10.0.0.1','169.254.169.254','::1','::ffff:127.0.0.1','fd42::1',HOST['public4'],HOST['public6']):
            if not address:continue
            answers=[(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443)) for ip in ('1.1.1.1',address)]
            with self.subTest(address=address),patch('node_runtime.socket.getaddrinfo',return_value=answers),patch.object(Runtime,'probe_tls') as probe:
                with self.assertRaises(ValueError):self.runtime().tls_probe()
                probe.assert_not_called()

    def test_public_dns_is_pinned_and_probe_uses_selected_egress_family(self):
        answers=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('1.1.1.1',443))]
        with patch('node_runtime.socket.getaddrinfo',return_value=answers) as dns,patch.object(Runtime,'probe_tls',return_value={'tls':'TLSv1.3','alpn':'h2','record':40}) as probe:
            result=self.runtime().tls_probe()
            self.assertEqual(result['alpn'],'h2');dns.assert_called_once()
            self.assertEqual(probe.call_args.args[0],'1.1.1.1');self.assertEqual(probe.call_args.args[3],HOST['public4'])

    def test_own_cover_uses_only_fixed_listener_without_dns(self):
        with patch('node_runtime.socket.getaddrinfo',side_effect=AssertionError('unexpected DNS')),patch.object(Runtime,'probe_tls',return_value={'tls':'TLSv1.3','alpn':'h2','record':40}) as probe:
            result=self.runtime({'cover':True,'domain':'node.example.test'}).tls_probe()
            self.assertTrue(result['own']);self.assertEqual(probe.call_args.args,('127.0.0.1',8443,'node.example.test',None))

    def test_rpc_does_not_accept_an_arbitrary_target(self):
        from node_manager import Manager
        manager=Manager(Mock(),self.runtime())
        for value in ({'action':'tls_probe','target':'127.0.0.1'}, {'action':'tls_probe','name':'evil.test'}):
            with self.assertRaises(ValueError):manager.rpc(value)

    def test_real_tls_negotiation_and_certificate_validation(self):
        with tempfile.TemporaryDirectory(prefix='node-tls-') as d:
            root=Path(d);cert=root/'cert.pem';key=root/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=node.example.test',
                '-addext','subjectAltName=DNS:node.example.test','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
            for protocols,version,name,success in [(['h2','http/1.1'],ssl.TLSVersion.TLSv1_3,'node.example.test',True),
                    (['http/1.1'],ssl.TLSVersion.TLSv1_2,'node.example.test',True),([],ssl.TLSVersion.TLSv1_3,'node.example.test',True),
                    (['h2'],ssl.TLSVersion.TLSv1_3,'wrong.example.test',False)]:
                context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key);context.set_alpn_protocols(protocols)
                context.minimum_version=version;context.maximum_version=version
                with socket.socket() as server:
                    server.bind(('127.0.0.1',0));server.listen();server.settimeout(5)
                    completed=[]
                    def serve():
                        try:
                            conn,_=server.accept()
                            with context.wrap_socket(conn,server_side=True):completed.append(True)
                        except (ssl.SSLError,OSError):pass
                    thread=threading.Thread(target=serve);thread.start()
                    with patch.dict(os.environ,{'SSL_CERT_FILE':str(cert)}):
                        if success:
                            result=Runtime.probe_tls('127.0.0.1',server.getsockname()[1],name)
                            self.assertEqual(result['alpn'],protocols[0] if protocols else '');self.assertEqual(result['tls'],'TLSv1.3' if version==ssl.TLSVersion.TLSv1_3 else 'TLSv1.2')
                            if version==ssl.TLSVersion.TLSv1_3:self.assertGreaterEqual(result['record'],27 if protocols else 17)
                        else:
                            with self.assertRaises(ssl.SSLCertVerificationError):Runtime.probe_tls('127.0.0.1',server.getsockname()[1],name)
                    thread.join(timeout=6);self.assertFalse(thread.is_alive())
                    if success:self.assertEqual(completed,[True], 'Peer did not finish the TLS handshake')

    def test_malformed_and_oversized_tls_response_rejected(self):
        for reply in (b'', b'\x17\x03\x03\xff\xff', b'not TLS'):
            with self.subTest(reply_length=len(reply)),socket.socket() as server:
                server.bind(('127.0.0.1',0));server.listen();server.settimeout(5)
                def serve():
                    conn,_=server.accept()
                    with conn:
                        conn.settimeout(5);conn.recv(8192)
                        if reply:conn.sendall(reply)
                thread=threading.Thread(target=serve);thread.start()
                try:
                    with self.assertRaises((ValueError,ssl.SSLError)):
                        Runtime.probe_tls('127.0.0.1',server.getsockname()[1],'node.example.test')
                finally:thread.join(timeout=6)
                self.assertFalse(thread.is_alive())

    def test_handshake_deadline_is_bounded(self):
        connection=Mock();connection.__enter__=Mock(return_value=connection);connection.__exit__=Mock(return_value=False)
        with patch('node_runtime.socket.create_connection',return_value=connection),patch('node_runtime.time.monotonic',side_effect=[0,9]):
            with self.assertRaises(TimeoutError):Runtime.probe_tls('1.1.1.1',443,'node.example.test')
        connection.recv.assert_not_called()

if __name__=='__main__':unittest.main()
