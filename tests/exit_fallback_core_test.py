"""Проверка блокировок при настоящем прямом резерве балансировщика Xray."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest

from node_policy_test import Echo, free_port, request
from node_warp_test import IDENTITY, PEER


@unittest.skipUnless(os.environ.get('VLESS_TEST_XRAY'), 'требуется Xray')
class ExitFallbackCoreTest(unittest.TestCase):
    def test_direct_fallback_checks_domains_and_resolved_ips_for_tcp_and_udp(self):
        fixture = Path(__file__).with_name('exit_nodes_test.php')
        result = subprocess.run(['php', str(fixture), '--fallback-fixture'], capture_output=True, check=True)
        routes = json.loads(result.stdout)
        primary = routes['balancers'][0]['selector'][0]
        alice, bob = IDENTITY['uuid'], PEER['id']
        listen = free_port()
        for listener in routes['inbounds']:
            listener['port'] = free_port()
            password = secrets.token_hex(32)
            listener['settings']['clients'][0] = {'password': password}
            out = next(hop for hop in routes['outbounds'] if hop['tag'] == listener['tag'])
            out['settings']['servers'][0].update(port=listener['port'], password=password)
        with ExitStack() as stack:
            tcp = stack.enter_context(socketserver.ThreadingTCPServer(('127.0.0.1', 0), Echo))
            udp = stack.enter_context(socketserver.ThreadingUDPServer(tcp.server_address, Echo))
            for srv in (tcp, udp):
                srv.label = b'direct'
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                stack.callback(srv.shutdown)
            config = {
                'inbounds': [{'listen': '127.0.0.1', 'port': listen, 'protocol': 'vless',
                              'settings': {'decryption': 'none', 'clients': [{'id': alice, 'email': 'alice'}, {'id': bob, 'email': 'bob'}]}}, *routes['inbounds']],
                'outbounds': [
                    {'tag': 'direct', 'protocol': 'freedom', 'settings': {'redirect': f'127.0.0.1:{tcp.server_address[1]}',
                        'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1/32'], 'port': str(tcp.server_address[1])}]}},
                    {'tag': 'block', 'protocol': 'blackhole'}, {'tag': primary, 'protocol': 'blackhole'}, *routes['outbounds']],
                'dns': {'hosts': {'allowed.list.test': '198.51.100.8', 'private.list.test': '198.51.100.8',
                                  'resolved.list.test': '192.0.2.8'}, 'servers': ['127.0.0.1']},
                'routing': {'domainStrategy': 'AsIs', 'rules': routes['rules'], 'balancers': routes['balancers']},
                'observatory': {'subjectSelector': [primary], 'probeURL': f'http://127.0.0.1:{tcp.server_address[1]}/', 'probeInterval': '1s'},
            }
            directory = Path(stack.enter_context(tempfile.TemporaryDirectory()))
            path = directory/'config.json'
            path.write_text(json.dumps(config))
            core = subprocess.Popen([os.environ['VLESS_TEST_XRAY'], 'run', '-c', str(path)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            stack.callback(core.wait, 5)
            stack.callback(core.terminate)
            for _ in range(50):
                self.assertIsNone(core.poll(), 'ядро отвергло сгенерированные правила')
                if request(listen, alice, 'allowed.list.test', False) == b'directx':
                    break
                time.sleep(.05)
            for datagram in (False, True):
                for dest in ('allowed.list.test', '198.51.100.8'):
                    self.assertEqual(request(listen, alice, dest, datagram), b'directx', (dest, datagram))
                for dest in ('private.list.test', 'resolved.list.test', '192.0.2.8'):
                    with self.subTest(dest=dest, udp=datagram):
                        self.assertEqual(request(listen, bob, dest, datagram), b'directx')
                        self.assertFalse(request(listen, alice, dest, datagram))
