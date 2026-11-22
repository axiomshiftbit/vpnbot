"""Node WARP identity isolation, validation and authenticated Xray data plane."""
import base64
import contextlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

from node_config_test import OPTIONS, HOST, KEYS, node
import node_warp

WARP_ID = '22222222-2222-4222-8222-222222222222'
PEER = {'id': '33333333-3333-4333-8333-333333333333', 'name': 'panel', 'enabled': True}
OPTIONS4 = OPTIONS | {'family': 4, 'warp_mode': 'wireguard'}
IDENTITY = KEYS | {'warp_uuid': WARP_ID}


def profile():
    key = base64.b64encode(bytes(range(32))).decode()
    return (f'[Interface]\nPrivateKey = {key}\nAddress = 172.16.0.2/32\nAddress = 2606:4700::2/128\n'
            f'[Peer]\nPublicKey = {key}\nEndpoint = engage.cloudflareclient.com:2408\n')


class NodeWarp(unittest.TestCase):
    def test_only_controller_gets_warp_login(self):
        for transport in node.TRANSPORTS:
            options = OPTIONS4 | {'transport': transport, 'domain': 'node.example.test'}
            for mode in ('wireguard', 'masque'):
                options['warp_mode'] = mode
                body = node.core_config(options, HOST, IDENTITY, [PEER], {'protocol': mode})
                self.assertEqual(body['outbounds'][0]['tag'], 'direct')
                self.assertEqual([c['email'] for c in body['inbounds'][0]['settings']['clients']], ['controller', 'vpnbot/warp', 'panel'])
                self.assertEqual(node.export_profile(options, HOST, IDENTITY)['warp_uuid'], WARP_ID)
                self.assertNotIn(WARP_ID, json.dumps(node.export_profile(options, HOST, IDENTITY, PEER)))
        self.assertNotIn('warp_uuid', node.export_profile(OPTIONS, HOST, IDENTITY))

    def test_reject_unusable_modes_and_collisions(self):
        for options in (OPTIONS4 | {'family': 6}, OPTIONS4 | {'warp_mode': 'bad'},
                        OPTIONS4 | {'wireguard': {'enabled': True, 'active': True}}):
            with self.assertRaises(ValueError):
                node.settings(options)
        for outbound, peers in ((None, []), ({'protocol': 'freedom'}, []),
                                ({'protocol': 'wireguard'}, [PEER | {'id': WARP_ID}])):
            with self.assertRaises(ValueError):
                node.core_config(OPTIONS4, HOST, IDENTITY, peers, outbound)
        with self.assertRaises(ValueError):
            node.identity(KEYS | {'warp_uuid': KEYS['uuid']})

    def test_warp_resolver_is_bound_to_its_own_authenticated_loopback_context(self):
        body = node.core_config(OPTIONS4, HOST, IDENTITY, [], {'protocol':'wireguard'})
        private = node_warp.isolate_resolver(body, WARP_ID)
        inlet, = private['inbounds']
        self.assertEqual((inlet['listen'], inlet['port'], inlet['protocol']), ('127.0.0.1',node.WARP_CORE_PORT,'trojan'))
        hop = next(o for o in body['outbounds'] if o['tag']=='warp')['settings']['servers'][0]
        self.assertEqual(hop['password'],inlet['settings']['clients'][0]['password'])
        self.assertNotIn(hop['password'],json.dumps(node.export_profile(OPTIONS4,HOST,IDENTITY)))
        self.assertEqual(private['outbounds'][0]['tag'],'block')
        self.assertEqual(private['routing']['rules'][0]['outboundTag'],'warp')
        self.assertTrue(private['dns']['disableFallback'])
        self.assertEqual(len([r for r in private['routing']['rules'] if r.get('inboundTag')==['warp-resolved']]),3)
        self.assertFalse(any(r.get('outboundTag')=='warp-resolve' for r in body['routing']['rules']))
        firewall = node.firewall(OPTIONS4,HOST)
        self.assertLess(firewall.index(f'tcp dport {node.WARP_CORE_PORT} meta skuid'),firewall.index(f'tcp dport {node.WARP_CORE_PORT} drop'))

    def test_old_masque_cores_do_not_register(self):
        for version in (b'Xray 26.10.9 (Xray)', b'Xray 26.9.30 ', b'unknown'):
            self.assertFalse(node_warp.masque_supported(version))
        for version in (b'Xray 26.10.10 (Xray)', b'Xray 26.10.28-1202 (Xray)'):
            self.assertTrue(node_warp.masque_supported(version))

    def test_wireguard_profile(self):
        settings = node_warp.wireguard(profile())['settings']
        self.assertEqual(settings['address'], ['172.16.0.2/32'])
        self.assertEqual(settings['peers'][0]['allowedIPs'], ['0.0.0.0/0'])
        for text in ('', profile().replace('engage.cloudflareclient.com', 'localhost'),
                     profile().replace('2408', '99999'), profile().replace('PrivateKey', 'Missing')):
            with self.assertRaises(ValueError):
                node_warp.wireguard(text)

    @unittest.skipUnless(os.environ.get('VLESS_TEST_XRAY'), 'requires Xray')
    def test_authenticated_routes_and_fail_closed(self):
        # Only the terminal sockets are replaced by loopback fixtures. Login,
        # loopback re-dispatch, DNS, ACL and UDP framing run in the real core.
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                if isinstance(self.request, tuple):
                    data, sock = self.request
                    sock.sendto(self.server.label + data, self.client_address)
                else:
                    message = self.request.recv(32)
                    self.request.sendall(self.server.label + message)

        with contextlib.ExitStack() as stack:
            directory = Path(stack.enter_context(tempfile.TemporaryDirectory()))
            host = HOST | {'onlink': ['11.77.0.0/24']}
            body = node.core_config(OPTIONS4, host, IDENTITY, [PEER], node_warp.wireguard(profile()))
            tcp_ports = {}
            for label in ('direct', 'warp'):
                tcp = stack.enter_context(socketserver.ThreadingTCPServer(('127.0.0.1', 0), Echo))
                udp = stack.enter_context(socketserver.ThreadingUDPServer(tcp.server_address, Echo))
                tcp_ports[label] = tcp.server_address[1]
                for server in [tcp, udp]:
                    server.label = label.encode()
                    threading.Thread(target=server.serve_forever, daemon=True).start()
                    stack.callback(server.shutdown)
            for out in body['outbounds']:
                if out['tag'] in tcp_ports:
                    label = out['tag']
                    out.clear()
                    out.update(tag=label, protocol='freedom', settings={'redirect': '127.0.0.1:'+str(tcp_ports[label]),
                               'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1/32']}]})
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            inbound = body['inbounds'][0]
            inbound.update(listen='127.0.0.1', port=port, streamSettings={'network': 'tcp'})
            inbound.pop('sniffing', None)
            for client in inbound['settings']['clients']:
                client.pop('flow', None)
            body['dns'] = {'hosts': {'global.example.test': '1.1.1.1', 'lan.example.test': '127.0.0.1',
                                    'aaaa.example.test': '2001:db8::10', 'dual.example.test': ['2001:db8::10', '1.1.1.1']}, 'servers': ['127.0.0.1']}
            config = directory/'config.json'
            config.write_text(json.dumps(body))
            core = subprocess.Popen([os.environ['VLESS_TEST_XRAY'], 'run', '-c', str(config)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            stack.callback(core.wait, 5)
            stack.callback(core.terminate)
            for _ in range(60):
                try:
                    socket.create_connection(('127.0.0.1', port), .1).close()
                    break
                except OSError:
                    time.sleep(.05)
            self.assertIsNone(core.poll())

            def request(login, address, udp=False):
                try:
                    ip = ipaddress.ip_address(address)
                    destination = (b'\x01' if ip.version == 4 else b'\x03') + ip.packed
                except ValueError:
                    destination = b'\x02' + bytes([len(address)]) + address.encode()
                command = b'\x02' if udp else b'\x01'
                data = b'hello'
                header = b'\0' + uuid.UUID(login).bytes + b'\0' + command + struct.pack('!H', 53) + destination
                try:
                    with socket.create_connection(('127.0.0.1', port), 1) as sock:
                        sock.settimeout(1)
                        sock.sendall(header + (struct.pack('!H', len(data)) if udp else b'') + data)
                        with sock.makefile('rb') as reader:
                            if reader.read(2) != bytes(2):
                                return None
                            size = struct.unpack('!H', reader.read(2))[0] if udp else 32
                            return reader.read1(size)
                except (OSError, struct.error):
                    return None

            for udp in (False, True):
                for login, label in [(KEYS['uuid'], b'direct'), (PEER['id'], b'direct'), (WARP_ID, b'warp')]:
                    self.assertEqual(request(login, '1.1.1.1', udp), label + b'hello')
                self.assertEqual(request(WARP_ID, 'global.example.test', udp), b'warphello')
                self.assertEqual(request(WARP_ID, 'dual.example.test', udp), b'warphello')
                for blocked in ('127.0.0.1', '10.10.0.13', '169.254.169.254', '100.64.0.1', HOST['public4'],
                                '11.77.0.5', 'lan.example.test', '::1', 'fd00::1', 'fe80::1', '::ffff:127.0.0.1',
                                '2606:4700:4700::1001', 'aaaa.example.test'):
                    with self.subTest(destination=blocked, udp=udp):
                        self.assertFalse(request(WARP_ID, blocked, udp))
