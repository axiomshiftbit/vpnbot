"""Exercise destination policy selection with two real Xray DNS contexts."""
from contextlib import ExitStack
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

from node_warp_test import HOST, IDENTITY, OPTIONS4, PEER, node, node_warp, profile
import node_policy


def fixture():
    routes = {'block': {'domain': ['domain:blocked.test'], 'ip': ['1.0.0.0/24']},
              'warp': {'domain': ['full:tunnel.test', 'keyword:video', 'regexp:^cdn[0-9]+\\.test$'], 'ip': ['11.77.0.0/24']}}
    value = {'options': OPTIONS4 | {'policy': {'routes': routes}}, 'identity': IDENTITY, 'peers': [PEER]}
    return value


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        if isinstance(self.request, tuple):
            data, sock = self.request
            sock.sendto(self.server.label + data, self.client_address)
        else:
            self.request.sendall(self.server.label + self.request.recv(32))


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def request(port, login, address, udp):
    try:
        addr = ipaddress.ip_address(address)
        target = (b'\1' if addr.version == 4 else b'\3') + addr.packed
    except ValueError:
        target = b'\2' + bytes([len(address)]) + address.encode()
    payload = b'\0' + uuid.UUID(login).bytes + b'\0' + (b'\2' if udp else b'\1') + struct.pack('!H', 443) + target
    try:
        with socket.create_connection(('127.0.0.1',port),1) as sock, sock.makefile('rb') as stream:
            sock.sendall(payload + (b'\0\1' if udp else b'') + b'x')
            if stream.read(2) != b'\0\0':
                return None
            if udp and len(stream.read(2)) != 2:
                return None
            return stream.read1(32)
    except OSError:
        return None


class NodePolicy(unittest.TestCase):
    def test_closed_schema(self):
        policy = fixture()['options']['policy']
        self.assertEqual(node_policy.validate(policy), policy)
        for wrong in ({'routes': {'direct': {'domain': ['full:a.test']}}},
                      {'routes': {'block': {}}},
                      {'routes': {'block': {'ip': ['1.2.3.999']}}},
                      {'routes': {'warp': {'domain': ['a.test']}}},
                      {'routes': {}, 'controller_ips': ['11.77.1.0/24']},
                      {'routes': {}, 'extra': 1}):
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                node_policy.validate(wrong)

    def test_named_lists_of_older_controllers_keep_only_shared_blocks(self):
        legacy = {'revision': 'a' * 32, 'controller_ips': ['11.77.1.0/24'],
                  'lists': {'ads': {'domain': ['full:ads.test']}, 'net': {'ip': ['1.0.0.0/24']}, 'tv': {'domain': ['full:tv.test']}},
                  'bindings': {'all': [{'list': 'ads', 'action': 'block'}, {'list': 'net', 'action': 'block'}],
                               'bot-' + 'a' * 20: [{'list': 'tv', 'action': 'warp'}]}}
        self.assertEqual(node_policy.validate(legacy), {'revision': 'a' * 32, 'controller_ips': ['11.77.1.0/24'],
                         'routes': {'block': {'domain': ['full:ads.test'], 'ip': ['1.0.0.0/24']}}})
        self.assertEqual(node_policy.validate({'lists': {}, 'bindings': {}}), {'routes': {}})

    def test_large_routes_snapshot_and_queue(self):
        import node_state
        from node_state_test import VALUE
        value = fixture()
        value['options']['policy']['routes']['block']['domain'] += [f'full:ads{i}.example.test' for i in range(5000)]
        value['options']['warp_mode'] = 'off'
        value.update(schema=1, images=VALUE['images'], tls={})
        value['identity'] = dict(value['identity'])
        value['identity'].pop('warp_uuid')
        self.assertEqual(node.settings(value['options']), value['options'])
        op = {'operation': 'configure', 'value': value['options']}
        self.assertGreater(len(node_state.encode(op, node_state.policy_size(op))), 65536)
        with tempfile.TemporaryDirectory() as temp:
            store = node_state.Store(Path(temp))
            generation = store.create(value)
            self.assertEqual(store.load(generation)['options']['policy'], value['options']['policy'])
        with self.assertRaises(ValueError):
            node_state.policy_size(dict(value, unknown='x' * 70000))

    def test_warp_list_without_the_warp_core_goes_direct(self):
        # Without WARP on the node a WARP entry must not silently become a block.
        value = fixture()
        value['options']['warp_mode'] = 'off'
        main = node.core_config(value['options'], HOST, IDENTITY, [PEER], None)
        node_policy.compile_policy(main, None, value)
        rules = main['routing']['rules']
        blocked = [r for r in rules if r.get('outboundTag') == 'block' and 'domain' in r]
        self.assertTrue(any('domain:blocked.test' in r['domain'] for r in blocked))
        self.assertFalse(any(d in r['domain'] for r in blocked for d in ('full:tunnel.test', 'video')))
        self.assertFalse(any('warp' in str(r.get('outboundTag', '')) for r in rules))

    def test_empty_routes_leave_the_core_untouched(self):
        value = fixture()
        value['options']['policy'] = {'routes': {}}
        value['options']['warp_mode'] = 'off'
        main = node.core_config(value['options'], HOST, IDENTITY, [PEER], None)
        before = json.dumps(main, sort_keys=True)
        node_policy.compile_policy(main, None, value)
        self.assertEqual(json.dumps(main, sort_keys=True), before)

    @unittest.skipUnless(os.environ.get('VLESS_TEST_XRAY'), 'requires Xray')
    def test_data_plane(self):
        value = fixture()
        revision = 'b' * 32
        value['options']['policy'].update(controller_ips=['11.77.1.0/24'], revision=revision)
        main = node.core_config(value['options'], HOST, IDENTITY, [PEER], node_warp.wireguard(profile()))
        strict = node_warp.isolate_resolver(main, IDENTITY['warp_uuid'])
        node_policy.compile_policy(main, strict, value)
        port, tunnel_port = free_port(), free_port()
        with ExitStack() as stack:
            directory = Path(stack.enter_context(tempfile.TemporaryDirectory()))
            ports = {}
            for label in ('direct', 'warp'):
                tcp = stack.enter_context(socketserver.ThreadingTCPServer(('127.0.0.1',0), Echo))
                udp = stack.enter_context(socketserver.ThreadingUDPServer(tcp.server_address, Echo))
                ports[label] = tcp.server_address[1]
                for srv in (tcp,udp):
                    srv.label = label.encode()
                    threading.Thread(target=srv.serve_forever, daemon=True).start()
                    stack.callback(srv.shutdown)
            for name, core, listen in [('strict',strict,tunnel_port), ('main',main,port)]:
                inbound = core['inbounds'][0]
                inbound.update(listen='127.0.0.1', port=listen, streamSettings={'network':'tcp'})
                inbound.pop('sniffing',None)
                for client in inbound['settings']['clients']:
                    client.pop('flow',None)
                for out in core['outbounds']:
                    if out['protocol'] == 'trojan':
                        out['settings']['servers'][0]['port'] = tunnel_port
                    elif out['tag'] in ports:
                        tag = out['tag']
                        out.clear()
                        out.update(tag=tag,protocol='freedom',settings={'redirect':f'127.0.0.1:{ports[tag]}',
                                   'finalRules':[{'action':'allow','ip':['127.0.0.1/32'],'port':str(ports[tag])}]})
                core['dns'] = {'hosts': {k:'1.1.1.1' for k in ['other.test','personal.test','direct.test','video.test','cdn7.test']} |
                               {'tunnel.test':'1.0.0.3' if name == 'strict' else '1.1.1.1','subnet.test':'11.77.0.8',
                                'www.gstatic.com':'11.77.1.0', 'guard.test':'11.77.1.0' if name == 'strict' else '1.1.1.1'},
                               'servers':['127.0.0.1']}
                path = directory / (name+'.json')
                path.write_text(json.dumps(core))
                proc = subprocess.Popen([os.environ['VLESS_TEST_XRAY'],'run','-c',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                stack.callback(proc.wait,5)
                stack.callback(proc.terminate)
                for _ in range(80):
                    if proc.poll() is not None:
                        self.fail(f'{name} core failed to start')
                    try:
                        socket.create_connection(('127.0.0.1',listen),.1).close()
                        break
                    except OSError:
                        time.sleep(.025)
            ordinary = node_policy.relay_login(IDENTITY['uuid'],'controller','direct',revision)
            tunnel = node_policy.relay_login(IDENTITY['uuid'],'controller','warp',revision)
            health = node_policy.relay_login(IDENTITY['uuid'],'controller','health',revision)
            self.assertFalse(request(port,ordinary,'www.gstatic.com',False))
            self.assertEqual(request(port,health,'www.gstatic.com',False), b'directx')
            self.assertFalse(request(port,health,'other.test',False))
            self.assertFalse(request(port,health,'www.gstatic.com',True))
            old = node_policy.relay_login(IDENTITY['uuid'],'controller','direct','c'*32)
            for udp in (False, True):
                self.assertEqual(request(port,ordinary,'guard.test',udp),b'directx')
                self.assertFalse(request(port,tunnel,'guard.test',udp))
                self.assertEqual(request(port,tunnel,'other.test',udp),b'warpx')
                self.assertFalse(request(port,old,'other.test',udp))
                self.assertFalse(request(port,ordinary,'11.77.1.0',udp))
                self.assertEqual(request(port,PEER['id'],'11.77.1.0',udp),b'directx')
                # The shared routes apply to every source: the controller and external peers.
                for login in (ordinary, PEER['id']):
                    for dest, expected in [('personal.test',b'directx'),('ads.blocked.test',None),('1.0.0.1',None),
                                           ('tunnel.test',None),('video.test',b'warpx'),('cdn7.test',b'warpx'),
                                           ('direct.test',b'directx'),('11.77.0.8',b'warpx'),('subnet.test',b'warpx'),
                                           ('other.test',b'directx'),('2606:4700::1111',None)]:
                        with self.subTest(udp=udp,subject=login==ordinary,dest=dest):
                            self.assertEqual(request(port,login,dest,udp) or None,expected)
                self.assertEqual(request(port,IDENTITY['uuid'],'personal.test',udp),b'directx')
                self.assertFalse(request(port,IDENTITY['uuid'],'1.0.0.1',udp))
