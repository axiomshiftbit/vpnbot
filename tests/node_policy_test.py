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
    scope = node_policy.peer_scope(PEER['id'])
    bot = 'bot-' + 'a' * 20
    lists = {'never': {'domain': ['domain:blocked.test'], 'ip': ['1.0.0.0/24']},
             'tunnel': {'domain': ['full:tunnel.test', 'keyword:video', 'regexp:^cdn[0-9]+\\.test$']},
             'direct': {'domain': ['full:direct.test']}, 'net': {'ip': ['11.77.0.0/24']},
             'personal': {'domain': ['full:personal.test']}}
    choices = [{'list': key, 'action': action} for key, action in
               [('tunnel','warp'), ('direct','direct'), ('net','warp'), ('personal','block')]]
    policy = {'lists': lists, 'bindings': {'all': [{'list':'never','action':'block'}], scope: choices, bot: choices}}
    value = {'options': OPTIONS4 | {'policy': policy}, 'identity': IDENTITY, 'peers':[PEER]}
    return value, bot


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
        value, _ = fixture()
        policy = value['options']['policy']
        self.assertEqual(node_policy.validate(policy), policy)
        for wrong in ({'lists':{},'bindings':{'all':[{'action':'block','list':'missing'}]}},
                      policy | {'bindings':{'all':[{'action':'direct','list':'never'}]}},
                      policy | {'lists':{'bad':{'ip':['1.2.3.999']}}}):
            with self.assertRaises(ValueError):
                node_policy.validate(wrong)

    def test_large_named_list_snapshot_and_queue(self):
        import node_state
        from node_state_test import VALUE
        value, bot = fixture()
        value['options']['policy']['lists']['large'] = {'domain':[f'full:ads{i}.example.test' for i in range(5000)]}
        value['options']['policy']['bindings'][bot].append({'action':'block','list':'large'})
        value['options']['warp_mode'] = 'off'
        value.update(schema=1,images=VALUE['images'],tls={})
        value['identity'] = dict(value['identity'])
        value['identity'].pop('warp_uuid')
        self.assertEqual(node.settings(value['options']), value['options'])
        op = {'operation':'configure','value':value['options']}
        self.assertGreater(len(node_state.encode(op,node_state.policy_size(op))),65536)
        with tempfile.TemporaryDirectory() as temp:
            store = node_state.Store(Path(temp))
            generation = store.create(value)
            self.assertEqual(store.load(generation)['options']['policy'], value['options']['policy'])
        with self.assertRaises(ValueError):
            node_state.policy_size(dict(value, unknown='x'*70000))

    def test_dedicated_login_without_rows_keeps_its_exit(self):
        # Another subject has rows, this one has none: its dedicated WARP login
        # must never fall through to the core's first outbound (direct).
        value, bot = fixture()
        policy = value['options']['policy']
        other = 'bot-' + 'b' * 20
        policy['bindings'] = {other: policy['bindings'][bot], bot: []}
        for strict in (False, True):
            with self.subTest(strict=strict):
                value['options']['warp_mode'] = 'off'
                main = node.core_config(value['options'], HOST, IDENTITY, [PEER], None)
                core = {'inbounds': [{'tag': 'warp-handoff', 'settings': {'clients': []}}], 'outbounds': [], 'routing': {'rules': []}} if strict else None
                if strict:
                    main['outbounds'].append({'tag': 'warp', 'protocol': 'trojan', 'settings': {'servers': [{'address': '127.0.0.1', 'port': 1, 'password': 'x'}]}})
                node_policy.compile_policy(main, core, value)
                for role, expected in (('direct', 'direct'), ('warp', 'warp' if strict else 'block')):
                    email = f'vpnbot/{bot}/{role}'
                    first = next((r for r in main['routing']['rules'] if email in r.get('user', [])), None)
                    self.assertIsNotNone(first, email)
                    self.assertEqual(set(first) - {'type', 'inboundTag', 'user', 'outboundTag'}, set(), email)
                    self.assertEqual(first['outboundTag'], expected, email)

    @unittest.skipUnless(os.environ.get('VLESS_TEST_XRAY'), 'requires Xray')
    def test_direct_ip_with_missing_default_warp(self):
        value, bot = fixture()
        policy = value['options']['policy']
        policy['bindings'][bot] = [{'list': 'net', 'action': 'direct'}]
        value['options']['warp_mode'] = 'off'
        main = node.core_config(value['options'], HOST, IDENTITY, [PEER], None)
        node_policy.compile_policy(main, None, value)
        login = node_policy.relay_login(IDENTITY['uuid'], bot, 'warp')
        with ExitStack() as stack:
            echo = stack.enter_context(socketserver.ThreadingTCPServer(('127.0.0.1', 0), Echo))
            echo.label = b'direct'
            threading.Thread(target=echo.serve_forever, daemon=True).start()
            stack.callback(echo.shutdown)
            port = free_port()
            inbound = main['inbounds'][0]
            inbound.update(listen='127.0.0.1', port=port, streamSettings={'network':'tcp'})
            for client in inbound['settings']['clients']:
                client.pop('flow', None)
            direct = next(o for o in main['outbounds'] if o['tag'] == 'direct')
            direct.clear()
            direct.update(tag='direct', protocol='freedom', settings={
                'redirect': f'127.0.0.1:{echo.server_address[1]}',
                'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1/32']}]})
            path = Path(stack.enter_context(tempfile.TemporaryDirectory())) / 'core.json'
            path.write_text(json.dumps(main))
            proc = subprocess.Popen([os.environ['VLESS_TEST_XRAY'], 'run', '-c', str(path)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            stack.callback(proc.wait, 5)
            stack.callback(proc.terminate)
            for _ in range(80):
                if proc.poll() is not None:
                    self.fail('Xray startup failed')
                try:
                    socket.create_connection(('127.0.0.1', port), .1).close()
                    break
                except OSError:
                    time.sleep(.025)
            self.assertEqual(request(port, login, '11.77.0.8', False), b'directx')
            self.assertFalse(request(port, login, '1.1.1.1', False))
            self.assertFalse(request(port, login, 'other.test', False))

    @unittest.skipUnless(os.environ.get('VLESS_TEST_XRAY'), 'requires Xray')
    def test_data_plane(self):
        value, bot = fixture()
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
            actor = node_policy.relay_login(IDENTITY['uuid'],bot,'direct',revision)
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
                self.assertFalse(request(port,actor,'11.77.1.0',udp))
                self.assertEqual(request(port,PEER['id'],'11.77.1.0',udp),b'directx')
                for login in (actor, PEER['id']):
                    for dest, expected in [('personal.test',None),('ads.blocked.test',None),('1.0.0.1',None),
                                           ('tunnel.test',None),('video.test',b'warpx'),('cdn7.test',b'warpx'),
                                           ('direct.test',b'directx'),('11.77.0.8',b'warpx'),('subnet.test',b'warpx'),
                                           ('other.test',b'directx'),('2606:4700::1111',None)]:
                        with self.subTest(udp=udp,subject=login==actor,dest=dest):
                            self.assertEqual(request(port,login,dest,udp) or None,expected)
                self.assertEqual(request(port,IDENTITY['uuid'],'personal.test',udp),b'directx')
                self.assertFalse(request(port,IDENTITY['uuid'],'1.0.0.1',udp))
