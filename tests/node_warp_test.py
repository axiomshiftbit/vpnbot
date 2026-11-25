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
import unittest.mock
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

    def test_official_ports_and_masque_transport(self):
        self.assertEqual(node.settings(OPTIONS4 | {'warp_port': 500})['warp_port'], 500)
        masque = OPTIONS4 | {'warp_mode': 'masque'}
        self.assertEqual(node.settings(masque | {'warp_port': 8443, 'warp_http': 'h3'})['warp_port'], 8443)
        self.assertEqual(node.settings(masque | {'warp_port': 443, 'warp_http': 'h2'})['warp_http'], 'h2')
        for wrong in (OPTIONS4 | {'warp_port': 443}, OPTIONS4 | {'warp_port': '500'}, OPTIONS4 | {'warp_http': 'h2'},
                      masque | {'warp_port': 2408}, masque | {'warp_port': 8443, 'warp_http': 'h2'}, masque | {'warp_http': 'h1'}):
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                node.settings(wrong)
        # A disabled WARP keeps no port choice that could fail a later apply.
        self.assertNotIn('warp_port', node.settings(OPTIONS4 | {'warp_mode': 'off', 'warp_port': 500}))
        for account in ('A' * 16, 'a' * 15, 1):
            with self.subTest(account=account), self.assertRaises(ValueError):
                node.identity(KEYS | {'warp_account': account})
        self.assertEqual(node.identity(KEYS | {'warp_account': 'a' * 16})['warp_account'], 'a' * 16)

    def test_account_directories_registration_and_port(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temp:
            root = Path(temp)
            seen = []

            def command(args, timeout=None, **_):
                directory = Path(next(a for a in args if a.startswith('type=bind,src=') and a.endswith(',dst=/account')).split(',')[1][4:])
                key = directory/'license.key'
                seen.append((args, key.read_text() if key.exists() else None))
                (directory/'wgcf-account.toml').write_text("device_id = 'device'\n")  # as wgcf register does
                return subprocess.CompletedProcess(args, 0, profile().encode(), b'')
            account = 'b' * 16
            node_warp.register('wireguard', 'image', root, account, 'AAAA-BBBB-CCCC', command)
            args, key = seen[-1]
            self.assertEqual(key, 'AAAA-BBBB-CCCC')
            self.assertFalse(any('AAAA-BBBB-CCCC' in a for a in args), 'the key never reaches process arguments')
            self.assertFalse((root/'warp/accounts'/account/'license.key').exists())
            with self.assertRaises(ValueError):
                node_warp.register('wireguard', 'image', root, account, None, command)  # not an empty directory
            for wrong in ('short', 'bad key with spaces', 'x' * 65):
                with self.subTest(key=wrong), self.assertRaises(ValueError):
                    node_warp.register('wireguard', 'image', root, 'c' * 16, wrong, command)
            # The legacy account stays at warp/ itself; a named one in its own directory.
            with unittest.mock.patch.object(node_warp, 'bootstrap_wireguard'):
                warp = node_warp.outbound('wireguard', 'image', root, command, account, 4500)
                node_warp.outbound('wireguard', 'image', root, command)
            self.assertTrue(warp['settings']['peers'][0]['endpoint'].endswith(':4500'))
            self.assertIn(f'type=bind,src={root}/warp/accounts/{account},dst=/account', seen[-2][0])
            self.assertIn(f'type=bind,src={root}/warp,dst=/account', seen[-1][0])
            with self.assertRaises(ValueError):
                node_warp.outbound('wireguard', 'image', root, command, '../escape')

    def test_registration_script_keys_both_kinds_and_fails_only_for_the_current_mode(self):
        stubs = {
            'wgcf': '#!/bin/sh\ncase "$1" in\n register) printf "device_id = \'d\'\\nlicense_key = \'free\'\\n" > "$4" ;;\n'
                    ' update) grep -q "license_key = \\"BAD" "$3" && exit 1; cp "$3" "$T/updated" ;;\n'
                    ' generate) echo profile > "$3" ;;\nesac\n',
            'helper': '#!/bin/sh\n[ -n "${HELPER_FAIL:-}" ] && exit 1\ncase "$1" in\n register) [ "${WARP_LICENSE_KEY:-}" = BAD ] && exit 1;'
                      ' mkdir -p masque.new && echo "${WARP_LICENSE_KEY:-free}" > masque.new/key ;;\n commit) mv masque.new masque ;;\nesac\n',
        }
        def run(mode, key=None, **env):
            temp = Path(tempfile.mkdtemp(dir='/tmp'))
            self.addCleanup(__import__('shutil').rmtree, temp)
            (temp/'bin').mkdir()
            for name, body in stubs.items():
                (temp/'bin'/name).write_text(body)
                (temp/'bin'/name).chmod(0o755)
            work = temp/'account'
            work.mkdir()
            if key:
                (work/'license.key').write_text(key)
            script = node_warp.REGISTER.replace('sh /helper', f'sh {temp}/bin/helper')
            result = subprocess.run(['sh', '-c', script, 'register', mode], cwd=work, capture_output=True,
                                    env=os.environ | {'PATH': f"{temp}/bin:{os.environ['PATH']}", 'T': str(temp)} | env)
            return result.returncode, work, temp
        code, work, temp = run('wireguard', 'AAAA-BBBB-CCCC')
        self.assertEqual(code, 0)
        self.assertIn('license_key = "AAAA-BBBB-CCCC"', (temp/'updated').read_text())
        self.assertEqual((work/'masque/key').read_text().strip(), 'AAAA-BBBB-CCCC', 'MASQUE gets the key too')
        self.assertFalse((work/'license.key').exists())
        code, work, _ = run('wireguard', None, HELPER_FAIL='1')
        self.assertEqual(code, 0, 'the other kind is best effort')
        self.assertTrue((work/'wgcf-profile.conf').exists() and not (work/'masque').exists())
        code, work, _ = run('masque', 'BAD')
        self.assertNotEqual(code, 0, 'a rejected key fails the current mode')
        code, work, _ = run('wireguard', 'BAD')
        self.assertNotEqual(code, 0)

    def test_docker_arguments_keep_options_before_the_image(self):
        # Options inserted before "run" made "docker --mount ...": MASQUE never registered.
        for mode in ('wireguard', 'masque'):
            args = node_warp.container('image', Path('/state/warp'), mode)
            self.assertEqual(args[:2], ['docker', 'run'])
            image = args.index('image')
            self.assertEqual(args[image - 2:image + 2], ['--entrypoint', 'timeout', 'image', '100'])
            options = args[2:image - 2]
            self.assertIn('type=bind,src=/state/warp,dst=/account', options)
            self.assertEqual(any(o.endswith(',dst=/helper,readonly') for o in options), mode == 'masque')
            self.assertEqual('WARP_MASQUE_DIR=/account/masque' in options, mode == 'masque')

    def test_info_masks_secrets_and_whitelists_fields(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temp:
            root = Path(temp)
            (root/'warp').mkdir(mode=0o700)
            (root/'warp/wgcf-account.toml').write_text("access_token = 'token-123456789'\ndevice_id = 'device-1'\n"
                                                       "license_key = 'AAAA-BBBB-CCCC'\nprivate_key = 'private-987654321'\nunknown = 'leak'\n")
            peer = base64.b64encode(bytes(range(32, 64))).decode()
            (root/'warp/wgcf-profile.conf').write_text(profile().replace('PublicKey = ' + base64.b64encode(bytes(range(32))).decode(),
                                                                         'PublicKey = ' + peer) + 'MTU = 1280\nUnknown = leak\n')
            result = node_warp.info(OPTIONS4 | {'warp_port': 500}, root, None)
            text = json.dumps(result)
            for secret in ('token-123456789', 'AAAA-BBBB-CCCC', 'private-987654321', base64.b64encode(bytes(range(32))).decode()[:20], 'leak'):
                self.assertNotIn(secret, text)
            self.assertIn(['license_key', '…CCCC'], result['account_fields'])
            self.assertIn(['Endpoint', 'engage.cloudflareclient.com:500'], result['profile'])
            self.assertEqual((result['account'], result['default_port']), ('legacy', 2408))

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
