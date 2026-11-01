#!/usr/bin/env python3
"""Run inside `unshare -n`: real node transports, core ACL and nft parser.

CORE_TEST_DIR must contain x31 and fork. All identities/certificates are disposable.
No production configuration is read and no external network is used.
"""
import copy
import itertools
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import socket
import socketserver
import struct
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


if os.geteuid() != 0 or os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
    raise SystemExit('Run as root in a separate network namespace')
os.umask(0o077)
source = Path(os.environ['NODE_SOURCE_DIR'])
sys.path.insert(0, str(source/'scripts'))
spec = importlib.util.spec_from_file_location('node_config', source / 'scripts/node_config.py')
node = importlib.util.module_from_spec(spec)
spec.loader.exec_module(node)
cores = Path(os.environ['CORE_TEST_DIR'])
root = Path(tempfile.mkdtemp(prefix='vpnbot-node-native-', dir='/run'))
processes, servers, results, masks = [], [], [], []
env = os.environ | {'GODEBUG': 'multipathtcp=0', 'SSL_CERT_FILE': str(root/'cert.pem')}


def run(args, **kwargs):
    return subprocess.run(list(map(str, args)), capture_output=True, text=True, **kwargs)


def check(label, ok):
    results.append({'case': label, 'ok': bool(ok)})
    print(('PASS ' if ok else 'FAIL ') + label, flush=True)
    if not ok:
        raise AssertionError(label)



class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', '16')
        self.end_headers()
        self.wfile.write(b'node-native-pass')

    def log_message(self, *args):
        pass


class Http6(ThreadingHTTPServer):
    address_family = socket.AF_INET6


class TorrentHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            if self.request.recv(1024).startswith(b'\x13BitTorrent protocol'):
                self.request.sendall(b'bt-fixture-pass')
        except OSError:
            pass


def torrent_request():
    try:
        with socket.create_connection(('127.0.0.1', 10871), timeout=3) as sock:
            sock.sendall(b'\x05\x01\x00')
            if sock.recv(2) != b'\x05\x00':
                return False
            sock.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('11.77.0.128')+struct.pack('!H', 18081))
            response = sock.recv(1024)
            if len(response) < 2 or response[1] != 0:
                return False
            sock.sendall(b'\x13BitTorrent protocol'+b'\0'*8+b'a'*20+b'b'*20)
            return sock.recv(1024) == b'bt-fixture-pass'
    except OSError:
        return False


def start(binary, name, config):
    path = root/(name+'.json')
    config['log'] = {'loglevel': 'debug'}
    path.write_text(json.dumps(config))
    checked = run([binary, 'run', '-test', '-c', path], env=env)
    check(name+'-core-validation', checked.returncode == 0)
    process = subprocess.Popen([str(binary), 'run', '-c', str(path)], env=env,
                               stdout=(root/(name+'.log')).open('w'), stderr=subprocess.STDOUT)
    processes.append(process)
    ports = [str(inbound['port']) for inbound in config['inbounds']]
    ready = False
    for _ in range(50):
        if process.poll() is not None:
            break
        ready = all(run(['ss', '-H', '-ltn', 'sport', '=', ':'+port]).stdout.strip() for port in ports)
        if ready:
            break
        time.sleep(.1)
    check(name+'-running', process.poll() is None and ready)
    return process


def stop(process):
    process.terminate()
    process.wait(timeout=5)
    processes.remove(process)


def request(url, positive=False):
    started = time.monotonic()
    result = run(['curl', '-sS', '--socks5-hostname', '127.0.0.1:10871',
                  '--connect-timeout', '2', '--max-time', '12' if positive else '3', url])
    if positive and time.monotonic()-started > 3:
        print('DIAGNOSTIC positive probe seconds '+str(round(time.monotonic()-started, 2)), flush=True)
    if positive and (result.returncode or result.stdout != 'node-native-pass'):
        print('DIAGNOSTIC positive probe curl status '+str(result.returncode), flush=True)
        for category in ('certificate', 'i/o timeout', 'connection refused', 'broken pipe', 'invalid', 'EOF'):
            count = sum(path.read_text(errors='replace').count(category) for path in root.glob('*.log'))
            if count:
                print('DIAGNOSTIC '+category+' '+str(count), flush=True)
    return result.returncode == 0 and result.stdout == 'node-native-pass'


def mptcp(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262) as conn:
        conn.settimeout(2)
        conn.connect(('127.0.0.1', port))
        return conn.getsockopt(socket.IPPROTO_TCP, 43)


try:
    run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262) as positive:
        positive.bind(('127.0.0.1', 0))
        positive.listen(1)
        check('mptcp-positive-control', mptcp(positive.getsockname()[1]) == 1)
    for address in ('11.77.0.4/32', '11.77.0.128/32', '2606:4700:4700::1111/128', '2620:fe::fe/128'):
        run(['ip', 'address', 'add', address, 'dev', 'lo'], check=True)
    names = 'DNS:node.example.test,DNS:mask.example.test,' + ','.join(
        f'DNS:padding-{i:03d}-abcdefghijklmnopqrstuvwxyz.example.test' for i in range(100))
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', root/'key.pem',
         '-out', root/'cert.pem', '-days', '1', '-subj', '/CN=node.example.test',
         '-addext', 'subjectAltName='+names], check=True)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_3
    tls.set_alpn_protocols(['h2', 'http/1.1'])
    tls.load_cert_chain(root/'cert.pem', root/'key.pem')
    torrent_server = socketserver.ThreadingTCPServer(('11.77.0.128', 18081), TorrentHandler)
    torrent_server.daemon_threads = True
    threading.Thread(target=torrent_server.serve_forever, daemon=True).start()
    servers.append(torrent_server)
    for cls, host in [(ThreadingHTTPServer, '11.77.0.128'), (Http6, '2620:fe::fe'), (ThreadingHTTPServer, '127.0.0.1')]:
        server = cls((host, 18080), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        if host != '127.0.0.1':
            mask = socket.socket(socket.AF_INET6 if cls is Http6 else socket.AF_INET)
            mask.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            mask.bind((host, 18443))
            mask.listen(32)
            masks.append(mask)

            def serve_one(conn):
                try:
                    # Match the real traffic probe budget. An aggressively
                    # short mock TLS deadline can abort REALITY handshakes.
                    conn.settimeout(12)
                    with tls.wrap_socket(conn, server_side=True) as wrapped:
                        wrapped.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nMASK')
                except OSError:
                    pass
                finally:
                    conn.close()

            def accept_loop(listener):
                while True:
                    try:
                        conn, _ = listener.accept()
                    except OSError:
                        return
                    threading.Thread(target=serve_one, args=(conn,), daemon=True).start()
            threading.Thread(target=accept_loop, args=(mask,), daemon=True).start()
    generated = run([cores/'x31', 'x25519'], check=True).stdout
    fields = {k.strip().lower().replace(' ', ''): v.strip() for k, v in
              (line.split(':', 1) for line in generated.splitlines() if ':' in line)}
    keys = {'uuid': str(uuid.uuid4()), 'private': fields['privatekey'],
            'public': fields.get('password(publickey)') or fields.get('password') or fields.get('publickey'),
            'short_id': os.urandom(8).hex(), 'path': os.urandom(16).hex()}
    host = dict(public4='11.77.0.4', public6='2606:4700:4700::1111', sources=['11.77.0.2'],
                admins=['11.77.0.3'], routers=['fe80::1'], ssh_ports=[22], interface='eth0', uid=995, gid=995)
    base_keys = keys
    cases = []
    binaries = [('origin', cores/'x31'), ('fork', cores/'fork')]
    if os.environ.get('NODE_ADVANCED_CASES') == '1':
        for core_name, binary in binaries:
            for transport, auth, mode in itertools.product(node.TRANSPORTS, ('x25519', 'mlkem768'), ('native', 'xorpub', 'random')):
                cases.append((core_name, binary, 4, transport, auth+'-'+mode, {'encryption': {'auth': auth, 'mode': mode}}))
            cases.append((core_name, binary, 6, 'reality', 'mldsa', {'reality': {'mldsa': True}}))
        for transport, protocol in itertools.product(('ws', 'xhttp', 'reality', 'grpc'), ('smux', 'h2mux')):
            cases.append(('fork', cores/'fork', 6, transport, protocol,
                          {'smux': {'enabled': True, 'protocol': protocol, 'half_close': 'require' if protocol == 'smux' else 'off', 'h2mux_frame': 32768}}))
        cases.append(('fork', cores/'fork', 4, 'xhttp', 'mux-cool', {'xhttp': {'mux': True}}))
        for core_name, binary in binaries:
            cases.append((core_name, binary, 4, 'xhttp', 'custom-xmux', {'xhttp': {'extra': {
                'xmux': {'maxConcurrency': '8-16', 'hMaxRequestTimes': '30-60'}, 'noGRPCHeader': True,
                'xPaddingBytes': '120-240', 'scMinPostsIntervalMs': 40}}}))
        for core_name in ('origin2', 'origin3'):
            if (cores/core_name).is_file():
                for transport in node.TRANSPORTS:
                    cases.append((core_name, cores/core_name, 4, transport, 'version', {}))
        for core_name, binary in binaries+[(name, cores/name) for name in ('origin2', 'origin3') if (cores/name).is_file()]:
            for field in ('dpi', 'finalmask'):
                cases.append((core_name, binary, 4, 'ws', field,
                              {field: {'fragment': {'enabled': True, 'packets': '1-3', 'length': '100-200', 'delay': '1-2'}}}))
            for enabled in (False, True):
                cases.append((core_name, binary, 4, 'ws', 'torrent-'+str(enabled), {'block_torrent': enabled}))
    else:
        for core_name, binary in binaries:
            for family, transport in itertools.product((4, 6), node.TRANSPORTS):
                cases.append((core_name, binary, family, transport, 'base', {}))
    # Explicitly cross the transport family and the internet egress family.
    # Previous native coverage exercised only 4->4 and 6->6 for VLESS.
    for core_name, binary in binaries+[(name, cores/name) for name in ('origin2', 'origin3') if (cores/name).is_file()]:
        for family, connection, transport in itertools.product((4,6),(4,6),node.TRANSPORTS):
            cases.append((core_name,binary,family,transport,'pair'+str(connection)+str(family),{}))
    for core_name, binary, family, transport, variant, advanced in cases:
        if os.environ.get('NODE_CASE_PREFIX') and not f'{core_name}-{family}-{transport}-{variant}'.startswith(os.environ['NODE_CASE_PREFIX']):
            continue
        label = f'{core_name}-{family}-{transport}-{variant}'
        if os.environ.get('NODE_CASE_FILTER') and not re.search(os.environ['NODE_CASE_FILTER'], label):
            continue
        connection = int(variant[4]) if variant.startswith('pair') else family
        options = dict(transport=transport, family=family, core=core_name,
                       domain='node.example.test', mask='mask.example.test', connect_family=connection, **({'xray': advanced} if advanced else {}))
        keys = copy.deepcopy(base_keys)
        if advanced.get('encryption', {}).get('auth', 'off') != 'off':
            import node_xray
            output = run([binary, 'vlessenc'], check=True).stdout
            keys['encryption'] = node_xray.parse_encryption_output(output, advanced['encryption']['auth'])
        if advanced.get('reality', {}).get('mldsa'):
            import node_xray, re
            output = run([binary, 'mldsa65'], check=True).stdout
            fields = {key.lower(): value for key, value in re.findall(r'^(Seed|Verify):\s*(\S+)', output, re.M | re.I)}
            keys['mldsa'] = node_xray.mldsa_identity(fields)
        rules = node.firewall(options, host)
        loaded = run(['unshare', '-n', 'nft', '-f', '-'], input=rules)
        check(label+'-nft-load', loaded.returncode == 0)
        config = node.core_config(options, host, keys)
        stream = config['inbounds'][0]['streamSettings']
        target = '11.77.0.128' if family == 4 else '[2620:fe::fe]'
        if transport == 'reality':
            stream['realitySettings']['dest'] = target+':18443'
        else:
            stream['tlsSettings']['certificates'] = [{'certificateFile': str(root/'cert.pem'), 'keyFile': str(root/'key.pem')}]
        server = start(binary, label+'-server', config)
        check(label+'-mptcp-disabled', mptcp(8443) == 0)
        exported = node.export_profile(options, host, keys)
        outbound = exported['outbound']
        parser = os.environ.get('PANEL_PARSER')
        if parser:
            for format in ('link', 'subscription'):
                imported = run([parser], input=exported[format], check=True)
                panel = json.loads(imported.stdout)
                check(label+'-3xui-'+format, panel['settings']['id'] == keys['uuid']
                      and panel['settings']['port'] == 443
                      and panel['streamSettings']['network'] == stream['network']
                      and panel['settings']['encryption'] == exported['outbound']['settings']['encryption']
                      and panel['streamSettings'].get('realitySettings', {}).get('mldsa65Verify', '')
                          == exported['outbound']['streamSettings'].get('realitySettings', {}).get('mldsa65Verify', ''))
            outbound = exported['outbound'] if advanced.get('smux', {}).get('enabled') or advanced.get('xhttp', {}).get('mux') or 'dpi' in advanced else panel
        bot_parser = os.environ.get('BOT_PROFILE_PARSER')
        if bot_parser:
            imported = run([bot_parser, options['core']], input=json.dumps(exported))
            check(label+'-main-bot-profile', imported.returncode == 0)
            outbound = json.loads(imported.stdout)
        endpoint = outbound['settings'].get('vnext', [outbound['settings']])[0]
        endpoint.update(address='127.0.0.1' if connection == 4 else '::1', port=8443)
        client_stream = outbound['streamSettings']
        user = endpoint.get('users', [endpoint])[0]
        if transport != 'reality':
            client_stream['tlsSettings']['certificates'] = [{'usage': 'verify', 'certificateFile': str(root/'cert.pem')}]
            if transport == 'xhttp':
                client_stream['xhttpSettings']['mode'] = 'stream-up'
        client = {'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1', 'port': 10871, 'protocol': 'socks'}],
                  'outbounds': [outbound]}
        process = start(cores/'fork' if advanced.get('smux', {}).get('enabled') else cores/'x31', label+'-client', client)
        check(label+'-real-traffic', request('http://'+target+':18080/', positive=True))
        if variant.startswith('torrent-'):
            check(label+'-bittorrent-payload', torrent_request() == (not advanced['block_torrent']))
        check(label+'-private-target-blocked', not request('http://127.0.0.1:18080/'))
        stop(process)
        user['id'] = str(uuid.uuid4())
        process = start(cores/'fork' if advanced.get('smux', {}).get('enabled') else cores/'x31', label+'-unauthorized', client)
        check(label+'-wrong-identity-blocked', not request('http://'+target+':18080/'))
        stop(process)
        stop(server)
finally:
    for process in processes:
        process.terminate()
        process.wait(timeout=5)
    for mask in masks:
        mask.close()
    for server in servers:
        server.shutdown()
        server.server_close()
    Path(os.environ['NODE_RESULTS_FILE']).write_text(json.dumps(results, indent=2))
    shutil.rmtree(root)
