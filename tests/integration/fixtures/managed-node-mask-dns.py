#!/usr/bin/env python3
"""REALITY target resolution with a host stub resolver and UID isolation."""
import base64
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading

if subprocess.run(['systemd-detect-virt', '--container'], capture_output=True).stdout.strip() != b'docker':
    raise SystemExit('Run only in the disposable Docker test host')
os.umask(0o077)
sys.path.insert(0, '/lab/scripts')
import node_install as install
import node_manager as manager
import node_runtime as runtime
import node_state as state

work = Path(tempfile.mkdtemp(prefix='node-mask-dns-', dir='/run'))
resolv = Path('/etc/resolv.conf')
original = resolv.read_bytes()
servers = []
failures = 0


def run(args, **kwargs):
    return subprocess.run(list(map(str, args)), capture_output=True, timeout=45, **kwargs)


def check(label, ok):
    global failures
    failures += not ok
    print(('PASS ' if ok else 'FAIL ')+label, flush=True)


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        if len(packet) < 17:
            return
        end = 12
        while end < len(packet) and packet[end]:
            end += packet[end]+1
        if end+5 > len(packet):
            return
        kind = int.from_bytes(packet[end+1:end+3], 'big')
        data = socket.inet_pton(socket.AF_INET if kind == 1 else socket.AF_INET6,
                                '11.77.0.128' if kind == 1 else '2620:fe::1234') if kind in (1, 28) else b''
        header = packet[:2]+struct.pack('!5H', 0x8180, 1, bool(data), 0, 0)
        answer = b'\xc0\x0c'+struct.pack('!HHIH', kind, 1, 5, len(data))+data if data else b''
        sock.sendto(header+packet[12:end+5]+answer, self.client_address)


class DNS6(socketserver.ThreadingUDPServer):
    address_family = socket.AF_INET6


class HTTP(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', '12')
        self.end_headers()
        self.wfile.write(b'mask-dns-ok!')

    def log_message(self, *_):
        pass


class HTTP6(ThreadingHTTPServer):
    address_family = socket.AF_INET6


try:
    if run(['ip', 'route', 'show', 'default'], check=True).stdout.strip():
        raise RuntimeError('external network must be detached')
    install.install_code('/lab/scripts')
    host = state.decode((install.ETC/'deployment.json').read_bytes())
    store = state.Store('/var/lib/vpnbot-node')
    backend = runtime.Runtime(store, host)
    control = manager.Manager(store, backend)
    before = store.load()
    for address in ('1.1.1.1', '9.9.9.9', '11.77.0.128'):
        run(['ip', 'address', 'replace', address+'/32', 'dev', 'lo'], check=True)
    for address in ('2606:4700:4700::1111', '2620:fe::fe', '2620:fe::1234'):
        run(['ip', '-6', 'address', 'replace', address+'/128', 'dev', 'lo', 'nodad'], check=True)
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
         '-subj', '/CN=mask.example.test', '-addext', 'subjectAltName=DNS:mask.example.test',
         '-keyout', work/'key.pem', '-out', work/'cert.pem'], check=True)
    for address in ('127.0.0.53', '1.1.1.1', '9.9.9.9', '2606:4700:4700::1111', '2620:fe::fe'):
        server = (DNS6 if ':' in address else socketserver.ThreadingUDPServer)((address, 53), DNS)
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    for address in ('11.77.0.128', '2620:fe::1234'):
        server = (HTTP6 if ':' in address else ThreadingHTTPServer)((address, 443), HTTP)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(work/'cert.pem', work/'key.pem')
        server.socket = context.wrap_socket(server.socket, server_side=True)
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    # Common systemd-resolved setup. The node must keep private DNS access
    # blocked while using a reachable public resolver for its mask target.
    resolv.write_text('nameserver 127.0.0.53\noptions timeout:1 attempts:1\n')
    for family in (4, 6):
        value = copy.deepcopy(before)
        value['options'] = dict(transport='reality', family=family, core='origin',
                                domain='', mask='mask.example.test', cover=False)
        change = control.apply(value)
        result = run(['curl', '--noproxy', '*', '-sS', '--max-time', '8', '--cacert', work/'cert.pem',
                      '--resolve', 'mask.example.test:8443:127.0.0.1', 'https://mask.example.test:8443/'])
        check('family'+str(family)+'-external-mask-dns-under-uid-guard', result.returncode == 0 and result.stdout == b'mask-dns-ok!')
        store.confirm(change['pending']['nonce'])
finally:
    resolv.write_bytes(original)
    if 'before' in locals():
        change = control.apply(before)
        store.confirm(change['pending']['nonce'])
    for server in servers:
        server.shutdown()
        server.server_close()
    shutil.rmtree(work)
raise SystemExit(bool(failures))
