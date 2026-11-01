#!/usr/bin/env python3
"""Disconnected container fixture: real TLS, downloads, restore and Xray check."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socketserver import TCPServer
import hashlib
import os
import ssl
import subprocess
import threading

os.umask(0o077)
root = Path('/work')
(root/'serve').mkdir(parents=True)
subprocess.run(['ip', 'address', 'add', '11.77.0.128/32', 'dev', 'lo'], check=True, capture_output=True)
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=dat-fixture', '-addext', 'subjectAltName=IP:11.77.0.128',
                '-keyout', '/work/tls.key', '-out', '/work/ca.pem'], check=True, capture_output=True)

class Server(ThreadingHTTPServer):
    def server_bind(self):
        TCPServer.server_bind(self)
        self.server_name, self.server_port = 'fixture', self.server_address[1]

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/redirect.dat':
            self.send_response(302)
            self.send_header('Location', 'https://127.0.0.1:18443/services.dat')
            self.end_headers()
            return
        path = root/'serve/services.dat'
        if self.path not in ('/services.dat', '/services.dat.sha256sum') or not path.is_file():
            self.send_response(404)
            self.end_headers()
            return
        data = path.read_bytes()
        if self.path.endswith('.sha256sum'):
            data = (hashlib.sha256(data).hexdigest()+'  services.dat\n').encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass

server = Server(('11.77.0.128', 18443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/work/ca.pem', '/work/tls.key')
server.socket = context.wrap_socket(server.socket, server_side=True)
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    result = subprocess.run(['php', '-d', 'curl.cainfo=/work/ca.pem', '/lab/tests/integration/fixtures/managed-node-dat-download.php'], capture_output=True)
    for line in result.stdout.decode().splitlines():
        if line.startswith(('PASS ', 'FAIL ')):
            print(line, flush=True)
    if result.returncode and b'FAIL ' not in result.stdout:
        print('FAIL PHP fixture exited before assertions', flush=True)
    raise SystemExit(result.returncode)
finally:
    server.shutdown()
    (root/'tls.key').unlink(missing_ok=True)
