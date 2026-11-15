"""Actual AnyTLS authentication/stream revoke through Supervisor.tick and PHP shared sync."""
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback

sys.path.insert(0, '/audit-source/scripts')
from protocol_service import Supervisor

ROOT = Path('/audit-fixture')
ROWS = []
DIAGNOSTICS = {}


def check(name, ok):
    ROWS.append({'name': name, 'passed': bool(ok)})
    if not ok:
        raise RuntimeError(name)


def command(argv, timeout=30):
    return subprocess.run(argv, capture_output=True, timeout=timeout)


def driver(root, *args):
    p = command(['php', '-d', 'display_errors=0', '/audit-tools/driver.php', str(root), *args])
    if p.returncode or json.loads(p.stdout).get('ok') is not True:
        raise RuntimeError('PHP synthetic driver failed')


class Target(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        try:
            if self.path == '/stream':
                for _ in range(1200):
                    self.wfile.write(b'synthetic-stream\n')
                    self.wfile.flush()
                    time.sleep(.05)
            else:
                self.wfile.write(b'SYNTHETIC-MANAGED-SYNC\n')
        except (BrokenPipeError, ConnectionResetError):
            pass


class Client:
    def __init__(self, root, source, port):
        self.port = port
        state = json.loads((root / 'protocols/anytls/desired.json').read_text())
        user = next(u for u in state['users'].values() if u['xray_source'] == source * 32)
        config = {'log': {'disabled': True}, 'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': port}],
                  'outbounds': [{'type': 'anytls', 'server': '127.0.0.1', 'server_port': 8443, 'password': user['password'],
                                 'tls': {'enabled': True, 'server_name': 'vpn.example.test', 'certificate_path': '/certs/cert_public'}}]}
        path = root / ('client-' + str(port) + '.json')
        path.write_text(json.dumps(config))
        self.process = subprocess.Popen(['sing-box', 'run', '-c', str(path)], stdin=subprocess.DEVNULL,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        until = time.monotonic() + 8
        while time.monotonic() < until and self.process.poll() is None:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.2):
                    return
            except OSError:
                time.sleep(.05)
        self.close()
        raise RuntimeError('native client unavailable')

    def request(self):
        p = command(['curl', '--socks5-hostname', '127.0.0.1:' + str(self.port), '--noproxy', '',
                     '--max-time', '2', '-fsS', 'http://11.77.0.2:18081/'], timeout=5)
        return p.returncode == 0 and p.stdout == b'SYNTHETIC-MANAGED-SYNC\n'

    def stream(self):
        sock = socket.create_connection(('127.0.0.1', self.port), timeout=3)
        def read(n):
            data = b''
            while len(data) < n:
                chunk = sock.recv(n - len(data))
                if not chunk:
                    raise EOFError('native stream setup closed')
                data += chunk
            return data
        sock.sendall(b'\x05\x01\x00')
        if read(2) != b'\x05\x00':
            raise RuntimeError('native SOCKS negotiation failed')
        sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('11.77.0.2') + struct.pack('!H', 18081))
        head = read(4)
        if head[1] != 0:
            raise RuntimeError('native SOCKS connect failed')
        read(6 if head[3] == 1 else 18)
        sock.sendall(b'GET /stream HTTP/1.1\r\nHost: synthetic\r\n\r\n')
        if b'200' not in sock.recv(4096):
            raise RuntimeError('native stream control failed')
        return sock

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)


def closed(sock):
    sock.settimeout(.3)
    until = time.monotonic() + 3
    while time.monotonic() < until:
        try:
            if sock.recv(4096) == b'':
                return True
        except (ConnectionResetError, BrokenPipeError):
            return True
        except TimeoutError:
            pass
    return False


def main():
    os.umask(0o077)
    ROOT.mkdir(exist_ok=True)
    p = command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                 '-subj', '/CN=vpn.example.test', '-addext', 'subjectAltName=DNS:vpn.example.test',
                 '-keyout', '/certs/cert_private', '-out', '/certs/cert_public'])
    if p.returncode:
        raise RuntimeError('synthetic TLS generation failed')
    p = command(['ip', 'addr', 'add', '11.77.0.2/32', 'dev', 'lo'])
    if p.returncode:
        raise RuntimeError('isolated address setup failed')
    for argv in [['ip', 'link', 'add', 'audit0', 'type', 'dummy'], ['ip', 'link', 'set', 'audit0', 'up'], ['ip', 'addr', 'add', '192.0.2.1/30', 'dev', 'audit0'], ['ip', 'route', 'add', 'default', 'dev', 'audit0']]:
        p = command(argv)
        if p.returncode:
            DIAGNOSTICS['network'] = {'argv': argv, 'error': p.stderr.decode(errors='replace')[:200]}
            raise RuntimeError('isolated default interface setup failed')
    stats = Path('/audit-bin/protocol-stats')
    httpd = http.server.ThreadingHTTPServer(('11.77.0.2', 18081), Target)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        for number, (kind, operation) in enumerate([('usage', 'disable'), ('desired', 'delete'), ('usage', 'rotate'), ('usage', 'quota'), ('target', 'none')]):
            root = ROOT / ('case-' + str(number))
            root.mkdir()
            clients = []
            stream = None
            supervisor = None
            label = kind + '-' + operation
            try:
                driver(root, 'init')
                os.environ['PROTOCOL_DESIRED'] = str(root / 'protocols/anytls/desired.json')
                supervisor = Supervisor(root / 'protocols/anytls/runtime', shutil.which('sing-box'), str(stats))
                try:
                    supervisor.tick()
                except Exception:
                    p = command([str(stats)])
                    DIAGNOSTICS['stats'] = {'exit': p.returncode, 'stdout_bytes': len(p.stdout), 'stderr_bytes': len(p.stderr), 'classes': [x for x in ['unknown command', 'flag provided but not defined', 'connection refused', 'deadline exceeded', 'not found', 'Permission denied', 'Unimplemented'] if x.encode().lower() in p.stderr.lower()]}
                    log = (supervisor.root / 'core.log').read_bytes() if (supervisor.root / 'core.log').exists() else b''
                    DIAGNOSTICS['core'] = {'bytes': len(log), 'classes': [x for x in ['operation not permitted', 'network is unreachable', 'unknown', 'FATAL', 'not found', 'no such file', 'v2ray', 'permission denied'] if x.encode().lower() in log.lower()]}
                    raise
                for letter, port in [('a', 10801), ('b', 10802), ('c', 10803)]:
                    clients.append(Client(root, letter, port))
                check(label + '-healthy-auth-positive-control', all(c.request() for c in clients))
                stream = clients[0].stream()
                driver(root, 'fault', kind, operation)
                # Execute the original supervisor tick with real core/API. No
                # mock counters, mocked apply or manually edited auth config.
                try:
                    supervisor.tick()
                except (RuntimeError, ValueError, KeyError):
                    pass
                if kind == 'target':
                    check(label + '-target-core-stopped', not supervisor.alive())
                    check(label + '-old-stream-closed', closed(stream))
                    check(label + '-old-auth-denied', not clients[0].request())
                    driver(root, 'repair')
                    supervisor.tick()
                    check(label + '-repair-auth-control', clients[0].request())
                elif operation == 'quota':
                    check(label + '-unknown-limited-auth-denied', not clients[2].request())
                    check(label + '-unlimited-auth-retained', clients[0].request() and clients[1].request())
                else:
                    check(label + '-old-stream-closed', closed(stream))
                    check(label + '-old-auth-denied', not clients[0].request())
                    check(label + '-neighbour-auth-retained', clients[1].request())
                    if operation == 'rotate':
                        clients.append(Client(root, 'a', 10804))
                        check(label + '-new-auth-control', clients[-1].request())
            finally:
                if stream is not None:
                    stream.close()
                for client in clients:
                    client.close()
                if supervisor is not None:
                    supervisor.stop()
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == '__main__':
    try:
        main()
        result = {'status': 'PASS', 'checks': ROWS}
    except Exception as error:
        result = {'status': 'FAIL', 'checks': ROWS, 'error_class': type(error).__name__, 'error_line': traceback.extract_tb(error.__traceback__)[-1].lineno, 'error_file': Path(traceback.extract_tb(error.__traceback__)[-1].filename).name, 'diagnostics': DIAGNOSTICS}
    print(json.dumps(result))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)
