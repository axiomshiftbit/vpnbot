#!/usr/bin/env python3
"""Synthetic HTTP/SOCKS endpoint and traffic checks; credentials never leave files."""
import http.server
import json
from pathlib import Path
import secrets
import socket
import struct
import sys
import time

ROOT = Path('/config')


def read_exact(sock, length):
    result = b''
    while len(result) < length:
        data = sock.recv(length - len(result))
        if not data:
            raise RuntimeError('SOCKS response truncated')
        result += data
    return result


def connect(port):
    sock = socket.create_connection(('127.0.0.1', int(port)), timeout=2)
    sock.sendall(b'\x05\x01\x00')
    if read_exact(sock, 2) != b'\x05\x00':
        raise RuntimeError('SOCKS negotiation failed')
    sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', 18081))
    reply = read_exact(sock, 10)
    if len(reply) != 10 or reply[:2] != b'\x05\x00':
        raise RuntimeError('SOCKS connection failed')
    return sock


def seed():
    generation = {name: secrets.token_hex(24) for name in ('old', 'new')}
    (ROOT / 'generations.json').write_text(json.dumps(generation))
    (ROOT / 'pac.json').write_text('{}')
    (ROOT / 'ss.acl').write_text('[proxy_all]\n')
    common = {'server': '127.0.0.1', 'server_port': 8388, 'method': 'chacha20-ietf-poly1305',
              'password': generation['old'], 'mode': 'tcp_only'}
    (ROOT / 'ssserver.json').write_text(json.dumps(dict(common, acl='/config/ss.acl')))
    (ROOT / 'sslocal.json').write_text(json.dumps(dict(common, local_address='127.0.0.1', local_port=1080)))
    for name, port in (('old', 1088), ('new', 1089)):
        (ROOT / ('client-' + name + '.json')).write_text(json.dumps(dict(
            common, password=generation[name], local_address='127.0.0.1', local_port=port)))
    (ROOT / 'initial-inodes.json').write_text(json.dumps({name: (ROOT / (name + '.json')).stat().st_ino
                                                        for name in ('ssserver', 'sslocal')}))
    for p in ROOT.iterdir():
        if p.is_file():
            p.chmod(0o600)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        if self.path == '/stream':
            try:
                for _ in range(600):
                    self.wfile.write(b'x' * 64)
                    self.wfile.flush()
                    time.sleep(.1)
            except (OSError, ConnectionError):
                pass
        else:
            self.wfile.write(b'synthetic-positive-control')


def main():
    mode = sys.argv[1]
    if mode == 'serve':
        seed()
        http.server.ThreadingHTTPServer(('127.0.0.1', 18081), Handler).serve_forever()
    elif mode == 'traffic':
        try:
            with connect(sys.argv[2]) as sock:
                sock.sendall(b'GET / HTTP/1.0\r\nHost: synthetic.test\r\n\r\n')
                body = b''
                while b'synthetic-positive-control' not in body and len(body) < 4096:
                    data = sock.recv(4096)
                    if not data:
                        break
                    body += data
                ok = b'synthetic-positive-control' in body
        except (OSError, RuntimeError):
            ok = False
        print(json.dumps({'ok': ok}))
    elif mode == 'hold':
        try:
            with connect(1088) as sock:
                sock.sendall(b'GET /stream HTTP/1.0\r\nHost: synthetic.test\r\n\r\n')
                if b'200' not in sock.recv(4096):
                    raise RuntimeError('stream not established')
                (ROOT / 'stream-open').touch()
                while sock.recv(4096):
                    pass
        except (OSError, RuntimeError):
            pass
        finally:
            (ROOT / 'stream-closed').touch()
    elif mode == 'state':
        values = json.loads((ROOT / 'generations.json').read_text())
        initial = json.loads((ROOT / 'initial-inodes.json').read_text())
        result = {'stream_open': (ROOT / 'stream-open').exists(), 'stream_closed': (ROOT / 'stream-closed').exists()}
        for name in ('ssserver', 'sslocal'):
            p = ROOT / (name + '.json')
            conf = json.loads(p.read_text())
            result[name] = {'old': conf['password'] == values['old'], 'new': conf['password'] == values['new'],
                            'same_inode': p.stat().st_ino == initial[name], 'private': p.stat().st_mode & 0o777 == 0o600}
        print(json.dumps(result))
    else:
        raise RuntimeError('unknown fixture mode')


if __name__ == '__main__':
    main()
