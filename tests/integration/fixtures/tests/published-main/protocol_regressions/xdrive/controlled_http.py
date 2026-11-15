#!/usr/bin/env python3
"""Ограниченный HTTP/WebDAV fixture. Запускать только в синтетическом контейнере."""
import argparse
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import threading
from urllib.parse import quote, urlsplit

MARKER = Path('/run/vpnbot-synthetic-audit')
MAX_RESPONSE = 96 * 1024 * 1024

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bind', default='127.0.0.1')
    p.add_argument('--port', type=int, default=8098)
    p.add_argument('--label', choices=('public', 'private', 'large'), default='public')
    p.add_argument('--propfind-bytes', type=int, default=0)
    a = p.parse_args()
    ip = ipaddress.ip_address(a.bind)
    if not MARKER.is_file() or MARKER.is_symlink() or MARKER.read_text().strip() != 'SYNTHETIC-ONLY':
        p.error('нужен маркер одноразового стенда /run/vpnbot-synthetic-audit')
    if not (ip.is_loopback or ip in ipaddress.ip_network('11.77.78.0/24') or ip in ipaddress.ip_network('172.30.79.0/24')):
        p.error('разрешены только адреса из предусмотренных тестовых сетей')
    if not 0 <= a.propfind_bytes <= MAX_RESPONSE or not 1024 <= a.port <= 65535:
        p.error('неверные пределы размера или порта')
    counters = Counter()
    files = {}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *args):
            pass
        def reply(self, status, body=b'', kind='text/plain'):
            self.send_response(status)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True
        def note(self):
            # Не сохраняем Authorization, Cookie, query string или тела запросов.
            with lock:
                counters[self.command] += 1
        def do_PROPFIND(self):
            self.note()
            if a.propfind_bytes:
                self.send_response(207)
                self.send_header('Content-Type', 'application/xml')
                self.send_header('Content-Length', str(a.propfind_bytes))
                self.send_header('Connection', 'close')
                self.end_headers()
                left = a.propfind_bytes
                try:
                    while left:
                        chunk = b'x' * min(left, 16384)
                        self.wfile.write(chunk)
                        left -= len(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                self.close_connection = True
                return
            with lock:
                names = list(files)
            body = '<d:multistatus xmlns:d="DAV:">' + ''.join('<d:response><d:href>' + quote(name) + '</d:href></d:response>' for name in names) + '</d:multistatus>'
            self.reply(207, body.encode(), 'application/xml')
        def do_PUT(self):
            self.note()
            try:
                length = int(self.headers.get('Content-Length', '0'))
            except ValueError:
                return self.reply(400)
            if not 0 <= length <= 4096:
                return self.reply(413)
            path = urlsplit(self.path).path
            body = self.rfile.read(length)
            with lock:
                if len(files) >= 16 and path not in files:
                    return self.reply(507)
                files[path] = body
            self.reply(201)
        def do_DELETE(self):
            self.note()
            with lock:
                files.pop(urlsplit(self.path).path, None)
            self.reply(204)
        def do_GET(self):
            path = urlsplit(self.path).path
            if path == '/stats':
                with lock:
                    body = json.dumps({'label': a.label, 'counts': dict(counters), 'objects': len(files)}).encode()
                return self.reply(200, body, 'application/json')
            self.note()
            with lock:
                body = files.get(path)
            self.reply(200, body if body is not None else a.label.encode())
    server = ThreadingHTTPServer((a.bind, a.port), Handler)
    server.daemon_threads = True
    print(json.dumps({'ready': True, 'label': a.label, 'port': a.port}), flush=True)
    server.serve_forever()

if __name__ == '__main__':
    main()
