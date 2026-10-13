#!/usr/bin/env python3
"""Три служебных сервера проверки маршрутов:
 :80   — «прямой» узел (отвечает DIRECT) и точка выдачи списков бота /pacfixture/<b64>;
 :3128 — «прокси» (любой запрос через него получает PROXY);
 :3129 — «прямой выход» для ядер, где direct подменён прокси (отвечает DIRECT);
 :8099 — сторонние rule-set из каталога /work/rs.
"""
import http.server, socketserver, subprocess, sys, threading, os

class Server(http.server.ThreadingHTTPServer):
    # Без getfqdn: в контейнере без сети он ждёт ответа DNS.
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name = 'lab'
        self.server_port = self.server_address[1]

class Base(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    word = b'DIRECT'
    def log_message(self, *a): pass
    def send(self, code, body, kind='text/plain'):
        self.send_response(code); self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(body))); self.send_header('Connection', 'close'); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        with open('/work/requests.log', 'a') as f: f.write('%s %s %s\n' % (self.server.server_port, self.headers.get('Host', '-'), self.path[:60]))
        self.handle_get()
    def handle_get(self): self.send(200, self.word)
    def do_CONNECT(self):
        # Ядра ходят через HTTP-прокси методом CONNECT: открываем «туннель» и
        # сами отвечаем на запрос внутри него.
        with open('/work/requests.log', 'a') as f: f.write('%s CONNECT %s\n' % (self.server.server_port, self.path))
        self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n'); self.wfile.flush()
        data = b''
        while b'\r\n\r\n' not in data:
            chunk = self.connection.recv(4096)
            if not chunk: return
            data += chunk
        self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(self.word) + self.word)
        self.wfile.flush(); self.close_connection = True

class Direct(Base):
    def handle_get(self):
        if self.path.startswith('/pacfixture/'):
            r = subprocess.run(['php', '/lab/routes.php', 'serve', self.path.split('/', 2)[2]], capture_output=True, timeout=60)
            if r.returncode != 0 or not r.stdout:
                return self.send(500, r.stderr[-300:] or b'empty')
            return self.send(200, r.stdout, 'application/octet-stream')
        self.send(200, b'DIRECT')

class Proxy(Base): word = b'PROXY'
class DirectOut(Base): word = b'DIRECT'

class Files(Base):
    def handle_get(self):
        path = '/work/rs/' + os.path.basename(self.path.split('?', 1)[0])
        if not os.path.isfile(path): return self.send(404, b'')
        self.send(200, open(path, 'rb').read(), 'application/octet-stream')

for port, handler in ((80, Direct), (3128, Proxy), (3129, DirectOut), (8099, Files)):
    server = Server(('0.0.0.0', port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
threading.Event().wait()
