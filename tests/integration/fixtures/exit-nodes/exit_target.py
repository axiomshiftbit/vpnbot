#!/usr/bin/env python3
"""Цель для набора узлов выхода: по ответу видно, каким путём пришёл запрос.

exit_target.py СЕРТИФИКАТ КЛЮЧ

- HTTP :8455 — тело `src=<адрес источника>`: через узел источник — контейнер
  узла, напрямую — сам Xray бота;
- HTTPS :443 — то, о чём спрашивает проба бота (generate_204, cdn-cgi/trace,
  страница YouTube); имена этих сайтов узел разрешает в адрес цели;
- HTTPS :8456 — маска REALITY узла (ядро 26.10.17 требует у маски ALPN).

Запросы пишутся в /tmp/exit-target.log строками «порт хост путь источник».
Внешние сервисы не используются.
"""
import http.server
import socketserver
import ssl
import sys
import threading

CERT, KEY = sys.argv[1], sys.argv[2]


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    # Без getfqdn: в стенде он ждёт DNS.
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def do_GET(self):
        source = self.client_address[0]
        host = (self.headers.get('Host') or '').split(':')[0]
        path = self.path.split('?', 1)[0]
        with open('/tmp/exit-target.log', 'a') as log:
            log.write(f'{self.server.server_port} {host} {path} {source}\n')
        code, body = 200, f'src={source}\n'
        if self.server.server_port == 443:
            if path == '/generate_204':
                code, body = 204, ''
            elif path == '/cdn-cgi/trace':
                body = f'ip={source}\nloc=FI\n'
            elif host == 'www.youtube.com':
                body = '<script>ytcfg.set({"INNERTUBE_CONTEXT_GL":"FI"})</script>'
            else:
                code, body = 404, ''
        data = body.encode()
        self.send_response(code)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def tls(server, alpn):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(CERT, KEY)
    context.set_alpn_protocols(alpn)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


servers = [Server(('0.0.0.0', 8455), Handler),
           tls(Server(('0.0.0.0', 443), Handler), ['http/1.1']),
           tls(Server(('0.0.0.0', 8456), Handler), ['h2', 'http/1.1'])]
for server in servers[1:]:
    threading.Thread(target=server.serve_forever, daemon=True).start()
servers[0].serve_forever()
