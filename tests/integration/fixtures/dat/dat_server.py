#!/usr/bin/env python3
"""Источник файлов .dat для сетевого стенда: HTTPS, ETag и 304, суммы рядом.

dat_server.py КАТАЛОГ АДРЕС ПОРТ СЕРТИФИКАТ КЛЮЧ

Отдаёт файлы каталога. Для каждого файла отвечает и на `<имя>.sha256sum`:
сумма считается на лету, если рядом не лежит готовый файл с таким именем
(так стенд подкладывает неверную сумму). Запросы пишутся в `requests.log`
каталога строками «код путь». Внешние источники в проверках не используются.
"""
import hashlib
import http.server
import os
import ssl
import sys

ROOT, HOST, PORT, CERT, KEY = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def reply(self, code, body=b'', headers=()):
        with open(os.path.join(ROOT, 'requests.log'), 'a') as log:
            log.write(f'{code} {self.path}\n')
        self.send_response(code)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        name = os.path.basename(self.path.split('?', 1)[0])
        path = os.path.join(ROOT, name)
        if name in ('', 'requests.log'):
            return self.reply(404)
        if not os.path.isfile(path):
            source = path[:-len('.sha256sum')]
            if name.endswith('.sha256sum') and os.path.isfile(source):
                with open(source, 'rb') as handle:
                    digest = hashlib.sha256(handle.read()).hexdigest()
                return self.reply(200, f'{digest}  {os.path.basename(source)}\n'.encode())
            return self.reply(404)
        with open(path, 'rb') as handle:
            body = handle.read()
        etag = '"' + hashlib.sha256(body).hexdigest()[:32] + '"'
        if self.headers.get('If-None-Match') == etag:
            return self.reply(304, headers=[('ETag', etag)])
        self.reply(200, body, [('ETag', etag), ('Content-Type', 'application/octet-stream')])


server = http.server.ThreadingHTTPServer((HOST, PORT), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(CERT, KEY)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
