#!/usr/bin/env python3
"""Минимальный WebDAV для проверки XDRIVE: PUT, GET, DELETE и PROPFIND глубины 1.

webdav_server.py КАТАЛОГ АДРЕС ПОРТ ЛОГИН ПАРОЛЬ

Хранит файлы в каталоге; вложенные папки должны существовать заранее, как в
настоящем хранилище. Нужен тесту на ядре и сетевому стенду: внешнее хранилище
в проверках не используется.
"""
import base64
import http.server
import os
import sys
import urllib.parse

ROOT, HOST, PORT, USER, PASSWORD = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
EXPECTED = 'Basic ' + base64.b64encode(f'{USER}:{PASSWORD}'.encode()).decode()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def reply(self, code, body=b'', kind='text/plain'):
        try:
            self.send_response(code)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass  # клиент закрыл соединение, не дождавшись ответа

    def target(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        self.body = self.rfile.read(length) if length else b''
        if self.headers.get('Authorization') != EXPECTED:
            self.reply(401)
            return None
        parts = [part for part in urllib.parse.unquote(urllib.parse.urlparse(self.path).path).split('/') if part]
        if any(part in ('.', '..') for part in parts):
            self.reply(400)
            return None
        return os.path.join(ROOT, *parts), parts

    def do_PUT(self):
        found = self.target()
        if not found:
            return
        path = found[0]
        if not os.path.isdir(os.path.dirname(path)):
            return self.reply(409)
        with open(path + '.part', 'wb') as stream:
            stream.write(self.body)
        os.replace(path + '.part', path)
        self.reply(201)

    def do_GET(self):
        found = self.target()
        if not found:
            return
        try:
            with open(found[0], 'rb') as stream:
                self.reply(200, stream.read(), 'application/octet-stream')
        except OSError:
            self.reply(404)

    def do_DELETE(self):
        found = self.target()
        if not found:
            return
        try:
            os.remove(found[0])
            self.reply(204)
        except OSError:
            self.reply(404)

    def do_PROPFIND(self):
        found = self.target()
        if not found:
            return
        path, parts = found
        if not os.path.isdir(path):
            return self.reply(404)
        base = '/' + '/'.join(urllib.parse.quote(part) for part in parts)
        names = sorted(name for name in os.listdir(path) if not name.endswith('.part'))
        items = ''.join(f'<d:response><d:href>{base}/{urllib.parse.quote(name)}</d:href></d:response>' for name in names)
        self.reply(207, ('<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>' + base
                         + '/</d:href></d:response>' + items + '</d:multistatus>').encode(), 'application/xml; charset=utf-8')


http.server.ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
