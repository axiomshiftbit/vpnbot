#!/usr/bin/env python3
"""Минимальный S3 для проверки XDRIVE: PUT, GET, DELETE объекта и ListObjectsV2.

s3_server.py АДРЕС ПОРТ БАКЕТ РЕГИОН КЛЮЧ СЕКРЕТ

Адресация через путь (/<бакет>/<ключ>), объекты в памяти. Подпись AWS SigV4
проверяется по-настоящему: неверный ключ, секрет, регион или искажённый
запрос получают 403 SignatureDoesNotMatch, как от настоящего S3. Нужен тесту
на ядре: внешнее хранилище в проверках не используется.
"""
import hashlib
import hmac
import http.server
import sys
import threading
import urllib.parse
from xml.sax.saxutils import escape

HOST, PORT, BUCKET, REGION, ACCESS, SECRET = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
OBJECTS, LOCK = {}, threading.Lock()


def quote(value):
    return urllib.parse.quote(value, safe='-_.~')


def signature_ok(handler, body):
    auth = handler.headers.get('Authorization', '')
    if not auth.startswith('AWS4-HMAC-SHA256 '):
        return False
    fields = dict(part.strip().split('=', 1) for part in auth[len('AWS4-HMAC-SHA256 '):].split(',') if '=' in part)
    credential = fields.get('Credential', '').split('/')
    if len(credential) != 5 or credential[0] != ACCESS or credential[2] != REGION or credential[3:] != ['s3', 'aws4_request']:
        return False
    payload = handler.headers.get('X-Amz-Content-Sha256', '')
    stamp = handler.headers.get('X-Amz-Date', '')
    if payload != hashlib.sha256(body).hexdigest() or not stamp.startswith(credential[1]):
        return False
    signed = fields.get('SignedHeaders', '').split(';')
    if not {'host', 'x-amz-content-sha256', 'x-amz-date'} <= set(signed):
        return False
    path, _, raw_query = handler.path.partition('?')
    pairs = sorted(urllib.parse.parse_qsl(raw_query, keep_blank_values=True))
    query = '&'.join(quote(name) + '=' + quote(value) for name, value in pairs)
    headers = ''.join(f"{name}:{' '.join((handler.headers.get(name) or '').split())}\n" for name in signed)
    canonical = '\n'.join([handler.command, path, query, headers, ';'.join(signed), payload])
    scope = '/'.join(credential[1:])
    to_sign = '\n'.join(['AWS4-HMAC-SHA256', stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = ('AWS4' + SECRET).encode()
    for part in credential[1:]:
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    expected = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, fields.get('Signature', ''))


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def reply(self, code, body=b'', kind='application/xml'):
        try:
            self.send_response(code)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass  # клиент закрыл соединение, не дождавшись ответа

    def error(self, code, name):
        self.reply(code, f'<?xml version="1.0" encoding="UTF-8"?><Error><Code>{name}</Code></Error>'.encode())

    def target(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        self.body = self.rfile.read(length) if length else b''
        if not signature_ok(self, self.body):
            self.error(403, 'SignatureDoesNotMatch')
            return None
        path, _, raw_query = self.path.partition('?')
        bucket, _, key = urllib.parse.unquote(path).lstrip('/').partition('/')
        if bucket != BUCKET:
            self.error(404, 'NoSuchBucket')
            return None
        return key, dict(urllib.parse.parse_qsl(raw_query, keep_blank_values=True))

    def do_PUT(self):
        found = self.target()
        if found:
            with LOCK:
                OBJECTS[found[0]] = self.body
            self.reply(200, b'')

    def do_GET(self):
        found = self.target()
        if not found:
            return
        key, query = found
        if key:
            with LOCK:
                data = OBJECTS.get(key)
            return self.reply(200, data, 'application/octet-stream') if data is not None else self.error(404, 'NoSuchKey')
        if query.get('list-type') != '2':
            return self.error(400, 'InvalidArgument')
        prefix, delimiter = query.get('prefix', ''), query.get('delimiter', '')
        with LOCK:
            keys = sorted(name for name in OBJECTS if name.startswith(prefix))
        contents, folders = [], set()
        for name in keys:
            rest = name[len(prefix):]
            if delimiter and delimiter in rest:
                folders.add(prefix + rest.split(delimiter, 1)[0] + delimiter)
            else:
                contents.append(f'<Contents><Key>{escape(name)}</Key><Size>{len(OBJECTS.get(name, b""))}</Size></Contents>')
        common = ''.join(f'<CommonPrefixes><Prefix>{escape(name)}</Prefix></CommonPrefixes>' for name in sorted(folders))
        self.reply(200, ('<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>' + escape(BUCKET) + '</Name><Prefix>'
                         + escape(prefix) + '</Prefix><KeyCount>' + str(len(contents)) + '</KeyCount><IsTruncated>false</IsTruncated>'
                         + ''.join(contents) + common + '</ListBucketResult>').encode())

    def do_DELETE(self):
        found = self.target()
        if found:
            with LOCK:
                OBJECTS.pop(found[0], None)
            self.reply(204)


http.server.ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
