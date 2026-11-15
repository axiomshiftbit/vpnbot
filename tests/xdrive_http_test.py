"""Настоящий cURL/HTTP/TLS; только результат проверки IP подменён для loopback."""
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('php') and shutil.which('openssl'), 'нужны PHP и OpenSSL')
class XdriveHttpTests(unittest.TestCase):
    def test_transport_pin_limits_tls_and_proxy(self):
        with tempfile.TemporaryDirectory() as directory:
            cert, key = Path(directory) / 'cert.pem', Path(directory) / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                            'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=localhost',
                            '-addext', 'subjectAltName=DNS:localhost', '-keyout', str(key), '-out', str(cert)],
                           check=True, capture_output=True)
            seen, servers = [], []

            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def handle(self):
                    try:
                        super().handle()
                    except (ConnectionResetError, BrokenPipeError):
                        pass

                def do_GET(self):
                    seen.append((self.server.server_address[0], self.path))
                    if self.path == '/redirect':
                        self.send_response(302)
                        self.send_header('Location', '/ok')
                        self.send_header('Content-Length', '0')
                        self.end_headers()
                        return
                    large = self.path in ('/large', '/chunked')
                    body = b'x' * (16384 if large else 2)
                    count = 192 if large else 1
                    self.send_response(200)
                    if self.path == '/chunked':
                        self.send_header('Transfer-Encoding', 'chunked')
                    else:
                        self.send_header('Content-Length', str(len(body) * count))
                    self.end_headers()
                    for _ in range(count):
                        self.wfile.write((b'%x\r\n' % len(body)) + body + b'\r\n' if self.path == '/chunked' else body)
                    if self.path == '/chunked':
                        self.wfile.write(b'0\r\n\r\n')

            def start(address, tls=False, port=0):
                server = http.server.ThreadingHTTPServer((address, port), Handler)
                if tls:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(cert, key)
                    server.socket = context.wrap_socket(server.socket, server_side=True)
                servers.append(server)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                return server.server_port

            code = r'''
require $argv[1] . '/app/bot.php';
class ProbeHttpBot extends Bot {
    public function __construct() {}
    protected function xdrivePublicIps(string $url): array {
        return in_array(parse_url($url, PHP_URL_HOST), ['localhost', 'wrong.invalid'], true) ? ['127.0.0.2'] : [];
    }
    public function probeRequest(string $url): array { return $this->xdriveHttp('GET', $url); }
}
[$status, $body] = (new ProbeHttpBot())->probeRequest($argv[2]);
echo json_encode(['status' => $status, 'bytes' => strlen($body), 'peak' => memory_get_peak_usage(true)]);
'''

            def request(url, environment=None):
                result = subprocess.run(['php', '-d', f'curl.cainfo={cert}', '-d', 'memory_limit=32M',
                                         '-r', code, str(ROOT), url], capture_output=True, text=True, timeout=20,
                                        env=environment or {**os.environ, 'NO_PROXY': '*', 'no_proxy': '*'})
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(result.stdout)

            try:
                port = start('127.0.0.2')
                start('127.0.0.1', port=port)
                tls_port = start('127.0.0.2', tls=True)
                start('127.0.0.1', tls=True, port=tls_port)
                base = f'http://localhost:{port}'
                for scheme, p in (('http', port), ('https', tls_port)):
                    with self.subTest(scheme=scheme):
                        self.assertEqual(request(f'{scheme}://localhost:{p}/ok')['status'], 200)
                self.assertFalse(any(ip == '127.0.0.1' for ip, _ in seen), 'cURL использует закреплённый IP')
                for path in ('/large', '/chunked'):
                    with self.subTest(path=path):
                        self.assertEqual(request(base + '/ok')['bytes'], 2)
                        result = request(base + path)
                        self.assertEqual((result['status'], result['bytes']), (0, 0))
                self.assertEqual(request(f'https://wrong.invalid:{tls_port}/ok')['status'], 0)
                before = len(seen)
                self.assertEqual(request(base + '/redirect')['status'], 302)
                self.assertEqual(len(seen), before + 1, 'redirect не обходится автоматически')
                self.assertEqual(request(f'http://127.0.0.1:{port}/ok')['status'], 0)
                with socket.socket() as proxy:
                    proxy.bind(('127.0.0.1', 0))
                    proxy.listen()
                    proxy.settimeout(.2)
                    address = 'http://127.0.0.1:%d' % proxy.getsockname()[1]
                    env = {k: v for k, v in os.environ.items() if k.lower() != 'no_proxy'}
                    env.update(HTTP_PROXY=address, http_proxy=address, ALL_PROXY=address, all_proxy=address)
                    self.assertEqual(request(base + '/ok', env)['status'], 200)
                    with self.assertRaises(socket.timeout):
                        proxy.accept()
            finally:
                for server in servers:
                    server.shutdown()
                    server.server_close()


if __name__ == '__main__':
    unittest.main()
