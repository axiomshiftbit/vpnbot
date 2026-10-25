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
class ExitRulesetDownloadTest(unittest.TestCase):
    def test_pinned_https_redirect_ipv6_and_certificate(self):
        # После проверки DNS возвращает 127.0.0.2; обычный резолвер localhost
        # ведёт на 127.0.0.1. Оба сервера настоящие, с доверенным сертификатом.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key = root / 'cert.pem', root / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                            'ec_paramgen_curve:P-256', '-nodes', '-days', '1',
                            '-subj', '/CN=localhost', '-addext',
                            'subjectAltName=DNS:localhost,DNS:localhost.,IP:127.0.0.1,IP:::1',
                            '-keyout', str(key), '-out', str(cert)],
                           check=True, capture_output=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            seen = []

            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def handle(self):
                    try:
                        super().handle()
                    except (ConnectionResetError, BrokenPipeError):
                        pass  # Клиент прерывает TLS при неверном имени сертификата.

                def do_GET(self):
                    seen.append((self.server.server_address[0], self.path))
                    if self.path in ('/redirect', '/private', '/loop'):
                        host = '127.0.0.1' if self.path == '/private' else 'localhost.'
                        path = '/loop' if self.path == '/loop' else '/ok'
                        self.send_response(302)
                        self.send_header('Location', f'https://{host}:{port}{path}')
                        self.send_header('Content-Length', '0')
                        self.end_headers()
                        return
                    address = self.server.server_address[0]
                    wrong = address == '127.0.0.1' or (address == '::1' and not self.headers['Host'].startswith('['))
                    body = b'wrong-address' if wrong else b'ruleset'
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            servers = []
            def start(server):
                server.socket = context.wrap_socket(server.socket, server_side=True)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                servers.append(server)
                return server

            try:
                good = start(http.server.ThreadingHTTPServer(('127.0.0.2', 0), Handler))
                port = good.server_port
                start(http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler))
                class IPv6Server(http.server.ThreadingHTTPServer):
                    address_family = socket.AF_INET6
                start(IPv6Server(('::1', port), Handler))
                code = r'''
require $argv[1] . '/app/bot.php';
class PinnedDownloadBot extends Bot {
    public function __construct() {}
    public function xdriveHostPublic(string $url): bool { return true; }
    public function safeExtUrlIps(string $url): array {
        return match(parse_url($url, PHP_URL_HOST)) {
            'localhost', 'localhost.', 'wrong.invalid' => ['127.0.0.2'],
            '[::1]' => ['::1'],
            default => [],
        };
    }
    public function download(string $url): ?string { return $this->exitRulesetDownload($url); }
}
echo json_encode((new PinnedDownloadBot())->download($argv[2]));
'''
                def download(host, path):
                    result = subprocess.run(['php', '-d', f'curl.cainfo={cert}', '-r', code,
                                             str(ROOT), f'https://{host}:{port}{path}'],
                                            capture_output=True, text=True, timeout=15,
                                            env={**os.environ, 'NO_PROXY': '*', 'no_proxy': '*'})
                    self.assertEqual(0, result.returncode, result.stderr)
                    return json.loads(result.stdout)

                self.assertEqual('ruleset', download('localhost', '/ok'), 'используется проверенный IP')
                self.assertEqual('ruleset', download('localhost', '/redirect'), 'каждый переход закрепляет IP заново')
                self.assertEqual('ruleset', download('[::1]', '/ok'), 'скобки IPv6 сохранены для curl')
                self.assertIsNone(download('localhost', '/private'), 'переход во внутреннюю сеть отвергнут')
                self.assertIsNone(download('wrong.invalid', '/ok'), 'проверка TLS-имени не отключена')
                self.assertIsNone(download('localhost', '/loop'), 'число переходов ограничено')
                self.assertFalse(any(ip == '127.0.0.1' for ip, _ in seen), 'непроверенный адрес не получил запрос')
            finally:
                for server in servers:
                    server.shutdown()
                    server.server_close()


if __name__ == '__main__':
    unittest.main()
