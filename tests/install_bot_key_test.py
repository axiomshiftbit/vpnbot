#!/usr/bin/env python3
"""init.sh: проверка ключа бота до записи config.php (чистая установка)."""
import os
import http.server
import re
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEY = '1234567890:AAH' + 'x' * 32
CURL = '''#!/bin/sh
printf '%s\\n' "$*" > "$LOG.args"
cat > "$LOG.stdin"
[ "$MODE" = offline ] && exit 6
case "$MODE" in ok) echo '{"ok":true,"result":{"id":1}}' ;; *) echo '{"ok":false,"error_code":401,"description":"Unauthorized"}' ;; esac
'''


@unittest.skipUnless(shutil.which('bash'), 'нужен bash')
class InstallBotKeyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        source = (ROOT / 'scripts/init.sh').read_text()
        functions = re.search(r'^normalize_bot_key\(\) \{.*?^check_bot_key\(\) \{.*?^\}\n', source, re.M | re.S).group()
        (self.tmp / 'bin').mkdir()
        (self.tmp / 'bin/curl').write_text(CURL); (self.tmp / 'bin/curl').chmod(0o755)
        self.script = self.tmp / 'run.sh'
        self.script.write_text('set -euo pipefail\nKEY=$VPNBOT_KEY\n' + functions
                               + 'normalize_bot_key\ncheck_bot_key\nprintf "%s" "$KEY" > "$LOG.key"\n')

    def run_key(self, key, mode, api=None):
        env = {'PATH': f'{self.tmp}/bin:/usr/bin:/bin', 'VPNBOT_KEY': key, 'MODE': mode, 'LOG': str(self.tmp / 'curl')}
        if api is not None:
            env['TELEGRAM_API'] = api
        return subprocess.run(['bash', str(self.script)], env=env, capture_output=True, text=True)

    def test_mirror_host_is_requested_over_https(self):
        # В .env и readme TELEGRAM_API — имя хоста: без схемы curl ушёл бы по http
        # и передал ключ открытым текстом.
        for api, expected in (('api.telegram.org', 'https://api.telegram.org/bot'), ('tg.example.org', 'https://tg.example.org/bot'),
                              ('https://tg.example.org/', 'https://tg.example.org/bot'), (None, 'https://api.telegram.org/bot')):
            with self.subTest(api=api):
                result = self.run_key(KEY, 'ok', api)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertIn(f'url = "{expected}{KEY}/getMe"', (self.tmp / 'curl.stdin').read_text())

    def test_plain_http_api_is_refused_before_any_request(self):
        for api in ('http://tg.example.org', 'tg.example.org/x?y', 'ftp://tg.example.org'):
            with self.subTest(api=api):
                (self.tmp / 'curl.args').unlink(missing_ok=True)
                result = self.run_key(KEY, 'ok', api)
                self.assertEqual(1, result.returncode)
                self.assertFalse((self.tmp / 'curl.args').exists(), 'запрос не отправлялся')
                self.assertNotIn(KEY, result.stdout + result.stderr)

    @unittest.skipUnless(shutil.which('curl') and shutil.which('openssl'), 'нужны curl и OpenSSL')
    def test_real_mirror_uses_tls_and_never_sends_key_over_http(self):
        cert, private = self.tmp / 'cert.pem', self.tmp / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                        'ec_paramgen_curve:P-256', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-out', str(cert), '-keyout', str(private)], check=True, capture_output=True)
        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                received.append(self.path == '/bot' + KEY + '/getMe')
                body = b'{"ok":true,"result":{"id":1}}'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        for tls in (False, True):
            with self.subTest(tls=tls):
                received.clear()
                server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
                if tls:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(cert, private)
                    server.socket = context.wrap_socket(server.socket, server_side=True)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                try:
                    # Настоящий curl вместо подмены setUp; ключ только синтетический.
                    env = {'PATH': os.environ['PATH'], 'VPNBOT_KEY': KEY,
                           'TELEGRAM_API': f'localhost:{server.server_port}',
                           'CURL_CA_BUNDLE': str(cert), 'NO_PROXY': '*', 'no_proxy': '*',
                           'LOG': str(self.tmp / 'real-curl')}
                    result = subprocess.run(['bash', str(self.script)], env=env,
                                            capture_output=True, text=True, timeout=25)
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual(tls, any(received), 'getMe допустим только по TLS')
                    self.assertNotIn(KEY, result.stdout + result.stderr)
                    if tls:
                        self.assertNotIn('WARN', result.stderr, 'доверенный HTTPS действительно прошёл')
                finally:
                    server.shutdown()
                    server.server_close()

    def test_accepted_key_is_normalized_and_never_in_arguments(self):
        result = self.run_key(' ' + KEY + '\r\n', 'ok')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(KEY, (self.tmp / 'curl.key').read_text(), 'пробелы и \\r убраны')
        self.assertNotIn(KEY, (self.tmp / 'curl.args').read_text(), 'ключ не в аргументах curl (виден в ps)')
        self.assertIn(f'bot{KEY}/getMe', (self.tmp / 'curl.stdin').read_text())
        self.assertNotIn(KEY, result.stdout + result.stderr)

    def test_empty_key_file_is_refused_before_the_branch_becomes_the_key(self):
        # VPNBOT_KEY="$(cat /root/.vpnbot-key)" с пустым файлом: без проверки
        # «master» из $1 стал бы ключом, а сообщение — про ключ в аргументе.
        source = (ROOT / 'scripts/init.sh').read_text()
        head = re.search(r'^KEY="\$\{VPNBOT_KEY:-\}"\n.*?^if \[ -z "\$KEY" \]; then\n.*?^fi\n', source, re.M | re.S).group()
        script = self.tmp / 'args.sh'
        script.write_text(head + 'printf "%s|%s" "$KEY" "$BRANCH"\n')
        run = lambda env, *args: subprocess.run(['bash', str(script), *args], env={'PATH': '/usr/bin:/bin', **env}, capture_output=True, text=True)
        empty = run({'VPNBOT_KEY': ''}, 'master')
        self.assertEqual((1, ''), (empty.returncode, empty.stdout))
        self.assertIn('VPNBOT_KEY пуст', empty.stderr)
        self.assertEqual(f'{KEY}|dev', run({'VPNBOT_KEY': KEY}, 'dev').stdout)
        legacy = run({}, KEY, 'dev')
        self.assertEqual(f'{KEY}|dev', legacy.stdout)
        self.assertIn('аргументом', legacy.stderr)
        self.assertIn('usage', run({}).stderr)

    def test_rejected_key_stops_install_without_printing_it(self):
        result = self.run_key(KEY, 'unauthorized')
        self.assertEqual(1, result.returncode)
        self.assertIn('401', result.stderr)
        self.assertFalse((self.tmp / 'curl.key').exists(), 'config.php не пишется')
        self.assertNotIn(KEY, result.stdout + result.stderr)

    def test_unreachable_telegram_only_warns(self):
        result = self.run_key(KEY, 'offline')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('WARN', result.stderr)
        self.assertNotIn(KEY, result.stdout + result.stderr)

    def test_malformed_key_rejected_before_any_request(self):
        for bad in ("123:AA'x;system('id');//" + 'x' * 30, 'AAH' + 'x' * 40, KEY + ':extra', '1234567890:short'):
            with self.subTest(bad=bad[:12]):
                for name in ('curl.args', 'curl.key'): (self.tmp / name).unlink(missing_ok=True)
                result = self.run_key(bad, 'ok')
                self.assertEqual(1, result.returncode)
                self.assertFalse((self.tmp / 'curl.args').exists(), 'запрос не отправлялся')
                self.assertNotIn(bad, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
