import hashlib
import http.server
import os
from pathlib import Path
import socketserver
import subprocess
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PhpStartupTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='vpnbot-php-start-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name in ('ssh', 'certs', 'bin', 'logs', 'config'):
            (self.root / name).mkdir()
        for name in ('key', 'key.pub'):
            (self.root / 'ssh' / name).write_text('synthetic-existing-key')
        (self.root / 'config/unit.json').write_text('{"listeners":{}}')
        self.status = 200
        self.calls = []
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_PUT(self):
                self.rfile.read(int(self.headers.get('Content-Length', 0)))
                self.do_GET()

            def do_GET(self):
                fixture.calls.append((self.command, self.path))
                self.send_response(fixture.status)
                self.end_headers()
                try:
                    self.wfile.write(b'{}')
                except BrokenPipeError:
                    pass  # curl --fail прекращает чтение ответа с ошибкой.

            def log_message(self, *_):
                pass

        server = socketserver.UnixStreamServer(str(self.root / 'control.sock'), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.executable('unitd', 'exit 0')
        self.executable('php', 'touch "$TEST_ROOT/polling" "$TEST_ROOT/start"')
        self.env = os.environ | {'PATH': str(self.root / 'bin') + ':' + os.environ['PATH'],
                                 'TEST_ROOT': str(self.root), 'IP': '192.0.2.1'}

    def executable(self, name, body):
        path = self.root / 'bin' / name
        path.write_text('#!/bin/sh\n' + body + '\n')
        path.chmod(0o755)

    def run_script(self, name):
        script = (ROOT / 'scripts' / name).read_text()
        for old, new in [('/var/run/control.unit.sock', str(self.root / 'control.sock')),
                         ('/start', str(self.root / 'start')),
                         *[(f'/{n}/', str(self.root / n) + '/') for n in ('ssh', 'certs', 'config', 'logs')]]:
            script = script.replace(old, new)
        return subprocess.run(['sh', '-c', script], env=self.env, capture_output=True, timeout=15)

    def test_restart_preserves_keys_and_certificate(self):
        self.assertEqual(0, self.run_script('start_php.sh').returncode)
        files = [*self.root.joinpath('ssh').glob('key*'), *self.root.joinpath('certs').glob('*')]
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
        self.assertEqual(0, self.run_script('start_php.sh').returncode)
        self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in files})
        self.assertEqual(0, self.run_script('check_file.sh').returncode)
        self.assertIn(('PUT', '/config'), self.calls)
        self.assertIn(('GET', '/status'), self.calls)

    def test_rejected_config_cannot_start_polling_or_keep_stale_marker(self):
        for status in (400, 500):
            with self.subTest(status=status):
                self.status = status
                self.root.joinpath('start').touch()
                self.assertNotEqual(0, self.run_script('start_php.sh').returncode)
                self.assertFalse(self.root.joinpath('polling').exists())
                self.assertFalse(self.root.joinpath('start').exists())

    def test_unit_start_failure_cannot_start_polling(self):
        self.executable('unitd', 'exit 1')
        self.assertNotEqual(0, self.run_script('start_php.sh').returncode)
        self.assertFalse(self.root.joinpath('polling').exists())

    def test_health_requires_live_control_api_and_polling(self):
        self.assertNotEqual(0, self.run_script('check_file.sh').returncode)
        self.root.joinpath('start').touch()
        self.assertEqual(0, self.run_script('check_file.sh').returncode)
        self.status = 503
        self.assertNotEqual(0, self.run_script('check_file.sh').returncode)
        self.root.joinpath('control.sock').unlink()
        self.assertNotEqual(0, self.run_script('check_file.sh').returncode)

    def test_invalid_certificate_is_replaced(self):
        self.root.joinpath('certs/self_public').write_text('invalid')
        self.root.joinpath('certs/self_private').write_text('invalid')
        self.assertEqual(0, self.run_script('start_php.sh').returncode)
        result = subprocess.run(['openssl', 'x509', '-noout', '-in', str(self.root / 'certs/self_public')],
                                capture_output=True)
        self.assertEqual(0, result.returncode)


if __name__ == '__main__':
    unittest.main()
