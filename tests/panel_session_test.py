import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from urllib.parse import urlencode


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('php'), 'нужен PHP')
class PanelSessionTest(unittest.TestCase):
    def test_simultaneous_sessions_revoke_independently(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            router = root / 'router.php'
            router.write_text(r'''<?php
require getenv('VPNBOT_TEST_SOURCE') . '/app/bot.php';
require getenv('VPNBOT_TEST_SOURCE') . '/app/panel/Panel.php';
class SessionFixtureBot extends Bot {
    public function __construct() {}
    public function getHashBot($notset = false) { return 'fixture'; }
    public function getPacConf() { return ['panelpswd'=>file_get_contents(__DIR__.'/hash')]; }
}
if (!is_file(__DIR__.'/hash')) file_put_contents(__DIR__.'/hash', password_hash('fixture-password', PASSWORD_BCRYPT, ['cost'=>4]));
$panel = new Panel(new SessionFixtureBot(), ['key'=>'synthetic-fixture-key', 'admin'=>[111,222]], new PanelStore(__DIR__.'/store'));
$panel->route($_SERVER['REQUEST_URI']);
''')
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            with (root / 'server.log').open('w+') as log:
                server = subprocess.Popen(['php', '-S', f'127.0.0.1:{port}', str(router)],
                    env={**os.environ, 'VPNBOT_TEST_SOURCE': str(ROOT), 'PANEL_HOSTS': '', 'PANEL_TRUSTED': ''},
                    stdout=log, stderr=log)
                try:
                    for _ in range(100):
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                                break
                        except OSError:
                            if server.poll() is not None:
                                log.seek(0)
                                self.fail(log.read())
                            time.sleep(.02)

                    def request(action, cookie='', fields=None):
                        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                        try:
                            headers = {'Cookie': cookie}
                            if fields is not None:
                                headers.update({'X-Panel': '1', 'Content-Type': 'application/x-www-form-urlencoded'})
                            connection.request('GET' if fields is None else 'POST', '/panelfixture/' + action,
                                               body=None if fields is None else urlencode(fields), headers=headers)
                            response = connection.getresponse()
                            body = response.read()
                            return response.status, response.getheader('Set-Cookie', '').split(';')[0], body
                        finally:
                            connection.close()

                    def login():
                        status, cookie, body = request('login', fields={'password': 'fixture-password', 'admin':111})
                        self.assertEqual(200, status, body)
                        self.assertTrue(json.loads(body)['ok'])
                        return cookie

                    # Два входа именно в одну секунду, чтобы проверить совпадение
                    # срока сессии. Не ждём границы: повтор нужен лишь при её пересечении.
                    for _ in range(10):
                        first, second = login(), login()
                        if first.split('.')[0] == second.split('.')[0]:
                            break
                    else:
                        self.fail('Не удалось получить две сессии с одинаковым сроком')
                    self.assertEqual(200, request('state', first)[0])
                    self.assertEqual(200, request('state', second)[0])
                    self.assertEqual(200, request('logout', first, {})[0])
                    self.assertEqual(401, request('state', first)[0], 'Копия отозванной сессии ещё действует')
                    self.assertEqual(200, request('state', second)[0], 'Выход завершил другую сессию')
                    self.assertNotEqual(first, second, 'Два входа получили одну и ту же сессию')
                    self.assertEqual(200, request('state', login())[0], 'Повторный вход выдал отозванную сессию')
                    parts = second.split('.')
                    parts[1] = '222'
                    self.assertEqual(401, request('state', '.'.join(parts))[0], 'Можно подменить администратора')
                    parts = second.split('.')
                    parts[2] = '0' * 32
                    self.assertEqual(401, request('state', '.'.join(parts))[0], 'Можно подменить идентификатор сессии')
                finally:
                    server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait()


if __name__ == '__main__':
    unittest.main()
