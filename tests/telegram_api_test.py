"""Адрес Bot API одинаково проверяют PHP (TelegramApi::normalize), update.sh и init.sh.

Токен бота подставляется в путь каждого запроса: адрес, который принял бы
bash, но отверг PHP (или наоборот), означал бы, что ход обновления уходит не
туда, куда ходит сам бот.
"""
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    'api.telegram.org', 'https://api.telegram.org/', 'tg-audit:8443', 'https://relay.example.com/0123456789abcdef',
    'relay.example.com:8443/a/b_c.d~e-f//', '  https://relay.example.com/p  ', 'https://[2001:db8::1]:8443/x', 'https://203.0.113.7/p',
    'https://x.y:65535', 'http://x.y', 'ftp://x.y', 'HTTPS://x.y', 'https://user@x.y', 'https://x.y/a?b', 'https://x.y/#f',
    'https://x.y/a b', 'https://x.y/../a', 'https://x.y/a/..', 'https://x.y/./a', 'https://x.y/a%2e', 'https://x.y:0',
    'https://x.y:65536', 'https://x.y:08443', 'https://-x.y', 'https://x_y.z', 'https://x.y/a;b', 'https://x.y/a"b',
    "https://x.y/a'b", 'https://x.y/a$b', 'https://x.y/a\\b', 'https://x.y/' + 'a' * 65, 'https://x.y' + '/a' * 9,
    'https://' + 'a' * 250 + '.y', '', ' ', 'https://x.y/a`id`', 'https://x.y/$(id)',
]
PHP = r'''
require $argv[1] . '/app/TelegramApi.php';
$out = [];
foreach (json_decode(stream_get_contents(STDIN), true) as $case) $out[] = TelegramApi::normalize($case);
echo json_encode($out);
'''


def update_functions():
    source = (ROOT / 'update/update.sh').read_text()
    return re.search(r'^telegram_api_base\(\) \{.*?^\}\n.*?^telegram_api_current\(\) \{.*?^\}\n', source, re.M | re.S).group()


@unittest.skipUnless(shutil.which('php'), 'нужен php')
class TelegramApiFormatTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_php_and_update_sh_accept_the_same_addresses(self):
        php = json.loads(subprocess.run(['php', '-r', PHP, str(ROOT)], input=json.dumps(CASES), capture_output=True, text=True, check=True).stdout)
        functions = update_functions()
        for case, expected in zip(CASES, php):
            with self.subTest(case=case):
                result = subprocess.run(['bash', '-c', functions + 'telegram_api_base "$1"', 'test', case],
                                        capture_output=True, text=True, env={'PATH': '/usr/bin:/bin'})
                got = result.stdout if result.returncode == 0 else None
                # PHP приводит имя хоста к нижнему регистру, bash оставляет как есть.
                self.assertEqual(expected, got.lower() if got and expected and got.lower() == expected else got)

    def test_update_uses_the_address_handed_over_by_the_bot(self):
        functions = update_functions()
        (self.tmp / 'update').mkdir()
        run = lambda env_api: subprocess.run(['bash', '-c', f'pwd={self.tmp}; TELEGRAM_API={env_api}; ' + functions + 'telegram_api_current'],
                                             capture_output=True, text=True, env={'PATH': '/usr/bin:/bin'}).stdout
        self.assertEqual('https://api.telegram.org', run('api.telegram.org'))
        self.assertEqual('https://mirror.example.org', run('mirror.example.org'))
        (self.tmp / 'update/api').write_text('https://relay.example.com/0123456789abcdef\n')
        self.assertEqual('https://relay.example.com/0123456789abcdef', run('mirror.example.org'))
        (self.tmp / 'update/api').write_text('http://evil.example/x\n')
        self.assertEqual('https://mirror.example.org', run('mirror.example.org'))
        (self.tmp / 'update/api').write_text('')
        self.assertEqual('https://api.telegram.org', run('"http://bad"'))

    def test_update_request_url_and_key_stay_off_argv(self):
        source = (ROOT / 'update/update.sh').read_text()
        self.assertIn('printf \'url = "%s/bot%s/%s"\\n\' "$_api" "$_key" "$method"', source)
        self.assertIn('_api=$(telegram_api_current)', source.split('_key=$(cat "$pwd/update/key")', 1)[1].split('\n', 2)[1])
        self.assertIn(': > "$pwd/update/api"', source)
        self.assertIn('"$pwd/update/api"', source.splitlines()[4])

    def test_bot_hands_its_address_to_update(self):
        source = (ROOT / 'app/bot.php').read_text()
        queue = source[source.index('public function queueUpdateCommand'):]
        queue = queue[:queue.index('\n    }\n')]
        self.assertIn("'api' => $this->telegramApiBase()", queue)
        self.assertLess(queue.index("'api' =>"), queue.index("writePrivateKey('/update/pipe'"))

    # Стенд гоняет тесты на копии git archive без .git — там проверять нечего.
    @unittest.skipUnless((ROOT / '.git').exists() and shutil.which('git'), 'нужен git checkout')
    def test_runtime_files_are_ignored_by_git_clean(self):
        if not (ROOT/'.git').exists():
            self.skipTest('copy without .git (stand): .gitignore is checked in the repository jobs')
        for path in ('config/telegram_api', 'config/telegram_api.0123.tmp', 'update/api', 'logs/nginx_tgrelay_access', 'config/tg_relay.lock'):
            with self.subTest(path=path):
                # The CI container runs as root over a checkout owned by the
                # runner user: without safe.directory git refuses (exit 128).
                result = subprocess.run(['git', '-c', 'safe.directory=*', 'check-ignore', '-q', path], cwd=ROOT)
                self.assertEqual(0, result.returncode, f'{path} должен быть в .gitignore: update.sh делает git clean -fd')


if __name__ == '__main__':
    unittest.main()
