#!/usr/bin/env python3
"""Каждый сервис с sshd получает постоянный ключ узла, который проверяет бот."""
import base64
import hashlib
import re
import runpy
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = yaml.safe_load((ROOT / 'docker-compose.yml').read_text())['services']
USE = 'cp -p /hostkey/ssh_host_ed25519_key /hostkey/ssh_host_ed25519_key.pub /etc/ssh/ 2>/dev/null || ssh-keygen -A'
WAIT = ('hostkey_wait=0; while [ -d /hostkey ] && [ ! -s /hostkey/ssh_host_ed25519_key.pub ] && [ "$hostkey_wait" -lt 60 ]; '
        'do sleep 1; hostkey_wait=$((hostkey_wait + 1)); done')
# dnstt держит свой ключ в /config/dnstt: им же пользуются клиенты туннеля.
OWN_KEY = {'dnstt'}


def start_script(service):
    command = service.get('entrypoint') or service.get('command') or []
    name = next((part for part in command if isinstance(part, str) and re.fullmatch(r'/start_\w+\.sh', part)), None)
    return ROOT / 'scripts' / name[1:] if name else None


def with_sshd():
    found = {}
    for name, service in COMPOSE.items():
        script = start_script(service)
        if script and name != 'php' and re.search(r'^\s*/usr/sbin/sshd -D', script.read_text(), re.M):
            found[name] = script
    return found


def issued():
    loop = re.search(r'^for service in ([a-z0-9 ]+); do$', (ROOT / 'scripts/start_php.sh').read_text(), re.M)
    return loop.group(1).split()


class HostKeysTest(unittest.TestCase):
    def test_every_sshd_service_mounts_only_its_own_key_read_only(self):
        services = with_sshd()
        self.assertGreaterEqual(len(services), 17)
        for name, service in COMPOSE.items():
            mounts = [volume for volume in service.get('volumes', []) if isinstance(volume, str) and 'hostkey' in volume]
            with self.subTest(name):
                if name in services and name not in OWN_KEY:
                    self.assertEqual(mounts, [f'./ssh/hosts/{name}:/hostkey:ro'])
                else:
                    self.assertEqual(mounts, [])
        # Каталог со всеми ключами видят только php и service: у них и так клиентский ключ бота.
        whole = sorted(name for name, service in COMPOSE.items() if './ssh:/ssh' in service.get('volumes', []))
        self.assertEqual(whole, ['php', 'service'])

    def test_php_issues_a_key_for_exactly_those_services(self):
        names = issued()
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), set(with_sshd()) - OWN_KEY)
        self.assertTrue(all(re.fullmatch(r'[a-z0-9]+', name) for name in names), 'имя должно пройти проверку в Bot::sshHostKeyTrusted')

    def test_start_scripts_use_the_issued_key_before_sshd_starts(self):
        for name, script in with_sshd().items():
            text = script.read_text()
            with self.subTest(script.name):
                if name in OWN_KEY:
                    self.assertIn('HostKey /dnstt/ssh_host_ed25519_key', text)
                    continue
                self.assertEqual(text.count(USE), 1)
                self.assertLess(text.index(USE), re.search(r'^\s*/usr/sbin/sshd -D', text, re.M).start())
                self.assertEqual(len(re.findall(r'ssh-keygen -A', text)), 1, 'случайный ключ — только запасной путь той же строки')

    def test_service_started_before_php_waits_for_its_key(self):
        script = (ROOT / 'scripts/start_php.sh').read_text()
        self.assertLess(script.index('for service in '), script.index('unitd --control'), 'ключи создаются до готовности php')
        # Не все сервисы ждут готовности php (up, service): ожидание стоит в самом скрипте.
        for name, path in with_sshd().items():
            if name in OWN_KEY:
                continue
            text = path.read_text()
            with self.subTest(path.name):
                self.assertEqual(text.count(WAIT), 1)
                self.assertLess(text.index(WAIT), text.index(USE))

    @unittest.skipUnless(shutil.which('ssh-keygen'), 'нужен ssh-keygen')
    def test_wait_ends_when_the_key_appears_and_is_skipped_without_the_mount(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            wait = WAIT.replace('/hostkey', str(base / 'hostkey')).replace('-lt 60', '-lt 5')
            started = time.monotonic()
            self.assertEqual(subprocess.run(['sh', '-ec', wait]).returncode, 0)
            self.assertLess(time.monotonic() - started, 0.9, 'без подключённого каталога ожидания нет')
            (base / 'hostkey').mkdir()
            late = subprocess.Popen(['sh', '-c', 'sleep 1.3; ssh-keygen -q -t ed25519 -N "" -f ' + str(base / 'hostkey/ssh_host_ed25519_key')])
            started = time.monotonic()
            self.assertEqual(subprocess.run(['sh', '-ec', wait + '; test -s ' + str(base / 'hostkey/ssh_host_ed25519_key')]).returncode, 0)
            self.assertLess(time.monotonic() - started, 4.5)
            late.wait()
            started = time.monotonic()
            self.assertEqual(subprocess.run(['sh', '-ec', wait]).returncode, 0)
            self.assertLess(time.monotonic() - started, 0.9, 'готовый ключ ожидания не требует')

    def test_stand_checks_every_sshd_service_on_live_containers(self):
        cases = ROOT / 'tests/integration/fixtures/tests/published-main'
        registry = runpy.run_path(cases / 'registry.py')
        listed_cases = registry['load_cases'](cases)
        self.assertIn('ssh_host_keys', listed_cases)
        # Полный прогон сверяет фактические результаты с тем же реестром.
        self.assertIn('validate_results', (ROOT / 'tests/integration/suite/run.py').read_text())
        text = (cases / 'ssh_host_keys.py').read_text()
        listed = re.search(r"^SERVICES=\[([^\]]+)\]$", text, re.M).group(1).replace("'", '').split(',')
        self.assertEqual(set(listed), set(with_sshd()))
        for scenario in ('accepted-with-its-own-key', 'impostor-rejected', 'neighbour-key-rejected', 'accepted-again-after-restore',
                         'recreated-service-keeps-its-key', 'restarted-service-keeps-its-key', 'service-without-a-key-waits-for-php',
                         'lost-key-reissued', 'php-restart-keeps-other-keys', 'key-mount-is-read-only', 'impostor-key-is-really-served',
                         'neighbour-key-is-really-served', 'own-key-is-served-again'):
            self.assertIn(scenario, text)
        # Подмена обязана быть настоящей: sshd находится по pid-файлу, а не по имени
        # (busybox pgrep его не находит), и отданный ключ сверяется с подложенным.
        self.assertNotIn('pgrep -', text)
        self.assertIn('/run/sshd.pid', text)

    def test_host_keys_are_not_part_of_the_repository_or_a_backup(self):
        # Правило «/ssh/*» с единственным исключением: ключи узлов в репозиторий не попадают.
        rules = (ROOT / '.gitignore').read_text().splitlines()
        self.assertIn('/ssh/*', rules)
        self.assertEqual([rule for rule in rules if rule.startswith('!') and 'ssh' in rule], ['!/ssh/.gitkeep'])
        self.assertNotIn('ssh/hosts', (ROOT / 'app/BotBackup.php').read_text())

    def issue(self, root):
        """Цикл из start_php.sh с каталогом /ssh, перенесённым во временный."""
        script = (ROOT / 'scripts/start_php.sh').read_text()
        loop = re.search(r'^for service in .*?^done$', script, re.M | re.S).group(0)
        return subprocess.run(['sh', '-ec', loop.replace('/ssh/hosts', str(root))], capture_output=True, text=True)

    @unittest.skipUnless(shutil.which('ssh-keygen'), 'нужен ssh-keygen')
    def test_issued_keys_are_stable_private_and_match_the_bot_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'hosts'
            self.assertEqual(self.issue(root).returncode, 0)
            keys = {name: (root / name / 'ssh_host_ed25519_key') for name in issued()}
            first = {name: key.read_bytes() for name, key in keys.items()}
            self.assertEqual(len(set(first.values())), len(first), 'у каждого сервиса свой ключ')
            for name, key in keys.items():
                with self.subTest(name):
                    self.assertEqual(key.stat().st_mode & 0o777, 0o600)
                    public = key.with_suffix('.pub').read_text().split()
                    self.assertEqual((public[0], public[2]), ('ssh-ed25519', name))
                    # Тот же расчёт, что в Bot::sshHostKeyFingerprint, сверяется с ssh-keygen.
                    blob = base64.b64decode(public[1])
                    self.assertEqual((len(blob), blob[:15]), (51, b'\0\0\0\x0bssh-ed25519'))
                    shown = subprocess.run(['ssh-keygen', '-l', '-E', 'sha1', '-f', str(key) + '.pub'], capture_output=True, text=True).stdout.split()[1]
                    self.assertEqual(shown, 'SHA1:' + base64.b64encode(hashlib.sha1(blob).digest()).decode().rstrip('='))
            # Повторный старт php ключи не меняет: иначе бот перестал бы узнавать работающие сервисы.
            self.assertEqual(self.issue(root).returncode, 0)
            self.assertEqual({name: key.read_bytes() for name, key in keys.items()}, first)
            # Неполная пара (сбой посреди создания) пересоздаётся целиком.
            (root / 'xr/ssh_host_ed25519_key.pub').unlink()
            (root / 'wg/ssh_host_ed25519_key').write_bytes(b'')
            self.assertEqual(self.issue(root).returncode, 0)
            for name in ('xr', 'wg'):
                self.assertNotEqual(keys[name].read_bytes(), first[name])
                self.assertTrue(keys[name].with_suffix('.pub').stat().st_size)
            self.assertEqual(keys['oc'].read_bytes(), first['oc'])

    @unittest.skipUnless(shutil.which('ssh-keygen'), 'нужен ssh-keygen')
    def test_start_script_line_installs_the_issued_key_or_falls_back(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'hostkey').mkdir()
            (base / 'etc').mkdir()
            line = USE.replace('/hostkey/', str(base / 'hostkey') + '/').replace('/etc/ssh/', str(base / 'etc') + '/')
            fallback = line.replace('ssh-keygen -A', 'touch ' + str(base / 'etc/random'))
            self.assertEqual(subprocess.run(['sh', '-ec', fallback]).returncode, 0)
            self.assertEqual(sorted(p.name for p in (base / 'etc').iterdir()), ['random'], 'без выданного ключа — запасной путь')
            (base / 'etc/random').unlink()
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(base / 'hostkey/ssh_host_ed25519_key')], check=True)
            self.assertEqual(subprocess.run(['sh', '-ec', fallback]).returncode, 0)
            self.assertEqual(sorted(p.name for p in (base / 'etc').iterdir()), ['ssh_host_ed25519_key', 'ssh_host_ed25519_key.pub'])
            self.assertEqual((base / 'etc/ssh_host_ed25519_key').stat().st_mode & 0o777, 0o600)
            self.assertEqual((base / 'etc/ssh_host_ed25519_key').read_bytes(), (base / 'hostkey/ssh_host_ed25519_key').read_bytes())


if __name__ == '__main__':
    unittest.main()
