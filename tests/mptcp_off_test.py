"""MPTCP выключен у всех программ на Go в контейнерах бота.

Go 1.24+ по умолчанию слушает TCP как MPTCP, а уязвимость ядра Linux
CVE-2026-98432 через слушающий сокет IPv4 MPTCP даёт удалённый root (XTLS
отозвал Xray 26.10.29 и выпустил 26.10.31 без MPTCP по умолчанию). Форк Xray,
AdGuard Home, Caddy и остальные программы на Go закрываются переменной
GODEBUG=multipathtcp=0 в трёх местах: .env (процессы скриптов запуска),
окружение модулей протоколов без env_file и SetEnv в sshd_config (процессы,
которые бот запускает по SSH: они окружение контейнера не наследуют).
Живая проверка слушателей — набор стенда mptcp_listeners.
"""
from pathlib import Path
import re
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


def env_file():
    values = {}
    for line in (ROOT / '.env').read_text().splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip()
    return values


class MptcpOffTest(unittest.TestCase):
    def test_env_file_disables_mptcp(self):
        self.assertEqual('multipathtcp=0', env_file().get('GODEBUG'))

    def test_every_service_gets_godebug(self):
        compose = yaml.safe_load((ROOT / 'docker-compose.yml').read_text())
        for name, service in compose['services'].items():
            with self.subTest(service=name):
                files = service.get('env_file') or []
                files = [f['path'] if isinstance(f, dict) else f for f in (files if isinstance(files, list) else [files])]
                environment = service.get('environment') or {}
                if isinstance(environment, list):
                    environment = dict(item.split('=', 1) for item in environment if '=' in item)
                own = environment.get('GODEBUG')
                self.assertTrue(own == 'multipathtcp=0' or (own is None and './.env' in files),
                                'GODEBUG=multipathtcp=0 из .env или своего окружения')

    def test_ssh_sessions_disable_mptcp(self):
        config = (ROOT / 'config/sshd_config').read_text()
        self.assertRegex(config, r'(?m)^SetEnv GODEBUG=multipathtcp=0$')
        compose = (ROOT / 'docker-compose.yml').read_text()
        self.assertGreater(compose.count('./config/sshd_config:/etc/ssh/sshd_config'), 10)

    def test_withdrawn_xray_is_not_pinned(self):
        env = env_file()
        for key in ('XRAY_VERSION', 'MASQUE_XRAY_VERSION'):
            with self.subTest(key=key):
                version = tuple(int(x) for x in re.findall(r'\d+', env[key])[:3])
                self.assertGreaterEqual(version, (26, 10, 31), 'v26.10.29 отозван (MPTCP)')
        self.assertNotIn('/v26.10.29/', (ROOT / '.github/workflows/tests.yml').read_text())

    def test_services_survive_docker_daemon_restart(self):
        # 2026-10-31 на тестовом сервере: apt dist-upgrade перезапустил dockerd, и службы с
        # restart: "no" (xray, adguard, naive, wireguard, ...) остались выключены.
        compose = yaml.safe_load((ROOT / 'docker-compose.yml').read_text())
        for name, service in compose['services'].items():
            with self.subTest(service=name):
                self.assertEqual('unless-stopped', service.get('restart'))

    def test_stand_checks_live_listeners(self):
        suite = ROOT / 'tests/integration/fixtures/tests/published-main/mptcp_listeners.py'
        self.assertTrue(suite.is_file())
        self.assertIn("'mptcp_listeners'", (suite.parent / 'run.py').read_text())


if __name__ == '__main__':
    unittest.main()
