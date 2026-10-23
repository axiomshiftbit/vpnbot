"""Цикл update/update.sh передаёт protocol_modules.py apply версию текущего дерева.

Найдено 2026-10-20 на тестовом сервере: цикл после обновления перезапускает сам себя и
наследует окружение процесса, запущенного при установке. С устаревшим VER
apply пересоздавал контейнеры протоколов с прежней версией в имени.
"""
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class UpdateLoopVerTest(unittest.TestCase):
    def test_apply_gets_version_of_current_tree(self):
        self.assertEqual(*self.apply_ver(None))

    def test_override_env_ver_is_kept(self):
        # Стенд задаёт имена контейнеров через VER=audit в override.env.
        self.assertEqual(self.apply_ver('IP=203.0.113.10\nVER=audit\n')[0], 'audit')

    def test_running_php_ver_wins_over_describe(self):
        # git describe удлиняет хеш, если префикс стал неоднозначным (на тестовом сервере —
        # 9 знаков при контейнерах с 7): имя берётся у работающего php.
        self.assertEqual(self.apply_ver(None, container_ver='2.30-773-g03fe93f')[0], '2.30-773-g03fe93f')

    def test_override_env_beats_running_php(self):
        self.assertEqual(self.apply_ver('VER=audit\n', container_ver='2.30-773-g03fe93f')[0], 'audit')

    def apply_ver(self, override, container_ver=None):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / 'update').mkdir()
            (repo / 'scripts').mkdir()
            (repo / 'config').mkdir()
            (repo / 'update' / 'update.sh').write_text((ROOT / 'update' / 'update.sh').read_text())
            (repo / 'config' / 'protocol-services.json').write_text('{}')
            if override is not None:
                (repo / 'override.env').write_text(override)
            seen = repo / 'seen-ver'
            (repo / 'scripts' / 'protocol_modules.py').write_text(
                'import os, pathlib\n'
                f'pathlib.Path({str(seen)!r}).write_text(os.environ.get("VER", ""))\n')
            git = ['git', '-C', str(repo), '-c', 'user.name=t', '-c', 'user.email=t@example.invalid']
            subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            subprocess.run(git + ['add', '-A'], check=True)
            subprocess.run(git + ['commit', '-qm', 'base'], check=True)
            subprocess.run(git + ['tag', 'v9.9'], check=True)
            expected = subprocess.run(['git', '-C', str(repo), 'describe', '--tags', '--always'],
                                      capture_output=True, text=True, check=True).stdout.strip()
            env = dict(os.environ, VER='2.30-709-gstale')
            # Подменный docker: без контейнера ответ пустой, как на чистой машине.
            bin_dir = repo / 'fake-bin'
            bin_dir.mkdir()
            (bin_dir / 'docker').write_text(
                '#!/bin/sh\n'
                f'[ -n {container_ver or ""!r} ] || exit 0\n'
                'case "$1" in\n'
                f'  ps) case "$*" in *working_dir={repo}*service=php*) echo abc123 ;; esac ;;\n'
                f'  inspect) printf "PATH=/usr/bin\\nVER=%s\\nTZ=UTC\\n" {container_ver or ""!r} ;;\n'
                'esac\n')
            (bin_dir / 'docker').chmod(0o755)
            env['PATH'] = f'{bin_dir}:{env["PATH"]}'
            proc = subprocess.Popen(['bash', 'update/update.sh'], cwd=repo, env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.time() + 10
                while time.time() < deadline and not seen.exists():
                    time.sleep(0.1)
            finally:
                proc.kill()
                proc.wait()
            self.assertTrue(seen.exists(), 'apply не запускался')
            return seen.read_text(), expected


if __name__ == '__main__':
    unittest.main()
