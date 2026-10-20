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
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / 'update').mkdir()
            (repo / 'scripts').mkdir()
            (repo / 'config').mkdir()
            (repo / 'update' / 'update.sh').write_text((ROOT / 'update' / 'update.sh').read_text())
            (repo / 'config' / 'protocol-services.json').write_text('{}')
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
            self.assertEqual(seen.read_text(), expected)


if __name__ == '__main__':
    unittest.main()
