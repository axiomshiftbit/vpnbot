"""Цикл update/update.sh не запускает protocol_modules.py apply каждую секунду.

Найдено 2026-11-14 на SERVER-B: Python раз в секунду вхолостую стоил ~4 с CPU в
минуту. apply обязан запускаться сразу при изменении его входов, не реже раз
в 10 с (сверка контейнеров и копия продлённых сертификатов) и повторяться
через секунду после неуспешного запуска.
"""
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class UpdateLoopApplyRateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        repo = self.repo = Path(self.tmp.name)
        for d in ('update', 'scripts', 'config/protocols/tuic'):
            (repo / d).mkdir(parents=True)
        (repo / 'update' / 'update.sh').write_text((ROOT / 'update' / 'update.sh').read_text())
        (repo / 'config' / 'protocol-services.json').write_text('{}')
        (repo / 'config' / 'protocols' / 'tuic' / 'desired.json').write_text('{}')
        (repo / 'config' / 'nginx.conf').write_text('a')
        # VER из override.env: без git describe и без обращения к docker.
        (repo / 'override.env').write_text('VER=audit\n')
        self.runs = repo / 'runs'
        self.fail = repo / 'fail'
        (repo / 'scripts' / 'protocol_modules.py').write_text(
            'import pathlib, sys\n'
            f'with open({str(self.runs)!r}, "a") as f: f.write("x")\n'
            f'sys.exit(1 if pathlib.Path({str(self.fail)!r}).exists() else 0)\n')
        self.proc = subprocess.Popen(['bash', 'update/update.sh'], cwd=repo,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def tearDown(self):
        self.proc.kill()
        self.proc.wait()
        self.tmp.cleanup()

    def count(self):
        return len(self.runs.read_text()) if self.runs.exists() else 0

    def wait_for(self, n, limit):
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline and self.count() < n:
            time.sleep(0.05)
        return self.count()

    def test_rate(self):
        self.assertEqual(1, self.wait_for(1, 5), 'первый запуск apply')
        time.sleep(3.5)
        self.assertEqual(1, self.count(), 'вхолостую apply не повторяется каждую секунду')
        # Изменение входа применяется на ближайшем проходе цикла (sleep 1).
        for path in ('config/protocol-services.json', 'config/protocols/tuic/desired.json', 'config/nginx.conf'):
            before = self.count()
            (self.repo / path).write_text((self.repo / path).read_text() + ' ')
            with self.subTest(path=path):
                self.assertEqual(before + 1, self.wait_for(before + 1, 2.5))
        # Неуспешный запуск (например, занятый lock) повторяется через секунду.
        self.fail.touch()
        (self.repo / 'config/protocol-services.json').write_text('{"x": 1}')
        before = self.count()
        self.assertGreaterEqual(self.wait_for(before + 3, 4.5), before + 3)
        self.fail.unlink()
        settled = self.wait_for(self.count() + 1, 2.5)
        time.sleep(2.5)
        self.assertEqual(settled, self.count(), 'после успешного запуска повторы прекращаются')
        # Не реже раза в 10 с даже без изменений.
        self.assertEqual(settled + 1, self.wait_for(settled + 1, 9))


if __name__ == '__main__':
    unittest.main()
