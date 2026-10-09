#!/usr/bin/env python3
"""Каждая загрузка при сборке образа проверяется до использования."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILES = sorted((ROOT / 'dockerfile').glob('*.dockerfile'))
MANIFEST = ROOT / 'dockerfile/sources.sha256'
# Установщик rustup не закреплён суммой: он лишь выбирает закреплённую версию
# компилятора на сборочном этапе, в итоговый образ не попадает.
ALLOWED = {('trusttunnel.dockerfile', 'https://sh.rustup.rs')}
VERIFIED = re.compile(r'sha256sum\s+(?:-c|--check)|go-source\.sh|git checkout -q "\$\{?\w+\}?"|rev-parse HEAD\)" = ')


def instructions(path):
    """RUN-инструкции целиком: строки с продолжением склеены, комментарии убраны."""
    text = re.sub(r'^\s*#.*\n', '', path.read_text(), flags=re.M)
    return [chunk for chunk in re.split(r'\n(?=[A-Z]+ )', text.replace('\\\n', ' ')) if chunk.startswith('RUN ')]


def env_pins():
    return dict(line.split('=', 1) for line in (ROOT / '.env').read_text().splitlines() if re.match(r'^[A-Z0-9_]+=', line))


class ImageSourcesTest(unittest.TestCase):
    def test_every_download_is_verified_in_the_same_step(self):
        seen = 0
        for path in DOCKERFILES:
            for run in instructions(path):
                urls = re.findall(r'https?://[^\s"\')]+', run)
                fetches = re.search(r'\b(?:curl|wget)\b[^;&|]*https?://|\bgit clone\b|\$\(asset ', run)
                if not fetches:
                    continue
                seen += 1
                if any((path.name, url) in ALLOWED for url in urls):
                    continue
                with self.subTest(path.name, step=run[:70]):
                    self.assertRegex(run, VERIFIED, 'загрузка без проверки суммы или коммита')
        self.assertGreaterEqual(seen, 10)

    def test_download_is_not_piped_into_an_interpreter_or_unpacker(self):
        for path in DOCKERFILES:
            for run in instructions(path):
                for pipe in re.findall(r'\b(?:curl|wget)\b[^;&]*https?://[^;&]*\|\s*(?:sudo\s+)?(sh|bash|tar|python3?)\b', run):
                    if any(name == path.name for name, _ in ALLOWED) and 'sh.rustup.rs' in run:
                        continue
                    with self.subTest(path.name):
                        self.fail('загрузка сразу передаётся в ' + pipe)

    def test_manifest_covers_the_pinned_versions(self):
        rows = [line.split() for line in MANIFEST.read_text().splitlines() if line and not line.startswith('#')]
        self.assertTrue(all(len(row) == 2 and re.fullmatch(r'[0-9a-f]{64}|[0-9a-f]{40}', row[0]) for row in rows))
        keys = [row[1] for row in rows]
        self.assertEqual(len(keys), len(set(keys)))
        env = env_pins()
        ocserv = re.search(r'^OCSERV_VERSION=(\S+)$', (ROOT / '.env').read_text(), re.M).group(1)
        for key in ('nginx/' + env['NGINX_VERSION'], 'ocserv/' + ocserv, 'shadowsocks-rust/' + env['SS_RUST_VERSION'],
                    'amneziawg-tools/' + env['AWG_TOOLS_VERSION']):
            with self.subTest(key):
                self.assertIn(key, keys, 'для закреплённой версии нет строки в dockerfile/sources.sha256')

    def test_dockerfile_defaults_match_the_pins(self):
        env = env_pins()
        for name, key in (('nginx.dockerfile', 'NGINX_VERSION'), ('ocserv.dockerfile', 'OCSERV_VERSION'),
                          ('shadowsocks.dockerfile', 'SS_RUST_VERSION'), ('wireguard.dockerfile', 'AWG_TOOLS_VERSION')):
            defaults = set(re.findall(rf'^ARG {key}=(\S+)$', (ROOT / 'dockerfile' / name).read_text(), re.M))
            with self.subTest(name):
                self.assertEqual(defaults, {env[key]})

    def check_snippet(self, key, content):
        """Та же команда, что в Dockerfile, на подставном файле."""
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'file'
            target.write_bytes(content)
            command = "awk -v key=\"%s\" '$2 == key {print $1 \"  %s\"}' %s | sha256sum -c -" % (key, target, MANIFEST)
            return subprocess.run(['sh', '-c', command], capture_output=True, text=True).returncode

    def test_verification_fails_closed(self):
        env = env_pins()
        self.assertNotEqual(self.check_snippet('nginx/' + env['NGINX_VERSION'], b'tampered'), 0)
        self.assertNotEqual(self.check_snippet('nginx/0.0.0', b'anything'), 0)
        self.assertNotEqual(self.check_snippet('', b'anything'), 0)

    def test_verification_accepts_the_reviewed_content(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            manifest, target = Path(directory) / 'sums', Path(directory) / 'file'
            target.write_bytes(b'reviewed')
            manifest.write_text(hashlib.sha256(b'reviewed').hexdigest() + '  demo/1.0\n')
            command = "awk -v key=\"demo/1.0\" '$2 == key {print $1 \"  %s\"}' %s | sha256sum -c -" % (target, manifest)
            self.assertEqual(subprocess.run(['sh', '-c', command], capture_output=True).returncode, 0)
            target.write_bytes(b'changed')
            self.assertNotEqual(subprocess.run(['sh', '-c', command], capture_output=True).returncode, 0)

    def test_dockerfiles_use_the_same_verification_command(self):
        for name, key, target in (('nginx.dockerfile', 'nginx/${NGINX_VERSION}', 'nginx.tar.gz'),
                                  ('ocserv.dockerfile', 'ocserv/${OCSERV_VERSION}', '/tmp/ocserv.tar.gz'),
                                  ('shadowsocks.dockerfile', 'shadowsocks-rust/${SS_RUST_VERSION}', 'shadowsocks-rust.tar.xz')):
            expected = "awk -v key=\"%s\" '$2 == key {print $1 \"  %s\"}' /sources.sha256 | sha256sum -c -" % (key, target)
            with self.subTest(name):
                source = (ROOT / 'dockerfile' / name).read_text()
                self.assertIn(expected, source)
                self.assertRegex(source, r'COPY (?:dockerfile/)?sources\.sha256 /sources\.sha256')


if __name__ == '__main__':
    unittest.main()
