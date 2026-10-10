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
                fetches = re.search(r'\b(?:curl|wget)\b[^;&|]*https?://|\bgit (?:clone|fetch)\b|\$\(asset ', run)
                if not fetches:
                    continue
                seen += 1
                with self.subTest(path.name, step=run[:70]):
                    self.assertRegex(run, VERIFIED, 'загрузка без проверки суммы или коммита')
        self.assertGreaterEqual(seen, 10)

    def test_download_is_not_piped_into_an_interpreter_or_unpacker(self):
        for path in DOCKERFILES:
            for run in instructions(path):
                for pipe in re.findall(r'\b(?:curl|wget)\b[^;&]*https?://[^;&]*\|\s*(?:sudo\s+)?(sh|bash|tar|python3?)\b', run):
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
                    'amneziawg-tools/' + env['AWG_TOOLS_VERSION'], 'trusttunnel/' + env['TT_REF']):
            with self.subTest(key):
                self.assertIn(key, keys, 'для закреплённой версии нет строки в dockerfile/sources.sha256')

    def test_dockerfile_defaults_match_the_pins(self):
        env = env_pins()
        for name, key in (('nginx.dockerfile', 'NGINX_VERSION'), ('ocserv.dockerfile', 'OCSERV_VERSION'),
                          ('shadowsocks.dockerfile', 'SS_RUST_VERSION'), ('wireguard.dockerfile', 'AWG_TOOLS_VERSION')):
            defaults = set(re.findall(rf'^ARG {key}=(\S+)$', (ROOT / 'dockerfile' / name).read_text(), re.M))
            with self.subTest(name):
                self.assertEqual(defaults, {env[key]})

    def test_no_ssh_host_keys_are_baked_into_an_image(self):
        # В Debian и Ubuntu установка openssh-server сразу создаёт ключи узла;
        # в Alpine — нет. Ключ в слое публичного образа известен всем.
        for path in DOCKERFILES:
            text = path.read_text()
            debian = re.search(r'^FROM (?:debian|ubuntu)[:\w.-]*\s*$', text, re.M)
            installs = re.search(r'apt-get install[^;]*openssh-server', text.replace('\\\n', ' '))
            with self.subTest(path.name):
                self.assertNotRegex(text, r'^RUN .*ssh-keygen -A', 'ключи узла создаются при старте контейнера, а не при сборке')
                if debian and installs:
                    self.assertIn('rm -f /etc/ssh/ssh_host_*', text)
        scripts = {p.name: p.read_text() for p in (ROOT / 'scripts').glob('start_*.sh')}
        self.assertIn('ssh-keygen -A', scripts['start_tt.sh'])
        self.assertLess(scripts['start_tt.sh'].index('ssh-keygen -A'), scripts['start_tt.sh'].index('sshd'))

    def test_trusttunnel_commit_is_pinned_and_no_installer_is_downloaded(self):
        source = (ROOT / 'dockerfile/trusttunnel.dockerfile').read_text()
        self.assertNotIn('rustup.rs', source)
        self.assertRegex(source, r'(?m)^FROM rust:\$\{RUST_VERSION\}-alpine AS build$')
        self.assertRegex(re.search(r'^ARG RUST_VERSION=(\S+)$', source, re.M).group(1), r'^\d+\.\d+\.\d+$')
        # Тег сверяется с записью в sources.sha256, полный коммит — сам с собой.
        lookup = """pinned=$(awk -v key="trusttunnel/${TT_REF}" '$2 == key {print $1}' %s)"""
        compare = 'test "%s" = "${pinned:-$TT_REF}"'
        self.assertIn(lookup % '/sources.sha256', source)
        self.assertIn(compare % '$(git rev-parse HEAD)', source)
        command = lookup % MANIFEST + ' && ' + compare % '$HEAD'
        pinned = next(line.split()[0] for line in MANIFEST.read_text().splitlines() if line.endswith('  trusttunnel/' + env_pins()['TT_REF']))
        other = 'f' * 40
        for ref, head, expected in ((env_pins()['TT_REF'], pinned, 0), (env_pins()['TT_REF'], other, 1), ('v9.9.9', other, 1), ('v9.9.9', 'v9.9.9', 0),
                                    (other, other, 0), (other, pinned, 1)):
            with self.subTest(ref=ref, head=head[:7]):
                done = subprocess.run(['sh', '-c', command], env={'TT_REF': ref, 'HEAD': head, 'PATH': '/usr/bin:/bin'})
                self.assertEqual(done.returncode, expected)

    def test_trusttunnel_endpoint_runs_with_mimalloc_and_keeps_its_process_name(self):
        source = (ROOT / 'dockerfile/trusttunnel.dockerfile').read_text()
        self.assertRegex(source, r'apk add --no-cache [^\n]*\bmimalloc2\b')
        self.assertIn('COPY --from=build /src/target/release/trusttunnel_endpoint /usr/local/libexec/', source)
        wrapper = re.search(r"printf '%s\\n' '(#!/bin/sh)' '([^']+)'", source)
        self.assertEqual(wrapper.group(2), 'LD_PRELOAD=/usr/lib/libmimalloc-secure.so.2 exec /usr/local/libexec/trusttunnel_endpoint "$@"')
        # Та же обёртка на подставной программе: аргументы доходят как есть,
        # переменная видна только ей, имя процесса — по нему бот ищет endpoint.
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'libexec').mkdir()
            real = base / 'libexec/trusttunnel_endpoint'
            real.write_text('#!/bin/sh\nprintf "%s|" "$LD_PRELOAD" "$@"; cat /proc/$$/comm\n')
            real.chmod(0o755)
            script = base / 'trusttunnel_endpoint'
            script.write_text(wrapper.group(1) + '\n' + wrapper.group(2).replace('LD_PRELOAD=/usr/lib/', 'LD_PRELOAD=/nonexistent/')
                              .replace('/usr/local/libexec/', str(base) + '/libexec/') + '\n')
            script.chmod(0o755)
            done = subprocess.run([str(script), 'vpn.toml', 'two words'], capture_output=True, text=True)
            self.assertEqual(done.stdout.strip(), '/nonexistent/libmimalloc-secure.so.2|vpn.toml|two words|trusttunnel_end')

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
