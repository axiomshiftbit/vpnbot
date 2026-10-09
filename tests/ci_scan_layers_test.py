#!/usr/bin/env python3
"""Секреты и конфиденциальные данные не попадают в образы и в репозиторий.

Образцы секретов собираются из частей во время теста: в самом файле нет ни
одной строки, которую нашла бы проверка репозитория.
"""
import base64
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import ci_retry  # noqa: E402
import ci_scan_layers as layers  # noqa: E402

# Общеизвестные адреса из тестов, справки и настроек по умолчанию: открытые
# DNS-серверы, учебные значения, идентификаторы OID и границы диапазонов.
# Новый публичный адрес в репозитории — повод убедиться, что это не сервер.
PUBLIC_ADDRESSES = frozenset('''
1.0.0.0 1.0.0.1 1.0.0.3 1.0.0.4 1.1.1.1 1.2.3.0 1.2.3.4 2.2.2.2 3.3.3.3 4.4.4.4 5.6.7.8 8.8.8.8 9.9.9.9 94.140.14.14
11.77.0.0 11.77.0.2 11.77.0.3 11.77.0.4 11.77.0.128 2.5.4.3 2.5.4.11 93.184.216.34 104.16.132.229 142.250.80.46
100.63.255.255 100.128.0.0 172.32.0.1 192.88.99.0 192.169.0.1 198.51.101.8 224.0.0.0 224.0.0.1
'''.split())
REAL_LOOKING = [scheme + '://' + user + ':Zx81kq9Lm2' + '@' + host for scheme, user, host in (
    ('https', 'admin', 'db.internal.net'), ('mysql', 'root', '10.0.0.5.nip.io'), ('https', 'deploy', 'example-corp.net'))]
# Адреса собраны из частей: проверка репозитория не должна найти их в этом файле.
SERVER, OTHER_SERVER = '.'.join(['45', '67', '89', '10']), '.'.join(['51', '15', '0', '1'])
BODY = base64.b64encode(bytes(range(200))).decode()


def pem(kind='OPENSSH PRIVATE KEY', body=BODY):
    dashes = '-' * 5
    return f'{dashes}BEGIN {kind}{dashes}\n{body[:64]}\n{body[64:]}\n{dashes}END {kind}{dashes}\n'.encode()


def layer(files):
    """Слой образа из словаря «путь → содержимое» (None — отметка удаления)."""
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as archive:
        for name, data in files.items():
            if data is None:
                directory, _, base = name.rpartition('/')
                name, data = f'{directory}/.wh.{base}', b''
            info = tarfile.TarInfo(name.lstrip('/'))
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def scan(files, allowed=(), private=None, index=1):
    return layers.scan_layer(io.BytesIO(layer(files)), index, set(allowed), private)


SAMPLES = {
    'private key': pem(),
    'OpenVPN static key': ('-' * 5 + 'BEGIN OpenVPN Static key V1' + '-' * 5 + '\n' + '0123456789abcdef' * 8 + '\n' + '-' * 5 + 'END').encode(),
    'PuTTY private key': ('PuTTY-User-Key' + '-File-3: ssh-ed25519\nEncryption: none\nComment: k\nPublic-Lines: 2\nAAAA\nBBBB\nPrivate-Lines: 1\n' + BODY[:60] + '\n').encode(),
    'age secret key': ('AGE-SECRET-' + 'KEY-1' + 'Q' * 58).encode(),
    'WireGuard key in a config': ('[Interface]\nPrivate' + 'Key = ' + 'a' * 43 + '=\n').encode(),
    'GitHub token': ('gh' + 'p_' + 'A1b2' * 9).encode(),
    'GitLab token': ('gl' + 'pat-' + 'x' * 20).encode(),
    'Telegram bot token': ('123456789' + ':AA' + 'h' * 33).encode(),
    'AWS access key': ('AK' + 'IA' + 'ABCDEFGH23456777').encode(),
    'Slack token': ('xo' + 'xb-' + '1234567890-abcdefghijklmn').encode(),
    'Discord webhook': ('https://discord' + '.com/api/webhooks/123456789012345678/' + 'w' * 60).encode(),
    'Google API key': ('AI' + 'za' + 'B' * 35).encode(),
    'Stripe key': ('sk_' + 'live_' + 'c' * 24).encode(),
    'AI provider key': ('sk-' + 'ant-' + 'd' * 48).encode(),
    'npm token': ('np' + 'm_' + 'e' * 36).encode(),
    'PyPI token': ('pypi-' + 'AgEIcHlwaS5vcmc' + 'f' * 60).encode(),
    'Docker Hub token': ('dckr_' + 'pat_' + 'g' * 27).encode(),
    'SendGrid key': ('SG' + '.' + 'h' * 22 + '.' + 'i' * 43).encode(),
    'Cloudflare token in a config': ('dns_cloudflare' + '_api_token = ' + 'j' * 40).encode(),
    'JSON Web Token': ('ey' + 'J' + 'k' * 20 + '.ey' + 'J' + 'l' * 20 + '.' + 'm' * 30).encode(),
    'URL with a password': ('https://deploy' + ':Zx81kq9Lm2@' + 'git.internal.net/repo.git').encode(),
    'proxy share link': ('vle' + 'ss://0f6f1c1e-1111-2222-3333-444455556666@' + 'vpn.internal.net:443?type=tcp').encode(),
}


class ContentRulesTest(unittest.TestCase):
    def test_every_rule_has_a_sample_and_finds_it(self):
        self.assertEqual(set(SAMPLES), {label for label, _ in layers.CONTENT})
        for label, sample in SAMPLES.items():
            with self.subTest(label):
                found = scan({'/opt/app/data.bin': b'\0\1prefix\n' + sample + b'\nsuffix\0'})
                self.assertEqual([row[0] for row in found], [label])

    def test_findings_never_carry_the_value(self):
        for label, sample in SAMPLES.items():
            found = scan({'/opt/data': sample})
            text = repr(found)
            for piece in re.findall(r'[A-Za-z0-9+/_-]{16,}', sample.decode()):
                with self.subTest(label):
                    self.assertNotIn(piece, text)

    def test_every_private_key_kind_is_found(self):
        for kind in ('PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'DSA PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'OPENSSH PRIVATE KEY',
                     'PGP PRIVATE KEY BLOCK', 'ED25519 PRIVATE KEY'):
            with self.subTest(kind):
                self.assertEqual([row[0] for row in scan({'/x': pem(kind)})], ['private key'])
        escaped = pem().replace(b'\n', b'\\n')
        self.assertEqual([row[0] for row in scan({'/app/settings.json': b'{"key": "' + escaped + b'"}'})], ['private key'])

    def test_key_marker_without_a_body_is_not_a_key(self):
        dashes = '-' * 5
        harmless = [f'{dashes}BEGIN PRIVATE KEY{dashes}\0{dashes}END PRIVATE KEY{dashes}', f'{dashes}BEGIN RSA PRIVATE KEY{dashes}',
                    f'{dashes}BEGIN PUBLIC KEY{dashes}\n{BODY}\n{dashes}END PUBLIC KEY{dashes}',
                    f'{dashes}BEGIN CERTIFICATE{dashes}\n{BODY}\n{dashes}END CERTIFICATE{dashes}']
        for text in harmless:
            with self.subTest(text[:30]):
                self.assertEqual(scan({'/usr/lib/libssl.so.3': text.encode()}), [])

    def test_documentation_placeholders_are_not_secrets(self):
        harmless = ['https://user:password@example.com/', 'socks5://username:passwd@proxy.local:1080', 'http://USER:PASSWORD@host.domain.tld',
                    'postgres://admin:hunter22@localhost.localdomain/db', 'https://${USER}:${TOKEN}@github.com/x/y', 'http://foo:barbazqux@server.test',
                    'git://%s:%s@github.com.invalid', '123456:AAshort', 'ghp_short', 'AKIAEXAMPLE', 'PrivateKey = <ключ>', 'https://example.com:8443/path@x.y',
                    'vless://11111111-2222-4333-8444-555555555555@vpn.example:443', 'trojan://credential@example.test:443']
        for text in harmless:
            with self.subTest(text):
                self.assertEqual(scan({'/usr/share/doc/readme': text.encode()}), [])

    def test_real_looking_credentials_in_a_url_are_found(self):
        for text in REAL_LOOKING:
            with self.subTest(text[:12]):
                self.assertEqual([row[0] for row in scan({'/etc/app.conf': text.encode()})], ['URL with a password'])

    def test_known_test_key_is_allowed_only_by_its_fingerprint(self):
        known = pem('RSA PRIVATE KEY')
        digest = scan({'/usr/lib/libgnutls.so.30': known})[0][2].split('fingerprint ')[1]
        self.assertRegex(digest, r'^[0-9a-f]{64}$')
        self.assertEqual(scan({'/usr/lib/libgnutls.so.30': known}, allowed=[digest]), [])
        # Тот же ключ в другой записи (перенос строк, экранирование) — тот же отпечаток.
        self.assertEqual(scan({'/other/place': known.replace(b'\n', b'\r\n')}, allowed=[digest]), [])
        self.assertEqual(scan({'/other/settings.json': known.replace(b'\n', b'\\n')}, allowed=[digest]), [])
        other = pem('RSA PRIVATE KEY', BODY[::-1])
        found = scan({'/usr/lib/libgnutls.so.30': other}, allowed=[digest])
        self.assertEqual([row[:2] for row in found], [('private key', '/usr/lib/libgnutls.so.30')])
        self.assertNotIn(digest, found[0][2])

    def test_known_keys_file_is_well_formed_and_small(self):
        rows = [line for line in layers.KNOWN.read_text().splitlines() if line and not line.startswith('#')]
        self.assertTrue(all(re.fullmatch(r'[0-9a-f]{64}  \S.*', row) for row in rows), 'строка: <sha256>  <откуда ключ>')
        self.assertEqual(len(rows), len({row.split()[0] for row in rows}))
        self.assertLessEqual(len(rows), 40, 'список исключений не должен разрастаться')


class LayerRulesTest(unittest.TestCase):
    def test_file_removed_by_a_later_layer_is_still_found_in_the_earlier_one(self):
        first = {'/etc/ssh/ssh_host_ed25519_key': pem(), '/usr/bin/tool': b'\x7fELF'}
        second = {'/etc/ssh/ssh_host_ed25519_key': None}
        found = scan(first, index=1) + scan(second, index=2)
        self.assertEqual(sorted(row[0] for row in found), ['SSH host key', 'private key'])
        self.assertTrue(all('layer 1' in row[2] for row in found))

    def test_sensitive_paths(self):
        blocked = {
            '/etc/ssh/ssh_host_rsa_key': 'SSH host key', '/opt/keys/id_ed25519': 'SSH identity', '/opt/keys/id_rsa_deploy': 'SSH identity',
            '/opt/k.ppk': 'SSH identity', '/var/lib/x/.ssh/known_hosts': 'SSH client state', '/etc/dropbear/authorized_keys': 'SSH client state',
            '/srv/.netrc': 'credentials file', '/srv/.docker/config.json': 'credentials file', '/srv/.git-credentials': 'credentials file',
            '/etc/ocserv/ocpasswd': 'password file', '/etc/nginx/htpasswd': 'password file', '/etc/ipsec.secrets': 'credentials file', '/etc/ppp/chap-secrets': 'credentials file',
            '/opt/client.p12': 'key store', '/opt/user.ovpn': 'key store', '/opt/vpn.mobileconfig': 'key store',
            '/srv/.env': 'environment file', '/srv/override.env': 'environment file', '/srv/.env.production': 'environment file',
            '/srv/.bash_history': 'shell or tool history', '/srv/.viminfo': 'shell or tool history',
            '/src/.git/config': 'git metadata', '/var/backup/users.sql': 'database or dump', '/etc/app.conf.bak': 'database or dump',
            '/app/config.php': 'vpnbot runtime data', '/config/pac.json': 'vpnbot runtime data', '/config/wg0.conf': 'vpnbot runtime data',
            '/config/hysteria/users.json': 'vpnbot runtime data', '/certs/cert_private': 'vpnbot runtime data', '/ssh/key': 'vpnbot runtime data',
            '/logs/xray.log': 'vpnbot runtime data', '/tmp/build.log': 'leftover in a home or temporary directory',
            '/root/notes.txt': 'leftover in a home or temporary directory', '/home/ci/x': 'leftover in a home or temporary directory',
        }
        for path, label in blocked.items():
            with self.subTest(path):
                self.assertIn(label, [row[0] for row in scan({path: b'x'})])
        harmless = ['/usr/local/bin/ocpasswd', '/usr/bin/htpasswd', '/usr/sbin/ocpasswd', '/etc/ssh/ssh_host_rsa_key.pub', '/etc/ssh/sshd_config', '/etc/ssl/cert.pem', '/usr/share/doc/env', '/usr/bin/id',
                    '/etc/ssh/moduli', '/usr/lib/python3/site-packages/dotenv/main.py', '/etc/environment', '/usr/share/git-core/templates/description']
        for path in harmless:
            with self.subTest(path):
                self.assertEqual(scan({path: b'x'}), [])

    def test_empty_files_and_directories_are_not_findings(self):
        self.assertEqual(scan({'/root/.ssh/authorized_keys': b'', '/tmp/empty': b''}), [])

    def test_password_hash_in_shadow(self):
        text = b'root:*::0:::::\nbin:!::0:::::\nsshd:!*:19000::::::\nadmin:$6$salt$' + b'h' * 40 + b':19000:0:99999:7:::\nnobody::0:::::\n'
        for path in ('/etc/shadow', '/etc/shadow-', '/etc/gshadow'):
            with self.subTest(path):
                self.assertEqual(scan({path: text}), [('password hash in ' + path, 'admin', 'layer 1')])

    def test_large_file_is_read_in_pieces_and_a_key_on_the_boundary_is_found(self):
        key = pem()
        with patch.object(layers, 'CHUNK', 4096), patch.object(layers, 'OVERLAP', 1024):
            for offset in (0, 3000, 4000, 4096, 8100, 20000):
                with self.subTest(offset=offset):
                    data = b'\0' * offset + key + b'\0' * 9000
                    self.assertEqual([row[0] for row in scan({'/usr/lib/libbig.so': data})], ['private key'])
            self.assertEqual(scan({'/usr/lib/libbig.so': b'\0' * 50000}), [])

    def test_image_config_and_build_history(self):
        token = SAMPLES['GitHub token'].decode()
        config = {'config': {'Env': ['PATH=/bin', 'BOT_TOKEN=' + 'v' * 12, 'API_KEY=', 'TZ=UTC'], 'Labels': {'note': token}},
                  'history': [{'created_by': 'RUN |1 NPM_PASSWORD=hunter2hunter2 /bin/sh -c make'}, {'created_by': 'ARG GH_TOKEN=$GH_TOKEN'},
                              {'created_by': 'RUN curl -H "Authorization: Bearer ' + token + '" https://x'}, {}]}
        found = layers.scan_config(config, set())
        self.assertEqual(sorted(set(row[:2] for row in found)), [('GitHub token', ''), ('secret-like environment variable', 'BOT_TOKEN'),
                                                                 ('secret-like value in the build history', 'NPM_PASSWORD')])
        self.assertNotIn(token, repr(found))
        self.assertNotIn('hunter2', repr(found))
        clean = {'config': {'Env': ['PATH=/bin', 'ENV=/root/.ashrc'], 'Entrypoint': ['/bin/sh']},
                 'history': [{'created_by': 'ARG SINGBOX_SOURCE_SHA256=' + 'a' * 64}, {'created_by': 'RUN apk add openssh'}]}
        self.assertEqual(layers.scan_config(clean, set()), [])


class PrivateMarkersTest(unittest.TestCase):
    def markers(self, text):
        with tempfile.NamedTemporaryFile('w', suffix='.txt') as stream:
            stream.write(text)
            stream.flush()
            return layers.markers(stream.name)

    def test_marker_is_found_by_number_without_its_value(self):
        private = self.markers('# адреса серверов\n203.0.113.77\n\nVpn.Example-Corp.net\n')
        found = scan({'/etc/app/upstream.conf': b'server 203.0.113.77:443;', '/usr/bin/tool': b'\0\0host=vpn.example-corp.NET\0',
                      '/etc/hosts': b'10.0.0.1 local'}, private=private)
        self.assertEqual(sorted(row[:2] for row in found), [('private marker #1', '/etc/app/upstream.conf'), ('private marker #2', '/usr/bin/tool')])
        self.assertNotIn('203.0.113', repr(found))
        self.assertNotIn('example-corp', repr(found).lower())

    def test_marker_matches_whole_values_only(self):
        private = self.markers('203.0.113.77\n')
        for text in (b'1203.0.113.77', b'203.0.113.771', b'203.0.113.7', b'203x0x113x77'):
            with self.subTest(text):
                self.assertEqual(scan({'/etc/x': text}, private=private), [])
        self.assertEqual(len(scan({'/etc/x': b'addr=203.0.113.77.'}, private=private)), 1)

    def test_markers_cover_the_image_config_and_the_repository(self):
        private = self.markers('203.0.113.77\n')
        found = layers.scan_config({'config': {'Env': ['UPSTREAM=203.0.113.77']}, 'history': []}, set(), private)
        self.assertEqual([row[0] for row in found], ['private marker #1'])

    def test_missing_or_empty_marker_file_disables_only_this_rule(self):
        self.assertIsNone(layers.markers('/nonexistent/markers'))
        self.assertIsNone(self.markers('# только комментарий\n\n'))
        self.assertEqual([row[0] for row in scan({'/x': pem()}, private=None)], ['private key'])


class Registry:
    """Подмена реестра: манифесты и слои по адресу."""

    def __init__(self, layers_data, attestation=b'{}', config=None, index=True, fail_first=()):
        self.blobs = {'sha256:config': json.dumps(config or {'config': {}, 'history': []}).encode(), 'sha256:att': attestation}
        self.blobs.update({f'sha256:l{n}': data for n, data in enumerate(layers_data, 1)})
        self.image = {'config': {'digest': 'sha256:config'}, 'layers': [{'digest': f'sha256:l{n}'} for n in range(1, len(layers_data) + 1)]}
        self.index, self.fail_first, self.calls = index, set(fail_first), []

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        if url in self.fail_first:
            self.fail_first.discard(url)
            raise OSError('reset')
        if '/token?' in url:
            return io.BytesIO(b'{"token": "pull-t0ken"}')
        name = url.rsplit('/', 1)[1]
        if '/manifests/' in url:
            if name == 'sha256:top' and self.index:
                return io.BytesIO(json.dumps({'manifests': [
                    {'digest': 'sha256:amd', 'platform': {'architecture': 'amd64', 'os': 'linux'}},
                    {'digest': 'sha256:prov', 'platform': {'architecture': 'unknown', 'os': 'unknown'}}]}).encode())
            if name == 'sha256:prov':
                return io.BytesIO(json.dumps({'layers': [{'digest': 'sha256:att'}]}).encode())
            return io.BytesIO(json.dumps(self.image).encode())
        return io.BytesIO(self.blobs[name])


class ImageTest(unittest.TestCase):
    REF = 'ghcr.io/axiomshiftbit/vpnbot-demo@sha256:top'

    def run_scan(self, registry, **environment):
        with patch.object(layers, 'open_url', registry), patch.object(ci_retry.time, 'sleep'), patch.dict(os.environ, environment, clear=False):
            return layers.scan_image(self.REF, set())

    def test_every_layer_the_config_and_the_attestation_are_inspected(self):
        registry = Registry([layer({'/bin/sh': b'\x7fELF'}), layer({'/opt/app/id_ed25519': pem()}), layer({'/opt/app/id_ed25519': None})],
                            attestation=b'{"buildArgs": {"T": "' + SAMPLES['Telegram bot token'] + b'"}}',
                            config={'config': {'Env': ['DB_PASSWORD=p4ssw0rd-value']}, 'history': []})
        found, count = self.run_scan(registry)
        self.assertEqual(count, 3)
        self.assertEqual(sorted((row[0], row[2].split(',')[0]) for row in found), [
            ('SSH identity', 'layer 2'), ('Telegram bot token', 'attestation'), ('private key', 'layer 2'),
            ('secret-like environment variable', 'image config')])

    def test_clean_image_passes_and_single_manifest_is_accepted(self):
        for index in (True, False):
            with self.subTest(index=index):
                self.assertEqual(self.run_scan(Registry([layer({'/bin/sh': b'\x7fELF'})], index=index)), ([], 1))

    def test_registry_credentials_come_from_the_environment_and_stay_with_the_token_endpoint(self):
        registry = Registry([layer({'/bin/sh': b'x'})])
        self.run_scan(registry, REGISTRY_USERNAME='actor', REGISTRY_PASSWORD='registry-s3cret')
        basic = [url for url, headers in registry.calls if headers.get('Authorization', '').startswith('Basic ')]
        self.assertEqual(basic, ['https://ghcr.io/token?scope=repository:axiomshiftbit/vpnbot-demo:pull&service=ghcr.io'])
        self.assertTrue(all(headers['Authorization'] == 'Bearer pull-t0ken' for url, headers in registry.calls if '/token?' not in url))

    def test_interrupted_layer_is_read_again_and_a_dead_registry_is_an_error(self):
        url = 'https://ghcr.io/v2/axiomshiftbit/vpnbot-demo/blobs/sha256:l1'
        registry = Registry([layer({'/opt/id_rsa': pem()})], fail_first=[url])
        found, _ = self.run_scan(registry)
        self.assertEqual(len(found), 2)
        self.assertEqual(sum(call[0] == url for call in registry.calls), 2)
        truncated = Registry([layer({'/opt/id_rsa': pem() * 50})[:60]])
        with self.assertRaises((EOFError, OSError, tarfile.TarError)):
            self.run_scan(truncated)

    def test_image_must_be_addressed_by_digest_and_have_layers(self):
        with self.assertRaises(ValueError):
            layers.registry('ghcr.io/axiomshiftbit/vpnbot-demo:latest')
        with self.assertRaises(ValueError):
            self.run_scan(Registry([]))

    def test_command_line_exit_codes(self):
        def run(registry):
            out = io.StringIO()
            with patch.object(layers, 'open_url', registry), patch.object(ci_retry.time, 'sleep'), patch('sys.stdout', out), \
                    patch.object(layers, 'MARKERS', Path('/nonexistent')):
                return layers.main([self.REF]), out.getvalue()
        code, text = run(Registry([layer({'/bin/sh': b'x'})]))
        self.assertEqual(code, 0)
        self.assertIn('Layer gate: 0 findings in 1 layers of vpnbot-demo', text)
        self.assertIn('Private markers: not configured', text)
        code, text = run(Registry([layer({'/srv/.env': SAMPLES['Telegram bot token']})]))
        self.assertEqual(code, 1)
        self.assertIn('BLOCK environment file: /srv/.env (layer 1', text)
        self.assertIn('BLOCK Telegram bot token: /srv/.env', text)
        self.assertNotIn(SAMPLES['Telegram bot token'].decode(), text)
        failed = subprocess.run([sys.executable, str(ROOT / 'scripts/ci_scan_layers.py'), 'ghcr.io/axiomshiftbit/vpnbot-demo:latest'],
                                capture_output=True, text=True, env=os.environ | {'VPNBOT_PRIVATE_MARKERS': '/nonexistent'})
        self.assertEqual((failed.returncode, failed.stderr.strip()), (2, 'Layer gate failed: ValueError'))


class RepositoryTest(unittest.TestCase):
    def test_tracked_files_carry_no_secrets_and_no_unknown_public_addresses(self):
        found = layers.scan_tree(ROOT, layers.known(), None, PUBLIC_ADDRESSES)
        self.assertEqual(found, [], 'секрет или адрес настоящего сервера в файле репозитория')

    def test_repository_scan_finds_a_planted_secret_and_address(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(['git', 'init', '-q', directory], check=True)
            (Path(directory) / 'notes.md').write_bytes(f'server {SERVER}, dns 1.1.1.1, version 1.2.3.4.5, lan 192.168.1.1\n'.encode() + SAMPLES['Telegram bot token'])
            (Path(directory) / 'id_ed25519').write_bytes(pem())
            (Path(directory) / 'untracked.txt').write_bytes(SAMPLES['GitHub token'])
            subprocess.run(['git', '-C', directory, 'add', 'notes.md', 'id_ed25519'], check=True)
            found = layers.scan_tree(directory, set(), None, PUBLIC_ADDRESSES)
        self.assertEqual(sorted(row[:2] for row in found), [('SSH identity', 'id_ed25519'), ('Telegram bot token', 'notes.md'),
                                                           ('private key', 'id_ed25519'), ('public IP address ' + SERVER, 'notes.md')])

    def test_public_addresses_are_recognised(self):
        text = f'8.8.8.8 10.0.0.1 172.16.5.4 192.168.0.1 127.0.0.1 169.254.1.1 100.64.0.1 999.1.1.1 v1.2.3.4-rc {SERVER}:443 [{OTHER_SERVER}]'.encode()
        self.assertEqual(layers.public_addresses(text), {'8.8.8.8', SERVER, OTHER_SERVER})
        self.assertEqual(layers.public_addresses(b'\0binary ' + SERVER.encode()), set())


class DockerfileTest(unittest.TestCase):
    DOCKERFILES = sorted((ROOT / 'dockerfile').glob('*.dockerfile'))
    # Готовые образы авторов программ; остальное собирается на Alpine.
    UPSTREAM = ('adguard/adguardhome:', 'tobyxdd/hysteria:', 'ghcr.io/telemt/telemt:')

    def lines(self, path, keyword):
        text = re.sub(r'^\s*#.*\n', '', path.read_text(), flags=re.M).replace('\\\n', ' ')
        return re.findall(rf'^{keyword}\s+(.+)$', text, re.M)

    def test_build_context_admits_only_build_sources(self):
        rules = [line for line in (ROOT / '.dockerignore').read_text().splitlines() if line and not line.startswith('#')]
        self.assertEqual(rules[0], '*')
        for rule in rules[1:]:
            with self.subTest(rule):
                self.assertRegex(rule, r'^(!(scripts|dockerfile)/|\*\*/)')
        tracked = subprocess.run(['git', '-c', 'safe.directory=*', '-C', str(ROOT), 'ls-files', 'dockerfile'], check=True, capture_output=True, text=True).stdout.split()
        present = sorted(str(p.relative_to(ROOT)) for p in (ROOT / 'dockerfile').rglob('*') if p.is_file() and '__pycache__' not in p.parts)
        # Сервисы с context: dockerfile отправляют сборщику весь каталог.
        self.assertEqual(sorted(tracked), present, 'в каталоге dockerfile лежит файл вне репозитория')

    def test_nothing_sensitive_is_copied_into_an_image(self):
        forbidden = re.compile(r'(^|[\s/])(\.env|override\.env|config(/|\s)|ssh(/|\s)|certs?(/|\s)|logs(/|\s)|\.git|id_[a-z0-9]+|\S+\.(pem|key|p12|ovpn))(\s|$)')
        for path in self.DOCKERFILES:
            for keyword in ('COPY', 'ADD'):
                for arguments in self.lines(path, keyword):
                    with self.subTest(path.name, line=arguments):
                        sources = arguments if '--from=' in arguments else re.sub(r'--\S+\s+', '', arguments)
                        self.assertNotRegex(sources.rsplit(' ', 1)[0] + ' ', r'(^|\s)\.{1,2}/?\s', 'копируется весь контекст сборки')
                        if '--from=' not in arguments:
                            self.assertNotRegex(sources, forbidden)
                            self.assertNotRegex(arguments, r'^https?://', 'ADD с адресом минует проверку суммы')

    def test_no_secret_enters_through_arguments_or_environment(self):
        secret = re.compile(r'TOKEN|SECRET|PASSW|PRIVATE|CREDENTIAL|API_?KEY', re.I)
        for path in self.DOCKERFILES:
            for keyword in ('ARG', 'ENV'):
                for arguments in self.lines(path, keyword):
                    with self.subTest(path.name, line=arguments):
                        self.assertNotRegex(arguments.split('=')[0], secret)
        workflow = (ROOT / '.github/workflows/images.yml').read_text()
        for block in re.findall(r'build-args:.*?(?=\n\s{0,10}\S[^\n]*:\s*(?:\n|\|))', workflow, re.S):
            self.assertNotIn('secrets.', block)
        self.assertNotRegex(workflow, r'--build-arg[^\n]*secrets\.')
        self.assertNotRegex(workflow, r'^\s*secrets:\s*\|', 'секреты сборки не используются: появление требует отдельной проверки')

    def test_images_are_built_on_alpine(self):
        for path in self.DOCKERFILES:
            stages = set()
            for arguments in self.lines(path, 'FROM'):
                image, _, stage = arguments.partition(' AS ')
                with self.subTest(path.name, image=image):
                    self.assertTrue(image in stages or image == '$image' or image.startswith('alpine:') or image.endswith('-alpine')
                                    or image.startswith(self.UPSTREAM), 'образ не на Alpine')
                stages.add(stage.strip())
            defaults = re.findall(r'^ARG image=(\S+)$', path.read_text(), re.M)
            self.assertTrue(all(value.startswith('alpine:') for value in defaults))

    def test_layer_gate_runs_for_every_image_before_publication(self):
        workflow = (ROOT / '.github/workflows/images.yml').read_text()
        security = workflow[workflow.index('\n  security:'):workflow.index('\n  native:')]
        self.assertIn('python3 scripts/ci_scan_layers.py "$image"', security)
        self.assertIn('bash scripts/ci_scan_image.sh "$image"', security)
        self.assertNotIn('continue-on-error', security)
        self.assertIn('python3 scripts/ci_scan_layers.py --tree .', workflow)
        self.assertRegex(workflow, r'publish:\n\s+needs: \[[^\]]*\bsecurity\b')


if __name__ == '__main__':
    unittest.main()
