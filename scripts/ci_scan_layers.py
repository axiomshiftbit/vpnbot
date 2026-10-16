#!/usr/bin/env python3
"""Секреты и конфиденциальные данные в слоях образа и в файлах репозитория.

Образ скачивается из реестра так, как его видит посторонний, и разбирается по
слоям: файл, удалённый более поздним слоем, в раннем всё равно остаётся.
Проверяются закрытые ключи, токены, ссылки с паролем, файлы с учётными данными
и настройками бота, остатки сборки в домашних и временных каталогах, пароли в
/etc/shadow, переменные окружения, история сборки и аттестации образа.

Адреса боевых серверов, домены и прочие приметы конкретной установки не
хранятся ни в репозитории, ни в секретах GitHub: их список лежит только на
своём runner в файле $VPNBOT_PRIVATE_MARKERS (по одной строке) и ищется во
всех слоях. Прогоны на серверах GitHub идут без этого правила.

Значения не печатаются — только вид находки, путь и отпечаток. Тестовые ключи
из состава чужих пакетов перечислены по отпечаткам в ci_known_test_keys.txt:
неизвестный ключ по тому же пути блокирует.

  ci_scan_layers.py ghcr.io/…@sha256:… [ещё образы]
  ci_scan_layers.py --tree КАТАЛОГ      файлы репозитория
"""
import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import urllib.request

from ci_retry import retrying

KNOWN = Path(__file__).with_name('ci_known_test_keys.txt')
MARKERS = Path(os.environ.get('VPNBOT_PRIVATE_MARKERS') or '/etc/vpnbot-ci-private-markers')
# Большие файлы читаются частями с перекрытием: находка на стыке не теряется.
CHUNK, OVERLAP = 32 * 1024 * 1024, 256 * 1024

# Тело ключа обязательно: одна строка-маркер встречается в любой библиотеке TLS.
CONTENT = [
    ('private key', rb'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\\rn]+(?:[A-Za-z-]+: [^\n]+\s+)*[A-Za-z0-9+/=\s\\]{100,}?-----END'),
    ('OpenVPN static key', rb'-----BEGIN OpenVPN (?:Static key V1|tls-crypt-v2 (?:server|client) key)-----\s+[0-9A-Za-z+/=\s]{100,}?-----END'),
    ('PuTTY private key', rb'PuTTY-User-Key-File-\d: [^\n]+\n(?:[^\n]+\n){2,}?Private-Lines: \d+\s+[A-Za-z0-9+/=\s]{40,}'),
    ('age secret key', rb'AGE-SECRET-KEY-1[0-9A-Z]{58}'),
    ('WireGuard key in a config', rb'(?m:^[ \t]*(?:PrivateKey|PresharedKey)[ \t]*=[ \t]*[A-Za-z0-9+/]{43}=)'),
    ('GitHub token', rb'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}'),
    ('GitLab token', rb'\bgl(?:pat|dt|rt|cbt|ptt)-[A-Za-z0-9_-]{20,}'),
    ('Telegram bot token', rb'(?<![0-9A-Za-z_-])\d{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])'),
    ('AWS access key', rb'\b(?:AKIA|ASIA)[A-Z2-7]{16}\b'),
    ('Slack token', rb'\bxox[abeoprs]-[A-Za-z0-9-]{20,}|hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}'),
    ('Discord webhook', rb'discord(?:app)?\.com/api/webhooks/\d{15,}/[A-Za-z0-9_-]{50,}'),
    ('Google API key', rb'\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])'),
    ('Stripe key', rb'\b[sr]k_live_[0-9a-zA-Z]{24,}'),
    ('AI provider key', rb'\bsk-(?:ant|proj|or)-[A-Za-z0-9_-]{40,}'),
    ('npm token', rb'\bnpm_[A-Za-z0-9]{36}\b'),
    ('PyPI token', rb'\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}'),
    ('Docker Hub token', rb'\bdckr_pat_[A-Za-z0-9_-]{27,}'),
    ('SendGrid key', rb'\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'),
    ('Cloudflare token in a config', rb'(?im:^[ \t]*(?:dns_cloudflare_api_token|CF_(?:API_)?TOKEN|CLOUDFLARE_API_TOKEN)[ \t]*[=:][ \t]*["\']?[A-Za-z0-9_-]{35,})'),
    ('JSON Web Token', rb'\beyJ[A-Za-z0-9_-]{16,}\.eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{20,}'),
    ('URL with a password', rb'\b[a-z][a-z0-9+.-]{1,15}://[A-Za-z0-9._%+-]{1,64}:[A-Za-z0-9._%+!*-]{6,}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+'),
    ('proxy share link', rb'\b(?:vless|trojan|hysteria2|hy2|tuic)://[A-Za-z0-9._%:-]{8,}@[A-Za-z0-9.-]+:\d{2,5}'),
]
PATTERN = re.compile(b'|'.join(b'(?P<r%d>%s)' % (index, body) for index, (_, body) in enumerate(CONTENT)))

PATHS = [(label, re.compile(pattern)) for label, pattern in [
    ('SSH host key', r'/etc/ssh/ssh_host_[a-z0-9_]+_key$'),
    ('SSH identity', r'/(?:id_(?:rsa|dsa|ecdsa|ed25519)(?:_[\w.-]+)?|[^/]+\.ppk)$(?<!\.pub)'),
    ('SSH client state', r'/\.ssh/[^/]+$|/authorized_keys2?$|/ssh/key(?:\.pub)?$'),
    ('credentials file', r'/(?:\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.docker/config\.json|\.aws/credentials|\.kube/config|\.config/gh/hosts\.yml|\.cargo/credentials(?:\.toml)?|\.htpasswd|ipsec\.secrets|chap-secrets)$'),
    # Одноимённые программы лежат в …/bin/ и файлами паролей не являются.
    ('password file', r'(?<!bin)/(?:htpasswd|ocpasswd|passwd\.txt)$'),
    ('key store', r'\.(?:p12|pfx|jks|keystore|kdbx|ovpn|mobileconfig)$'),
    ('environment file', r'/(?:\.env(?:\.[\w-]+)?|override\.env|secrets\.env)$'),
    ('shell or tool history', r'/\.(?:[a-z]+_history|viminfo|lesshst|wget-hsts)$'),
    ('git metadata', r'/\.git/(?:config|HEAD|packed-refs)$'),
    ('database or dump', r'\.(?:sqlite3?|sql|sql\.gz|dump|bak|backup|old|orig|swp)$'),
    ('vpnbot runtime data', r'^/(?:app/config\.php|config/[^/]+\.(?:json|conf|yaml|yml|toml|key)|config/(?:hysteria|trusttunnel|telemt|mieru|masque|protocols)/.+|certs/.+|ssh/.+|logs/.+|update/.+)$'),
    ('leftover in a home or temporary directory', r'^/(?:root|home/[^/]+|tmp|var/tmp)/.+$'),
]]
# .env в репозитории — закреплённые версии, а не секреты; каталоги и дампы там свои.
TREE_PATHS = {'SSH host key', 'SSH identity', 'credentials file', 'key store', 'shell or tool history'}
SECRET_NAME = re.compile(r'TOKEN|SECRET|PASSW|PRIVATE|CREDENTIAL|API_?KEY|AUTH', re.I)
# Заполнители из документации: «scheme://user:password@host» секретом не является.
PLACEHOLDER = re.compile(
    rb'://(?:(?i:user(?:name)?|login|foo)|[A-Z_]+|%s|\$\{?\w+\}?)[:@]'
    rb'|:(?:(?i:pass(?:word|wd)?|secret|token|pwd)|[A-Z_]+|%s|\$\{?\w+\}?|x+|\*+)@'
    rb'|@(?:[\w.-]*\.)?(?:example(?:\.[a-z]+)?|localhost(?:\.localdomain)?|[\w-]+\.(?:test|invalid|local|tld)|host|server|proxy)(?![\w-])')


def known():
    return {line.split()[0] for line in KNOWN.read_text().splitlines() if line and not line.startswith('#')}


def markers(path=None):
    """Приметы конкретной установки: адреса серверов, домены, учётные записи."""
    path = Path(path or MARKERS)
    if not path.is_file():
        return None
    values = [line.strip() for line in path.read_text().splitlines() if line.strip() and not line.startswith('#')]
    if not values:
        return None
    parts = '|'.join('(?P<m%d>%s)' % (index, re.escape(value)) for index, value in enumerate(values))
    return re.compile(('(?<![A-Za-z0-9])(?:' + parts + ')(?![A-Za-z0-9])').encode(), re.I)


def fingerprint(value):
    return hashlib.sha256(re.sub(rb'\\[rn]|[\s\\]', b'', value)).hexdigest()


def scan_bytes(path, data, where, allowed, private=None):
    found = []
    for match in PATTERN.finditer(data):
        label = CONTENT[int(match.lastgroup[1:])][0]
        value = match.group()
        if label in ('URL with a password', 'proxy share link') and PLACEHOLDER.search(value):
            continue
        digest = fingerprint(value)
        if digest not in allowed:
            found.append((label, path, f'{where}, fingerprint {digest}'))
    if private:
        for match in private.finditer(data):
            found.append((f'private marker #{int(match.lastgroup[1:]) + 1}', path, where))
    return found


def pieces(stream):
    tail = b''
    while block := stream.read(CHUNK):
        yield tail + block
        tail = block[-OVERLAP:]


def public_addresses(data):
    """Публичные IPv4 в текстовом файле: адрес настоящего сервера в образе не нужен."""
    if b'\0' in data[:8192]:
        return set()
    found = set()
    for raw in re.findall(rb'(?<![0-9A-Za-z.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Za-z]|\.\d)', data):
        try:
            address = ipaddress.ip_address(raw.decode())
        except ValueError:
            continue
        if address.is_global:
            found.add(str(address))
    return found


def shadow(path, data, where):
    found = []
    for line in data.decode(errors='replace').splitlines():
        user, _, rest = line.partition(':')
        password = rest.split(':')[0]
        if password and password[0] not in '*!':
            found.append(('password hash in ' + path, user, where))
    return found


def scan_layer(stream, layer, allowed, private=None):
    """Находки одного слоя: [(вид, путь, где)]."""
    found, where = [], f'layer {layer}'
    with tarfile.open(fileobj=stream, mode='r|*') as archive:
        for member in archive:
            path = '/' + member.name.lstrip('./')
            if not member.isfile() or member.size == 0:
                continue
            for label, pattern in PATHS:
                if pattern.search(path):
                    found.append((label, path, f'{where}, {member.size} bytes'))
            for data in pieces(archive.extractfile(member)):
                if re.fullmatch(r'/etc/g?shadow-?', path):
                    found += shadow(path, data, where)
                found += scan_bytes(path, data, where, allowed, private)
    return sorted(set(found))


def scan_config(config, allowed, private=None):
    """Переменные окружения, метки и история сборки из конфигурации образа."""
    found = []
    settings = config.get('config') or {}
    for entry in settings.get('Env') or []:
        name, _, value = entry.partition('=')
        if SECRET_NAME.search(name) and value:
            found.append(('secret-like environment variable', name, 'image config'))
    history = '\n'.join(item.get('created_by', '') for item in config.get('history') or [])
    for match in re.finditer(r'\b(\w*(?:TOKEN|SECRET|PASSW|PRIVATE|CREDENTIAL|API_?KEY)\w*)=(?!\$)["\']?[^\s"\']', history, re.I):
        found.append(('secret-like value in the build history', match.group(1), 'image config'))
    return found + scan_bytes('', (history + '\n' + json.dumps(settings)).encode(), 'image config or build history', allowed, private)


def tracked(root):
    """Файлы под управлением git; в распакованном архиве без .git — все файлы."""
    root = Path(root)
    if (root / '.git').exists():
        listing = subprocess.run(['git', '-c', 'safe.directory=*', '-C', str(root), 'ls-files', '-z'], check=True, capture_output=True)
        return sorted(filter(None, listing.stdout.decode().split('\0')))
    return sorted(str(path.relative_to(root)) for path in root.rglob('*') if path.is_file() and '__pycache__' not in path.parts)


def scan_tree(root, allowed, private=None, addresses=None):
    """Файлы репозитория под управлением git: из них собираются образы.

    addresses — общеизвестные публичные адреса; без списка адреса не проверяются.
    """
    found = []
    for name in tracked(root):
        path = Path(root) / name
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        found += scan_bytes(name, data, 'repository', allowed, private)
        for label, pattern in PATHS:
            if label in TREE_PATHS and pattern.search('/' + name):
                found.append((label, name, 'repository'))
        if addresses is not None:
            found += [('public IP address ' + address, name, 'repository') for address in sorted(public_addresses(data) - addresses)]
    return sorted(set(found))


def open_url(url, headers):
    return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=180)


def registry(ref):
    """Доступ к реестру по ссылке «host/repo@sha256:…»; учётные данные — из окружения."""
    host, _, rest = ref.partition('/')
    repo, _, digest = rest.partition('@')
    if not digest.startswith('sha256:'):
        raise ValueError('image must be addressed by digest')
    headers = {}
    user, password = os.environ.get('REGISTRY_USERNAME'), os.environ.get('REGISTRY_PASSWORD')
    if user and password:
        headers['Authorization'] = 'Basic ' + base64.b64encode(f'{user}:{password}'.encode()).decode()
    with retrying(open_url, f'https://{host}/token?scope=repository:{repo}:pull&service={host}', headers, errors=(OSError,)) as response:
        token = json.load(response)['token']
    return f'https://{host}/v2/{repo}', {'Authorization': 'Bearer ' + token}, digest


ACCEPT = ', '.join(['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json',
                    'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'])


def scan_image(ref, allowed, private=None):
    base, auth, digest = registry(ref)

    def fetch_json(path):
        with retrying(open_url, base + path, auth | {'Accept': ACCEPT}, errors=(OSError,)) as response:
            return json.load(response)

    def layer_findings(blob, index):
        with open_url(base + '/blobs/' + blob, auth) as stream:
            return scan_layer(stream, index, allowed, private)

    def blob_findings(blob, where):
        with open_url(base + '/blobs/' + blob, auth) as stream:
            return [row for data in pieces(stream) for row in scan_bytes('', data, where, allowed, private)]

    manifest, found = fetch_json('/manifests/' + digest), []
    if 'manifests' in manifest:
        images = [m for m in manifest['manifests'] if (m.get('platform') or {}).get('architecture') == 'amd64']
        if len(images) != 1:
            raise ValueError('expected exactly one amd64 image')
        # Аттестации (происхождение, SBOM) публикуются рядом с образом и несут
        # параметры сборки.
        for other in manifest['manifests']:
            if other is not images[0]:
                for layer in fetch_json('/manifests/' + other['digest']).get('layers') or []:
                    found += retrying(blob_findings, layer['digest'], 'attestation', errors=(OSError,))
        manifest = fetch_json('/manifests/' + images[0]['digest'])
    found += scan_config(fetch_json('/blobs/' + manifest['config']['digest']), allowed, private)
    if not manifest.get('layers'):
        raise ValueError('image has no layers')
    for index, layer in enumerate(manifest['layers'], 1):
        # Обрыв посреди слоя: читаем слой заново целиком.
        found += retrying(layer_findings, layer['digest'], index, errors=(OSError, EOFError, tarfile.TarError))
    return sorted(set(found)), len(manifest['layers'])


def main(arguments):
    allowed, private, total = known(), markers(), 0
    print('Private markers:', f'loaded ({private.groups})' if private else 'not configured on this runner')
    if arguments[:1] == ['--tree']:
        found = scan_tree(arguments[1], allowed, private)
        for kind, path, where in found:
            print('BLOCK', kind + ':', path, '(' + where + ')')
        print(f'Repository gate: {len(found)} findings')
        return 1 if found else 0
    for ref in arguments:
        found, layers = scan_image(ref, allowed, private)
        total += len(found)
        for kind, path, where in found:
            print('BLOCK', kind + ':', path, '(' + where + ')')
        print(f'Layer gate: {len(found)} findings in {layers} layers of {ref.split("@")[0].rsplit("/", 1)[-1]}')
    return 1 if total else 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, KeyError, EOFError, tarfile.TarError, subprocess.SubprocessError, http.client.HTTPException) as error:
        # Текст ошибки может содержать адрес с учётными данными.
        print('Layer gate failed:', type(error).__name__, file=sys.stderr)
        sys.exit(2)
