#!/usr/bin/env python3
"""Известные уязвимости и свежесть закреплённых версий.

Trivy видит пакеты Alpine и модули внутри Go-бинарников. Он не видит программы,
собранные из исходников на C (nginx, strongSwan, pppd, ocserv), готовые
бинарники на Rust (TeleMT, shadowsocks-rust) и уязвимости самих приложений,
объявленные их авторами. snolc и TrustTunnel собираются cargo auditable:
зависимости проверяет Trivy. Этот скрипт сверяет закреплённые версии с NVD (по
CPE продукта) и с объявлениями безопасности репозиториев GitHub.

У ocserv нет записей ни в NVD, ни на GitHub: автор отмечает исправления
безопасности пометкой [SECURITY] в описании релиза на GitLab. Релиз новее
закреплённого с такой пометкой (или с номером CVE) блокирует допуск.

Допуск блокируют уязвимости HIGH и CRITICAL, для которых известна версия с
исправлением. Недоступный источник после повторов — тоже отказ: отсутствие
ответа не равно отсутствию уязвимостей. Отставание версий только печатается.

У nginx запись в NVD появляется с опозданием: 1.30.5 проходил как чистый, хотя
nginx.org уже объявил четыре исправленные в 1.30.6 уязвимости. Поэтому nginx
сверяется ещё и со страницей объявлений nginx.org, и любое объявление,
исправленное в закреплённой стабильной ветке, блокирует допуск независимо от
важности: nginx стоит наружу, а исправление — номер патч-версии.

Компиляторы Go и Rust, snolc, базовый Alpine и инструменты сборки проверяются
только на свежесть (release/toolchain/git/alpine): уязвимости стандартной
библиотеки Go и пакетов Rust находит Trivy в собранных бинарниках.
Недоступный источник свежести не блокирует допуск — репозиторий snolc уже
бывал недоступен.

Каждая закреплённая версия (`*_VERSION`, `*_REF` в .env и ARG Dockerfile)
обязана быть в COMPONENTS или в UNCHECKED с причиной — это проверяет тест.
Перед полным прогоном: `make versions`.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from ci_retry import retrying
import ci_assets
import ci_waivers
import ci_release_policy as release

ROOT = Path(__file__).resolve().parents[1]
BLOCKING = {'HIGH', 'CRITICAL'}
# Версия: ключ .env либо ARG в Dockerfile. cpe — продукт в NVD; repo — источник
# объявлений безопасности и последнего релиза; gitlab — проект, чьи описания
# релизов служат объявлениями.
COMPONENTS = [
    dict(name='nginx', pin='NGINX_VERSION', cpe='f5:nginx', nginx=True, fresh='nginx/nginx', tag_prefix='release-', branch=True),
    dict(name='strongSwan', pin='dockerfile/ipsec.dockerfile:STRONGSWAN_VERSION', cpe='strongswan:strongswan', repo='strongswan/strongswan'),
    dict(name='pppd', pin='dockerfile/ipsec.dockerfile:PPP_VERSION', cpe='samba:ppp', repo='ppp-project/ppp'),
    dict(name='OpenVPN', pin='OPENVPN_VERSION', cpe='openvpn:openvpn', repo='OpenVPN/openvpn'),
    dict(name='Easy-RSA', pin='EASYRSA_VERSION', cpe='openvpn:easy-rsa', repo='OpenVPN/easy-rsa'),
    dict(name='AdGuard Home', pin='ADGUARD_VERSION', cpe='adguard:adguardhome', repo='AdguardTeam/AdGuardHome'),
    dict(name='sing-box', pin='SINGBOX_VERSION', cpe='sagernet:sing-box', repo='SagerNet/sing-box'),
    dict(name='sing-box Windows', pin='asset:sing-box Windows', repo='SagerNet/sing-box'),
    dict(name='jQuery webapp', pin='asset:jquery', repo='jquery/jquery'),
    dict(name='JSONEditor webapp', pin='asset:jsoneditor', repo='josdejong/jsoneditor'),
    dict(name='WinSW Windows', pin='asset:WinSW', repo='winsw/winsw'),
    dict(name='mihomo', pin='MIHOMO_VERSION', cpe='metacubex:mihomo', repo='MetaCubeX/mihomo'),
    dict(name='Caddy', pin='CADDY_VERSION', cpe='caddyserver:caddy', repo='caddyserver/caddy'),
    dict(name='Xray', pin='XRAY_VERSION', repo='XTLS/Xray-core'),
    dict(name='Xray (fork)', pin='XRAY_FORK_VERSION', repo='Jolymmiles/Xray-core'),
    # Older cores kept in the xr image (selectable on the main server and nodes): advisories
    # apply to them as to the current core; only the comparison with the latest release is skipped.
    dict(name='Xray (slot 2)', pin='XRAY_VERSION_2', repo='XTLS/Xray-core', stale=True),
    dict(name='Xray (slot 3)', pin='XRAY_VERSION_3', repo='XTLS/Xray-core', stale=True),
    dict(name='Xray (MASQUE)', pin='MASQUE_XRAY_VERSION', repo='XTLS/Xray-core'),
    dict(name='Hysteria', pin='HYSTERIA_VERSION', repo='apernet/hysteria', tag_prefix='app/'),
    dict(name='TeleMT', pin='TELEMT_VERSION', repo='telemt/telemt'),
    dict(name='TrustTunnel', pin='dockerfile/trusttunnel.dockerfile:TT_REF', repo='TrustTunnel/TrustTunnel'),
    dict(name='shadowsocks-rust', pin='SS_RUST_VERSION', repo='shadowsocks/shadowsocks-rust'),
    dict(name='Mieru', pin='MIERU_VERSION', repo='enfein/mieru'),
    dict(name='AmneziaWG', pin='AWG_GO_VERSION', repo='amnezia-vpn/amneziawg-go'),
    dict(name='amneziawg-tools', pin='AWG_TOOLS_VERSION', repo='amnezia-vpn/amneziawg-tools'),
    dict(name='ocserv', pin='OCSERV_VERSION', gitlab='openconnect/ocserv'),
    dict(name='Go', pin='PROTOCOL_GO_VERSION', toolchain='go'),
    dict(name='Go (Caddy)', pin='CADDY_GO_VERSION', toolchain='go'),
    dict(name='Go (MASQUE)', pin='MASQUE_GO_VERSION', toolchain='go'),
    dict(name='Rust (snolc)', pin='dockerfile/snolc.dockerfile:RUST_VERSION', release='rust-lang/rust'),
    dict(name='Rust (TrustTunnel)', pin='dockerfile/trusttunnel.dockerfile:RUST_VERSION', release='rust-lang/rust'),
    dict(name='Rust (TeleMT)', pin='dockerfile/telemt.dockerfile:RUST_VERSION', release='rust-lang/rust'),
    dict(name='Rust (shadowsocks)', pin='dockerfile/shadowsocks.dockerfile:RUST_VERSION', release='rust-lang/rust'),
    dict(name='snolc', pin='dockerfile/snolc.dockerfile:SNOLC_VERSION', release='owenewans/snolc'),
    # Только свежесть: у этих проектов нет ни CPE в NVD, ни объявлений GitHub,
    # либо это инструменты сборки, не попадающие в образ.
    dict(name='wgcf', pin='WGCF_VERSION', release='ViRb3/wgcf'),
    dict(name='dnslookup', pin='DNSLOOKUP_VERSION', release='ameshkov/dnslookup'),
    dict(name='xcaddy', pin='XCADDY_VERSION', release='caddyserver/xcaddy'),
    # Старые теги caddy2-naive-<дата> выглядели бы «новее» по числам.
    dict(name='forwardproxy (Naive)', pin='FORWARDPROXY_VERSION', release='klzgrad/forwardproxy', tag_prefix='v'),
    dict(name='v2ray-plugin', pin='V2RAY_PLUGIN_VERSION', release='teddysun/v2ray-plugin'),
    dict(name='Cloak', pin='CLOAK_VERSION', release='cbeuw/Cloak'),
    dict(name='simple-tls', pin='SIMPLE_TLS_VERSION', release='IrineSistiana/simple-tls'),
    dict(name='tun2socks', pin='dockerfile/wireguard.dockerfile:TUN2SOCKS_VERSION', release='xjasonlyu/tun2socks'),
    dict(name='cargo-auditable', pin='dockerfile/snolc.dockerfile:CARGO_AUDITABLE_VERSION', release='rust-secure-code/cargo-auditable'),
    dict(name='cargo-auditable (TrustTunnel)', pin='dockerfile/trusttunnel.dockerfile:CARGO_AUDITABLE_VERSION', release='rust-secure-code/cargo-auditable'),
    dict(name='cargo-auditable (TeleMT)', pin='dockerfile/telemt.dockerfile:CARGO_AUDITABLE_VERSION', release='rust-secure-code/cargo-auditable'),
    dict(name='cargo-auditable (shadowsocks)', pin='dockerfile/shadowsocks.dockerfile:CARGO_AUDITABLE_VERSION', release='rust-secure-code/cargo-auditable'),
    dict(name='Trivy', pin='scripts/ci_scan_image.sh:TRIVY', pattern=r'/trivy/releases/download/v([0-9.]+)/', release='aquasecurity/trivy'),
    dict(name='DNSTT', pin='dockerfile/dnstt.dockerfile:DNSTT_REF', git='https://www.bamsoftware.com/git/dnstt.git'),
    dict(name='Alpine', pin='IMAGE', alpine=True),
]

# Закреплённые значения, которые сознательно не сверяются с последним выпуском.
UNCHECKED = {}
FRESHNESS_ONLY = ('toolchain', 'release', 'git', 'alpine')


def numbers(version):
    """Числовые части версии: v26.10.5-1858 → (26, 10, 5, 1858)."""
    return tuple(int(part) for part in re.findall(r'\d+', version))


def pins(root=ROOT):
    env = dict(line.split('=', 1) for line in (root / '.env').read_text().splitlines()
               if re.match(r'^[A-Z0-9_]+=', line))
    found, assets = {}, None
    for item in COMPONENTS:
        source = item['pin']
        if source.startswith('asset:'):
            if assets is None:
                assets, _bom = ci_assets.inventory(root)
            value = assets[source.removeprefix('asset:')]
        elif ':' in source:
            path, key = source.split(':')
            match = re.search(item.get('pattern') or rf'^ARG {key}=(\S+)$', (root / path).read_text(), re.M)
            value = match.group(1) if match else ''
        else:
            value = env.get(source, '')
        if not numbers(value):
            raise ValueError('pinned version is missing: ' + item['name'])
        found[item['name']] = value
    return found


def http_json(url, token=None):
    request = urllib.request.Request(url, headers={'Accept': 'application/json', 'User-Agent': 'vpnbot-ci'})
    parts = urllib.parse.urlsplit(url)
    if token and parts.scheme == 'https':
        # Ключ уходит только своему адресату по точному имени хоста: NVD —
        # своим заголовком, GitHub — как Bearer; остальным адресам — без ключа.
        if parts.hostname == 'services.nvd.nist.gov':
            request.add_header('apiKey', token)
        elif parts.hostname == 'api.github.com':
            request.add_header('Authorization', 'Bearer ' + token)
    with urllib.request.urlopen(request, timeout=40) as response:
        return json.load(response)


def fetch(url, token=None):
    return retrying(http_json, url, token, errors=(OSError, ValueError))


def http_text(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'vpnbot-ci'})
    with urllib.request.urlopen(request, timeout=40) as response:
        return response.read().decode('utf-8', 'replace')


def fetch_text(url):
    return retrying(http_text, url, errors=(OSError, ValueError))


def severity(cve):
    metrics = cve.get('metrics', {})
    for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        for metric in metrics.get(key, []):
            value = metric.get('cvssData', {}).get('baseSeverity') or metric.get('baseSeverity')
            if value:
                return value.upper()
    return 'UNKNOWN'


def nvd_findings(cpe, version):
    """CVE из NVD, применимые ровно к этой версии продукта."""
    clean = '.'.join(map(str, numbers(version)[:3]))
    query = urllib.parse.urlencode({'virtualMatchString': f'cpe:2.3:a:{cpe}:{clean}', 'resultsPerPage': 500})
    key = os.environ.get('NVD_API_KEY') or None
    # Без ключа NVD принимает пять запросов за тридцать секунд.
    time.sleep(0.7 if key else 6.5)
    data = fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?' + query, key)
    if not isinstance(data.get('vulnerabilities'), list):
        raise ValueError('unexpected NVD response')
    return sorted((item['cve']['id'], severity(item['cve'])) for item in data['vulnerabilities']
                  if item['cve'].get('vulnStatus') != 'Rejected')


def advisory_version(version):
    """SemVer для advisories: prerelease ниже выпуска, build metadata не сравнивается.

    Сокращённые границы 1/1.2 означают 1.0.0/1.2.0. Неизвестный формат
    останавливает проверку, вместо извлечения произвольных цифр из строки.
    """
    match = re.fullmatch(r'v?(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?(?:\.(0|[1-9]\d*))?'
                         r'(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?', str(version))
    if not match:
        raise ValueError('unsupported advisory version')
    core = tuple(int(value or 0) for value in match.group(1, 2, 3))
    prerelease = match.group(4)
    parts = []
    for value in prerelease.split('.') if prerelease else []:
        if value.isdigit():
            if len(value) > 1 and value.startswith('0'):
                raise ValueError('invalid numeric prerelease')
            parts.append((0, int(value)))
        else:
            parts.append((1, value))
    return core, prerelease is None, tuple(parts)


def patched_versions(patched):
    """Исправленные версии; авторы иногда пишут «>= v1.2.3» или «v.1.2.3»."""
    if patched is None or patched == '':
        return []
    if not isinstance(patched, str):
        raise ValueError('unsupported patched versions')
    versions = []
    for value in patched.split(','):
        value = re.sub(r'^(?:>=|=)\s*', '', value.strip())
        versions.append(advisory_version(re.sub(r'^v\.(?=\d)', 'v', value)))
    return versions


def advisory_fix_available(patched):
    return bool(patched_versions(patched))


def normalize_range(vulnerable):
    """Свободные формы, которые авторы пишут в объявлениях репозиториев."""
    text = vulnerable.strip()
    match = re.fullmatch(r'(\S+)\s+to\s+(\S+)', text)
    if match:
        return f'>= {match.group(1)}, <= {match.group(2)}'
    match = re.fullmatch(r'(\S+)\s+and\s+(?:later|above|newer)', text)
    if match:
        return '>= ' + match.group(1)
    # «>=1.0.3 <3.5.0»: условия через пробел вместо запятой.
    return re.sub(r'(?<=[^\s,|])\s+(?=(?:<=|>=|<|>|=)\s*v?\d)', ', ', text)


def affected(version, vulnerable, patched):
    """Только диапазон определяет применимость; patched — отдельный набор веток."""
    current = advisory_version(version)
    if not isinstance(vulnerable, str) or not vulnerable.strip():
        raise ValueError('missing vulnerable version range')
    fixed = patched_versions(patched)
    try:
        matched = range_matches(current, normalize_range(vulnerable))
    except ValueError:
        # Непонятный текст диапазона не решает ничего, кроме случая, когда все
        # исправленные версии строго старше закреплённой: тогда она не затронута.
        if fixed and all(current > version for version in fixed):
            return False
        raise
    # Открытый диапазон («>= v26.1.13») при исправлении во всех ветках не
    # старше закреплённой версии: она уже содержит исправление.
    return matched and not (fixed and all(current >= version for version in fixed))


def range_matches(current, vulnerable):
    groups = []
    for group in vulnerable.split('||'):
        clauses = []
        for clause in group.split(','):
            match = re.fullmatch(r'\s*(<=|>=|<|>|=)?\s*([^\s,|]+)\s*', clause)
            if not match:
                raise ValueError('unsupported vulnerable version range')
            operator, bound = match.group(1) or '=', advisory_version(match.group(2))
            clauses.append({'<': current < bound, '<=': current <= bound, '>': current > bound,
                            '>=': current >= bound, '=': current == bound}[operator])
        groups.append(all(clauses))
    return any(groups)


def advisory_findings(repo, version, token):
    """Опубликованные объявления безопасности репозитория, затрагивающие версию."""
    data = fetch(f'https://api.github.com/repos/{repo}/security-advisories?per_page=100&state=published', token)
    if not isinstance(data, list):
        raise ValueError('unexpected advisories response')
    found = []
    for advisory in data:
        for item in advisory.get('vulnerabilities') or []:
            if affected(version, item.get('vulnerable_version_range'), item.get('patched_versions')):
                found.append((advisory.get('cve_id') or advisory['ghsa_id'], (advisory.get('severity') or 'unknown').upper(),
                              advisory_fix_available(item.get('patched_versions'))))
                break
    return sorted(set(found))


SECURITY_NOTE = re.compile(r'\[SECURITY\]|\bCVE-\d{4}-\d{4,}|\bsecurity (?:fix|issue|vulnerabilit)', re.I)


def gitlab_findings(project, version):
    """Релизы проекта GitLab новее закреплённого: (находки, последняя версия)."""
    data = fetch('https://gitlab.com/api/v4/projects/' + urllib.parse.quote(project, safe='') + '/releases?per_page=100')
    if not isinstance(data, list) or not all(isinstance(item, dict) and item.get('tag_name') for item in data):
        raise ValueError('unexpected GitLab response')
    current = numbers(version)
    if current not in {numbers(item['tag_name']) for item in data}:
        # Без закреплённой версии в списке нельзя судить, что вышло после неё.
        raise ValueError('pinned version is not among GitLab releases')
    newer = sorted((item for item in data if numbers(item['tag_name']) > current and not item.get('upcoming_release')),
                   key=lambda item: numbers(item['tag_name']))
    found = []
    for item in newer:
        notes = item.get('description') or ''
        if SECURITY_NOTE.search(notes):
            idents = sorted(set(re.findall(r'CVE-\d{4}-\d{4,}', notes))) or ['security fix in ' + item['tag_name']]
            # Важность автор не указывает: исправление уже выпущено, обновляемся.
            found += [(ident, 'HIGH', True) for ident in idents]
    return found, (newer[-1]['tag_name'] if newer else None)


NGINX_ADVISORIES = 'https://nginx.org/en/security_advisories.html'
NGINX_SEVERITY = {'major': 'HIGH', 'medium': 'MEDIUM', 'minor': 'LOW', 'low': 'LOW', 'none': 'LOW'}


def nginx_findings(version):
    """Объявления nginx.org, затрагивающие версию: (идентификатор, важность, исправлено).

    «Not vulnerable: 1.31.7+, 1.30.6+» — исправление в каждой из веток;
    «Vulnerable: 1.30.0-1.30.5, 1.31.0, …» — затронутые диапазоны и отдельные
    версии (первый выпуск стабильной ветки часто указан одним номером). Сборки
    только для Windows (nginx/Windows …) к образу не относятся. Нераспознанная
    запись — отказ: пропустить затронутую версию хуже, чем остановить допуск."""
    page = fetch_text(NGINX_ADVISORIES)
    entries = re.findall(r'<li><p>(.*?)</p></li>', page, re.S)
    if len(entries) < 10:
        raise ValueError('unexpected nginx.org advisories page')
    current, found = numbers(version)[:3], []
    for entry in entries:
        # Каждый тег — граница строки: поля «Vulnerable:» и т. п. не слипаются со ссылками.
        text = re.sub(r'<[^>]+>', '\n', entry)
        level = re.search(r'Severity:\s*(\w+)', text)
        vulnerable = re.search(r'^\s*Vulnerable:\s*(.+?)\s*$', text, re.M)
        safe = re.search(r'^\s*Not vulnerable:\s*(.+?)\s*$', text, re.M)
        if not level or not vulnerable:
            raise ValueError('unexpected nginx.org advisory entry')
        hit = False
        for part in (part.strip() for part in vulnerable.group(1).split(',')):
            if part.startswith('nginx/Windows '):
                continue
            bounds = re.fullmatch(r'([0-9.]+)(?:-([0-9.]+))?', part)
            if part != 'all' and not bounds:
                raise ValueError('unexpected nginx.org vulnerable range')
            hit = hit or part == 'all' or numbers(bounds.group(1)) <= current <= numbers(bounds.group(2) or bounds.group(1))
        fixes = [numbers(part) for part in re.findall(r'([0-9.]+)\+', safe.group(1) if safe else '')]
        if not hit or any(current >= fix and (current[:2] == fix[:2] or current[:2] > max(fixes)[:2]) for fix in fixes):
            continue
        ident = re.search(r'CVE-\d{4}-\d{4,}', text)
        name = ident.group(0) if ident else 'nginx: ' + ' '.join(text.split('Severity')[0].split())[:60]
        # Исправлено, если выпуск с исправлением есть в этой же или более новой ветке.
        found.append((name, NGINX_SEVERITY.get(level.group(1).lower(), 'UNKNOWN'), any(fix > current for fix in fixes)))
    return sorted(set(found))


def latest_release(repo, prefix, token, branch=None):
    """Последний стабильный выпуск; branch — версия, чья ветка (x.y) не меняется."""
    data = fetch(f'https://api.github.com/repos/{repo}/releases?per_page=30', token)
    if not isinstance(data, list):
        raise ValueError('unexpected releases response')
    tags = [r['tag_name'] for r in data if not r.get('prerelease') and not r.get('draft')]
    if not data:
        # Проект без GitHub-релизов (amneziawg-go): только теги.
        # GitHub отдаёт теги не по номеру версии: берём страницу побольше.
        listing = fetch(f'https://api.github.com/repos/{repo}/tags?per_page=100', token)
        if not isinstance(listing, list):
            raise ValueError('unexpected tags response')
        tags = [t['name'] for t in listing if not re.search(r'(?i)(rc|beta|alpha|pre|dev)', t['name'])]
    tags = [tag for tag in tags if tag.startswith(prefix) and numbers(tag)
            and (branch is None or numbers(tag)[:2] == numbers(branch)[:2])]
    return max(tags, key=numbers) if tags else None


def latest_git(url):
    """Коммит основной ветки по «простому» HTTP-протоколу git (HEAD и info/refs)."""
    head = re.match(r'ref: (refs/heads/\S+)', fetch_text(url.rstrip('/') + '/HEAD'))
    refs = dict((name, sha) for sha, name in re.findall(r'^([0-9a-f]{40})\t(\S+)$', fetch_text(url.rstrip('/') + '/info/refs'), re.M))
    if not head or head.group(1) not in refs:
        raise ValueError('unexpected git refs response')
    return refs[head.group(1)]


def latest_alpine():
    """(последняя стабильная ветка, дата окончания поддержки community закреплённой)."""
    data = fetch('https://alpinelinux.org/releases.json')
    if not isinstance(data, dict) or not data.get('latest_stable'):
        raise ValueError('unexpected alpinelinux.org response')
    return data['latest_stable'], {branch.get('rel_branch'): next((repo.get('eol_date') for repo in branch.get('repos', [])
                                                                    if repo.get('name') == 'community'), None)
                                   for branch in data.get('release_branches', [])}


def latest_go():
    data = fetch('https://go.dev/dl/?mode=json')
    if not isinstance(data, list):
        raise ValueError('unexpected go.dev response')
    stable = [item['version'] for item in data if item.get('stable') and numbers(item.get('version', ''))]
    return max(stable, key=numbers) if stable else None


def latest_only(item, version, token):
    """Свежесть без проверки уязвимостей: (последняя версия или None, источник ответил, примечания)."""
    try:
        if item.get('toolchain') == 'go':
            return latest_go(), True, []
        if item.get('git'):
            return latest_git(item['git']), True, []
        if item.get('alpine'):
            latest, eol = latest_alpine()
            return latest, True, alpine_notes(version, eol)
        return latest_release(item['release'], item.get('tag_prefix', ''), token), True, []
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        # Сбой или непривычный ответ источника свежести не блокирует допуск.
        return None, False, []


def newer_than(item, latest, version):
    if not latest:
        return None
    if item.get('git'):
        return latest[:12] if latest != version else None
    return latest if numbers(latest) > numbers(version) else None


def alpine_notes(version, eol, today=None):
    """Предупреждение: поддержка community закреплённой ветки кончилась или кончится за 30 дней."""
    branch = 'v' + '.'.join(map(str, numbers(version)[:2]))
    date = eol.get(branch)
    today = today or time.strftime('%Y-%m-%d', time.gmtime())
    if date and time.mktime(time.strptime(date, '%Y-%m-%d')) - time.mktime(time.strptime(today, '%Y-%m-%d')) <= 30 * 86400:
        return [f'поддержка community {branch} заканчивается {date}' if date >= today else f'поддержка community {branch} закончилась {date}']
    return []


def check(root=ROOT, token=None, freshness=True):
    rows, blocked = [], []
    versions = pins(root)
    for item in COMPONENTS:
        name, version = item['name'], versions[item['name']]
        findings = []
        if item.get('cpe'):
            findings += [(cve, level, True, 'NVD') for cve, level in nvd_findings(item['cpe'], version)]
        if item.get('repo'):
            findings += [(ident, level, fixable, 'GitHub') for ident, level, fixable in advisory_findings(item['repo'], version, token)]
        newer = None
        if any(item.get(key) for key in FRESHNESS_ONLY):
            latest, answered, notes = latest_only(item, version, token) if freshness else (None, True, [])
            source = 'go.dev' if item.get('toolchain') else 'git' if item.get('git') else 'alpinelinux.org' if item.get('alpine') else 'GitHub'
            rows.append(dict(name=name, version=version, findings=[], newer=newer_than(item, latest, version), sources=[],
                             freshness=source, unchecked=not answered, notes=notes))
            continue
        if item.get('gitlab'):
            noted, newer = gitlab_findings(item['gitlab'], version)
            findings += [(ident, level, fixable, 'GitLab') for ident, level, fixable in noted]
        if item.get('nginx'):
            findings += [(ident, level, fixable, 'nginx.org') for ident, level, fixable in nginx_findings(version)]
        if freshness and (item.get('repo') or item.get('fresh')) and not item.get('stale'):
            newer = newer_than(item, latest_release(item.get('repo') or item['fresh'], item.get('tag_prefix', ''), token,
                                                    version if item.get('branch') else None), version)
        sources = [s for s, key in (('NVD', 'cpe'), ('GitHub', 'repo'), ('GitLab', 'gitlab'), ('nginx.org', 'nginx')) if item.get(key)]
        rows.append(dict(name=name, version=version, findings=findings, newer=newer, sources=sources))
        blocked += [(name, version, *finding) for finding in findings
                    if (finding[1] in BLOCKING or finding[3] == 'nginx.org') and finding[2]]
    return rows, blocked


def report(rows, blocked, waived=frozenset()):
    lines = []
    for row in rows:
        state = 'нет источника данных' if not row['sources'] else ', '.join(row['sources'])
        if row.get('freshness'):
            state = 'источник свежести недоступен' if row['unchecked'] else 'свежесть по ' + row['freshness']
            lines.append(f"{row['name']} {row['version']}: {state}")
        else:
            lines.append(f"{row['name']} {row['version']}: проверено по {state}" if row['sources'] else f"{row['name']} {row['version']}: {state}")
        for ident, level, fixable, source in row['findings']:
            mark = 'BLOCK' if (level in BLOCKING or source == 'nginx.org') and fixable else 'note '
            if mark == 'BLOCK' and (row['name'], row['version'], ident) in waived:
                mark = 'WAIVE'
            lines.append(f"  {mark} {ident} {level} ({source})")
        for note in row.get('notes', []):
            lines.append(f"  внимание: {note}")
        if row['newer']:
            lines.append(f"  вышла версия {row['newer']}")
    outdated = [row for row in rows if row['newer']]
    lines.append(f'Component gate: {len(blocked)} blocking findings; {len(outdated)} components have a newer release')
    return '\n'.join(lines)


def apply_waivers(blocked):
    """Explicitly allowed exact findings (scripts/ci_vuln_waivers.json) stop blocking."""
    blocked, waived, hints = ci_waivers.split(
        blocked, lambda entries, f: ci_waivers.component_waiver(entries, f[2], f[0], f[1]))
    lines = []
    for (name, version, ident, level, _fixable, source), entry in waived:
        lines.append(f'WAIVED {name} {version} {ident} {level} ({source}) — {ci_waivers.describe(entry)}')
        ci_waivers.annotate('warning', f'Допуск с исключением: {name} {version} {ident} {level} — {ci_waivers.describe(entry)}')
    for (name, version, ident, *_rest), entry in hints:
        lines.append(f'есть исключение для {name} {version} {ident} ({ci_waivers.describe(entry)}); '
                     'действует только при ручном запуске с allow_waivers')
    return blocked, lines, frozenset((f[0], f[1], f[2]) for f, _entry in waived)


def main():
    token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    rows, blocked = check(token=token)
    blocked, waiver_lines, waived = apply_waivers(blocked)
    warnings = [release.warning('waiver', ident) for _name, _version, ident in sorted(waived)]
    if blocked and release.policy()['allow_vulnerabilities']:
        warnings += [release.warning('vulnerability', finding[2]) for finding in blocked]
        waived = waived | frozenset((f[0], f[1], f[2]) for f in blocked)
        blocked = []
    text = report(rows, blocked, waived) + ''.join('\n' + line for line in waiver_lines)
    print(text)
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a') as stream:
            stream.write('### Закреплённые версии\n\n```\n' + text + '\n```\n')
    if not blocked and os.environ.get('CI_REPORT_FILE'):
        release.write_report('components', warnings, len(rows))
    elif warnings:
        release.announce(warnings, 'components')
    return 1 if blocked else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        # Адрес запроса может содержать ключ API: печатаем только вид ошибки.
        print('Component gate failed:', type(error).__name__, file=sys.stderr)
        sys.exit(2)
