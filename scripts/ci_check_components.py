#!/usr/bin/env python3
"""Известные уязвимости и свежесть закреплённых версий.

Trivy видит пакеты Alpine и модули внутри Go-бинарников. Он не видит программы,
собранные из исходников на C (nginx, strongSwan, pppd, ocserv), готовые
бинарники на Rust (TeleMT, shadowsocks-rust) и уязвимости самих приложений,
объявленные их авторами. Этот скрипт сверяет закреплённые версии с NVD (по
CPE продукта) и с объявлениями безопасности репозиториев GitHub.

Допуск блокируют уязвимости HIGH и CRITICAL, для которых известна версия с
исправлением. Недоступный источник после повторов — тоже отказ: отсутствие
ответа не равно отсутствию уязвимостей. Отставание версий только печатается.
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

ROOT = Path(__file__).resolve().parents[1]
BLOCKING = {'HIGH', 'CRITICAL'}
# Версия: ключ .env либо ARG в Dockerfile. cpe — продукт в NVD; repo — источник
# объявлений безопасности и последнего релиза.
COMPONENTS = [
    dict(name='nginx', pin='NGINX_VERSION', cpe='f5:nginx'),
    dict(name='strongSwan', pin='dockerfile/ipsec.dockerfile:STRONGSWAN_VERSION', cpe='strongswan:strongswan', repo='strongswan/strongswan'),
    dict(name='pppd', pin='dockerfile/ipsec.dockerfile:PPP_VERSION', cpe='samba:ppp', repo='ppp-project/ppp'),
    dict(name='OpenVPN', pin='OPENVPN_VERSION', cpe='openvpn:openvpn', repo='OpenVPN/openvpn'),
    dict(name='Easy-RSA', pin='EASYRSA_VERSION', cpe='openvpn:easy-rsa', repo='OpenVPN/easy-rsa'),
    dict(name='AdGuard Home', pin='ADGUARD_VERSION', cpe='adguard:adguardhome', repo='AdguardTeam/AdGuardHome'),
    dict(name='sing-box', pin='SINGBOX_VERSION', cpe='sagernet:sing-box', repo='SagerNet/sing-box'),
    dict(name='mihomo', pin='MIHOMO_VERSION', cpe='metacubex:mihomo', repo='MetaCubeX/mihomo'),
    dict(name='Caddy', pin='CADDY_VERSION', cpe='caddyserver:caddy', repo='caddyserver/caddy'),
    dict(name='Xray', pin='XRAY_VERSION', repo='XTLS/Xray-core'),
    dict(name='Xray (fork)', pin='XRAY_FORK_VERSION', repo='Jolymmiles/Xray-core'),
    dict(name='Hysteria', pin='HYSTERIA_VERSION', repo='apernet/hysteria', tag_prefix='app/'),
    dict(name='TeleMT', pin='TELEMT_VERSION', repo='telemt/telemt'),
    dict(name='shadowsocks-rust', pin='SS_RUST_VERSION', repo='shadowsocks/shadowsocks-rust'),
    dict(name='Mieru', pin='MIERU_VERSION', repo='enfein/mieru'),
    dict(name='AmneziaWG', pin='AWG_GO_VERSION', repo='amnezia-vpn/amneziawg-go'),
    dict(name='amneziawg-tools', pin='AWG_TOOLS_VERSION', repo='amnezia-vpn/amneziawg-tools'),
    dict(name='ocserv', pin='OCSERV_VERSION'),
]


def numbers(version):
    """Числовые части версии: v26.10.5-1858 → (26, 10, 5, 1858)."""
    return tuple(int(part) for part in re.findall(r'\d+', version))


def pins(root=ROOT):
    env = dict(line.split('=', 1) for line in (root / '.env').read_text().splitlines()
               if re.match(r'^[A-Z0-9_]+=', line))
    found = {}
    for item in COMPONENTS:
        source = item['pin']
        if ':' in source:
            path, key = source.split(':')
            match = re.search(rf'^ARG {key}=(\S+)$', (root / path).read_text(), re.M)
            value = match.group(1) if match else ''
        else:
            value = env.get(source, '')
        if not numbers(value):
            raise ValueError('pinned version is missing: ' + item['name'])
        found[item['name']] = value
    return found


def http_json(url, token=None):
    request = urllib.request.Request(url, headers={'Accept': 'application/json', 'User-Agent': 'vpnbot-ci'})
    if token:
        # NVD принимает ключ своим заголовком, GitHub — как Bearer.
        if 'nvd.nist.gov' in url:
            request.add_header('apiKey', token)
        else:
            request.add_header('Authorization', 'Bearer ' + token)
    with urllib.request.urlopen(request, timeout=40) as response:
        return json.load(response)


def fetch(url, token=None):
    return retrying(http_json, url, token, errors=(OSError, ValueError))


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


def affected(version, vulnerable, patched):
    """Попадает ли версия в диапазон объявления GitHub («>= 2.0.0, < 2.9.2»)."""
    current = numbers(version)
    for clause in filter(None, (part.strip() for part in (vulnerable or '').split(','))):
        match = re.match(r'^(<=|>=|<|>|=)\s*v?([0-9][^\s]*)$', clause)
        if not match:
            # Нераспознанная запись диапазона: надёжнее считать версию затронутой
            # и сверить по версии с исправлением ниже.
            continue
        operator, bound = match.group(1), numbers(match.group(2))
        if not {'<': current < bound, '<=': current <= bound, '>': current > bound,
                '>=': current >= bound, '=': current == bound}[operator]:
            return False
    fixed = numbers(patched or '')
    return not fixed or current < fixed


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
                              bool(numbers(item.get('patched_versions') or ''))))
                break
    return sorted(set(found))


def latest_release(repo, prefix, token):
    data = fetch(f'https://api.github.com/repos/{repo}/releases?per_page=30', token)
    tags = [r['tag_name'] for r in data if not r.get('prerelease') and not r.get('draft') and r['tag_name'].startswith(prefix)
            and numbers(r['tag_name'])]
    return max(tags, key=numbers) if tags else None


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
        if freshness and item.get('repo'):
            latest = latest_release(item['repo'], item.get('tag_prefix', ''), token)
            if latest and numbers(latest) > numbers(version):
                newer = latest
        sources = [s for s, key in (('NVD', 'cpe'), ('GitHub', 'repo')) if item.get(key)]
        rows.append(dict(name=name, version=version, findings=findings, newer=newer, sources=sources))
        blocked += [(name, version, *finding) for finding in findings if finding[1] in BLOCKING and finding[2]]
    return rows, blocked


def report(rows, blocked):
    lines = []
    for row in rows:
        state = 'нет источника данных' if not row['sources'] else ', '.join(row['sources'])
        lines.append(f"{row['name']} {row['version']}: проверено по {state}" if row['sources'] else f"{row['name']} {row['version']}: {state}")
        for ident, level, fixable, source in row['findings']:
            lines.append(f"  {'BLOCK' if level in BLOCKING and fixable else 'note '} {ident} {level} ({source})")
        if row['newer']:
            lines.append(f"  вышла версия {row['newer']}")
    outdated = [row for row in rows if row['newer']]
    lines.append(f'Component gate: {len(blocked)} blocking findings; {len(outdated)} components have a newer release')
    return '\n'.join(lines)


def main():
    token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    rows, blocked = check(token=token)
    text = report(rows, blocked)
    print(text)
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a') as stream:
            stream.write('### Закреплённые версии\n\n```\n' + text + '\n```\n')
    return 1 if blocked else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        # Адрес запроса может содержать ключ API: печатаем только вид ошибки.
        print('Component gate failed:', type(error).__name__, file=sys.stderr)
        sys.exit(2)
