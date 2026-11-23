#!/usr/bin/env python3
"""Решение о допуске образа по отчёту Trivy (JSON).

Блокируют: уязвимости HIGH и CRITICAL с известным исправлением, секреты в слоях
образа, ОС образа не Alpine или снятая с поддержки, отсутствие проверки пакетов ОС.
Уязвимости без исправления только перечисляются: обновлять пока не на что.
"""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ci_waivers  # noqa: E402
import ci_release_policy as release


# Every statically linked application must remain visible even with zero CVEs.
# Xray compatibility slots pinned in .env are mandatory like the primary/fork/helper
# binaries. Native C/C++ and OS package coverage are separate.
RUST_TARGETS = {
    'tt': {'usr/local/libexec/trusttunnel_endpoint', 'usr/local/bin/setup_wizard'},
    'telemt': {'usr/local/bin/telemt'},
    'ss': {'usr/bin/' + name for name in ('sslocal', 'ssserver', 'ssmanager', 'ssservice', 'ssurl')},
    'snolc': {'opt/snolc/runtime/bin/snolc', 'opt/snolc/sbom/vpnbot-snolc-modules'},
}
GO_TARGETS = {
    'php': {'usr/bin/' + name for name in ('dnslookup', 'sing-box', 'mihomo')},
    'wg': {'usr/bin/' + name for name in ('warp-socks', 'wgcf', 'tun2socks', 'amneziawg-go')},
    'ad': {'opt/adguardhome/AdGuardHome'},
    'xr': {'usr/bin/xray', 'usr/bin/xray-smux', 'usr/bin/wireproxy-node'},
    'np': {'usr/local/bin/caddy'},
    'ss': {'usr/bin/' + name for name in ('ck-client', 'ck-server', 'simple-tls', 'v2ray-plugin')},
    'dnstt': {'usr/local/bin/dnstt-server'},
    'hysteria': {'usr/local/bin/hysteria'},
    'protocol': {'usr/local/bin/sing-box', 'usr/local/bin/protocol-stats'},
    'mieru': {'usr/local/bin/mita', 'usr/local/bin/mieru-control'},
    'masque': {'usr/local/bin/xray'},
}


# These local replacements are part of the pinned/patched application source,
# not unknown third-party versions. Product advisories are checked separately.
GO_LOCAL_SOURCES = {
    'usr/local/bin/hysteria': {'../core', '../extras'},
    'usr/bin/xray-smux': {'./third_party/reality'},
    'usr/local/bin/caddy': {'/caddy', '/forwardproxy'},
}


def xray_slots(root=Path(__file__).resolve().parents[1]):
    """Older Xray cores pinned in .env are shipped as /usr/bin/xray-N and must be scanned too."""
    env = root / '.env'
    if not env.exists():
        return set()
    pinned = dict(line.split('=', 1) for line in env.read_text().splitlines() if line.startswith('XRAY_VERSION_') and '=' in line)
    return {'usr/bin/xray-' + key.removeprefix('XRAY_VERSION_') for key, value in pinned.items() if value.strip()}


def require_packages(results, kind, expected, label):
    targets = set()
    for result in results:
        target = result.get('Target', '').lstrip('/')
        packages = result.get('Packages') or []
        if result.get('Class') != 'lang-pkgs' or result.get('Type') != kind or not packages:
            continue
        if kind == 'gobinary':
            # Source-built main modules have (devel), omitted by Trivy. Require
            # versioned stdlib/dependencies, permitting only root/source modules.
            if not any(p.get('Name') == 'stdlib' and p.get('Version') for p in packages):
                continue
            valid = all(p.get('Name') and (p.get('Version') or p.get('Relationship') == 'root'
                        or p.get('Name') in GO_LOCAL_SOURCES.get(target, set())) for p in packages)
        else:
            valid = all(p.get('Name') and p.get('Version') for p in packages)
        if valid:
            targets.add(target)
    assert expected <= targets, label + ' package scan missing: ' + ', '.join(sorted(expected - targets))


def require_embedded_npm(results, label):
    # Trivy reads npm lock files only in filesystem scans. In an image it reads
    # the CycloneDX SBOM written by the frontend build; BOMRef marks its entries.
    packages = [p for result in results if result.get('Class') == 'lang-pkgs' and result.get('Type') == 'node-pkg'
                for p in result.get('Packages') or [] if (p.get('Identifier') or {}).get('BOMRef')]
    valid = packages and all(p.get('Name') and p.get('Version')
                             and str((p.get('Identifier') or {}).get('PURL', '')).startswith('pkg:npm/') for p in packages)
    assert valid, label + ' package scan missing: embedded CycloneDX npm SBOM'


def gate(d, image_name=None, asset_bom=None):
    os = d.get('Metadata', {}).get('OS', {})
    # Только Alpine: для Debian сканер показывал десятки уязвимостей высокой
    # важности без исправления, и блокировать по ним было нечем.
    results = d.get('Results', [])
    if image_name == 'assets':
        import ci_assets
        ci_assets.verify_scan(d, asset_bom or {})
    else:
        assert os.get('Family') == 'alpine' and not os.get('EOSL', False), 'unsupported/EOL operating system'
        assert any(x.get('Class') == 'os-pkgs' and x.get('Packages')
                   and all(p.get('Name') and p.get('Version') for p in x['Packages'])
                   for x in results), 'OS package scan missing'
    require_packages(results, 'rustbinary', RUST_TARGETS.get(image_name, set()), 'Rust')
    require_packages(results, 'gobinary', GO_TARGETS.get(image_name, set()) | (xray_slots() if image_name == 'xr' else set()), 'Go')
    if image_name == 'ad':
        require_embedded_npm(results, 'AdGuard frontend npm')
    blocked, unfixed, secrets, medium = [], [], [], 0
    for result in results:
        for v in result.get('Vulnerabilities') or []:
            if v.get('Severity') in ('HIGH', 'CRITICAL') and v.get('FixedVersion'):
                blocked.append((v['VulnerabilityID'], v.get('PkgName'), v.get('InstalledVersion'), v['FixedVersion']))
            elif v.get('Severity') in ('HIGH', 'CRITICAL'):
                unfixed.append((v['VulnerabilityID'], v.get('PkgName'), v.get('InstalledVersion')))
            elif v.get('Severity') == 'MEDIUM' and v.get('FixedVersion'):
                medium += 1
        # Ключ или токен, попавший в слой образа, публикуется вместе с ним.
        # Печатаем только правило и путь: само значение в журнал не выводится.
        for found in result.get('Secrets') or []:
            secrets.append((found.get('RuleID', 'unknown'), result.get('Target', '')))
    return sorted(set(blocked)), sorted(set(secrets)), sorted(set(unfixed)), medium


def main(path, asset_bom_path=None):
    asset_bom = json.loads(Path(asset_bom_path).read_text()) if asset_bom_path else None
    blocked, secrets, unfixed, medium = gate(json.loads(Path(path).read_text()), os.environ.get('IMAGE_NAME'), asset_bom)
    # Only exact vulnerability + package + installed version, and only in a run
    # that explicitly allowed waivers. Secrets are never waived.
    blocked, waived, hints = ci_waivers.split(blocked, lambda entries, row: ci_waivers.package_waiver(entries, row[0], row[1], row[2]))
    warnings = [release.warning('waiver', row[0]) for row, _entry in waived]
    for row, entry in waived:
        print('WAIVED', *row, '—', ci_waivers.describe(entry))
        ci_waivers.annotate('warning', f'Допуск с исключением: {row[0]} {row[1]} {row[2]} — {ci_waivers.describe(entry)}')
    for row, entry in hints:
        print('note waiver', row[0], row[1], row[2], '— действует только при ручном запуске с allow_waivers')
    for row in blocked:
        print('BLOCK', *row)
    for row in secrets:
        print('BLOCK secret', *row)
    for row in unfixed:
        print('note unfixed', *row)
    if waived:
        print('Security gate waivers:', len(waived), 'fixable high/critical findings admitted by scripts/ci_vuln_waivers.json')
    print('Security gate:', len(blocked), 'fixable high/critical findings;', len(secrets), 'secrets;',
          len(unfixed), 'high/critical without a fix;', medium, 'fixable medium')
    if secrets:
        return 1
    if blocked and release.policy()['allow_vulnerabilities']:
        warnings += [release.warning('vulnerability', row[0]) for row in blocked]
        blocked = []
    if not blocked and os.environ.get('CI_REPORT_FILE'):
        release.write_report('security-'+os.environ['IMAGE_NAME'], warnings, 1)
    elif warnings:
        release.announce(warnings, 'security')
    return 1 if blocked else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None))
