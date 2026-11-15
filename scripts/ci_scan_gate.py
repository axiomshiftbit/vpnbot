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
        assert any(x.get('Class') == 'os-pkgs' for x in results), 'OS package scan missing'
    if image_name == 'tt':
        # Отчёт без Rust inventory не доказывает проверку зависимостей.
        # --list-all-pkgs оставляет список и у полностью чистого бинарника.
        targets = {x.get('Target', '').lstrip('/') for x in results
                   if x.get('Class') == 'lang-pkgs' and x.get('Type') == 'rustbinary'
                   and x.get('Packages')
                   and all(p.get('Name') and p.get('Version') for p in x['Packages'])}
        expected = {'usr/local/libexec/trusttunnel_endpoint', 'usr/local/bin/setup_wizard'}
        assert expected <= targets, 'Rust package scan missing: ' + ', '.join(sorted(expected - targets))
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
