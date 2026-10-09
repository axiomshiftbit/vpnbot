#!/usr/bin/env python3
"""Решение о допуске образа по отчёту Trivy (JSON).

Блокируют: уязвимости HIGH и CRITICAL с известным исправлением, секреты в слоях
образа, ОС образа не Alpine или снятая с поддержки, отсутствие проверки пакетов ОС.
Уязвимости без исправления только перечисляются: обновлять пока не на что.
"""
import json
import sys


def gate(d):
    os = d.get('Metadata', {}).get('OS', {})
    # Только Alpine: для Debian сканер показывал десятки уязвимостей высокой
    # важности без исправления, и блокировать по ним было нечем.
    assert os.get('Family') == 'alpine' and not os.get('EOSL', False), 'unsupported/EOL operating system'
    results = d.get('Results', [])
    assert any(x.get('Class') == 'os-pkgs' for x in results), 'OS package scan missing'
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


def main(path):
    blocked, secrets, unfixed, medium = gate(json.load(open(path)))
    for row in blocked:
        print('BLOCK', *row)
    for row in secrets:
        print('BLOCK secret', *row)
    for row in unfixed:
        print('note unfixed', *row)
    print('Security gate:', len(blocked), 'fixable high/critical findings;', len(secrets), 'secrets;',
          len(unfixed), 'high/critical without a fix;', medium, 'fixable medium')
    return 1 if blocked or secrets else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
