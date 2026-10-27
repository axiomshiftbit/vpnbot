#!/usr/bin/env python3
"""Подготовить opt-in сеть Xray после настройки IPv6 и nftables на хосте."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

SOURCE = 'fd42:7662:6::9'
RESERVED = tuple(map(ipaddress.IPv6Network, ('2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20')))


def validate(value):
    if not isinstance(value, dict) or value.get('enabled') is not True:
        raise ValueError('IPv6 egress must be explicitly enabled')
    public = value.get('public', '')
    if not isinstance(public, str) or '%' in public:
        raise ValueError('IPv6 must be an unscoped address string')
    address = ipaddress.IPv6Address(public)
    if not address.is_global or address not in ipaddress.IPv6Network('2000::/3') or any(address in net for net in RESERVED):
        raise ValueError('A global unicast IPv6 address is required')
    interface = value.get('interface', '')
    if not isinstance(interface, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', interface):
        raise ValueError('Invalid WAN interface')
    return {'enabled': True, 'public': str(address), 'interface': interface}


def check_xray(root):
    # Только проверяем; не печатаем конфигурацию с учётными данными клиентов.
    config = json.loads((Path(root) / 'config/xray.json').read_text())
    checked = False
    for index, outbound in enumerate(config.get('outbounds', [])):
        if outbound.get('protocol') != 'freedom' or (index != 0 and outbound.get('tag') != 'direct'):
            continue
        settings = outbound.get('settings', {})
        rules = settings.get('finalRules', [])
        if settings.get('domainStrategy') != 'ForceIPv4' or not rules or rules[0].get('action') != 'block' or '::/0' not in rules[0].get('ip', []):
            raise ValueError('Сначала добавьте в боте «IPv6 этого сервера»: обычный выход ещё не защищён от смены семейства адресов')
        checked = True
    if not checked:
        raise ValueError('Не найден защищённый обычный выход Xray')


def check_firewall(public, interface):
    result = subprocess.run(['nft', '-j', 'list', 'table', 'ip6', 'filter'], check=True, capture_output=True, text=True)
    objects = json.loads(result.stdout).get('nftables', [])
    chains = {item['chain']['name']: item['chain'] for item in objects if 'chain' in item}
    expected = {
        'input': ('filter', 'input', 0, 'drop'),
        'forward': ('filter', 'forward', 0, 'drop'),
        'postrouting': ('nat', 'postrouting', 100, 'accept'),
        'egress_guard': ('filter', 'postrouting', 110, 'accept'),
    }
    if any(tuple(chains.get(name, {}).get(field) for field in ('type', 'hook', 'prio', 'policy')) != shape for name, shape in expected.items()):
        raise ValueError('Сначала загрузите адаптированный IPv6 firewall с закрытыми input/forward и egress_guard')
    def match(left, right):
        return {'match': {'op': '==', 'left': left, 'right': right}}
    source = {'payload': {'protocol': 'ip6', 'field': 'saddr'}}
    wan = match({'meta': {'key': 'oifname'}}, interface)
    required = {
        'postrouting': [wan, match(source, SOURCE), {'snat': {'addr': {'map': {'key': source, 'data': '@egress6_snat'}}}}],
        'egress_guard': [wan, match(source, {'prefix': {'addr': 'fc00::', 'len': 7}}), {'drop': None}],
    }
    for name, expression in required.items():
        rules = [[e for e in item['rule']['expr'] if 'counter' not in e]
                 for item in objects if item.get('rule', {}).get('chain') == name]
        if rules != [expression]:
            raise ValueError('Отсутствует штатная защита SNAT/ULA для выбранного WAN: ' + name)
    for item in objects:
        mapping = item.get('map', {})
        if mapping.get('name') == 'egress6_snat':
            for pair in mapping.get('elem', []):
                if isinstance(pair, list) and len(pair) == 2 and pair[0] == SOURCE and ipaddress.IPv6Address(pair[1]) == ipaddress.IPv6Address(public):
                    return
    raise ValueError('egress6_snat не содержит выбранный публичный IPv6')


def prepare(root, value):
    value = validate(value)
    interface, public = value['interface'], value['public']
    result = subprocess.run(['ip', '-j', '-6', 'addr', 'show', 'dev', interface], check=True, capture_output=True, text=True)
    addresses = [a for link in json.loads(result.stdout) for a in link.get('addr_info', [])]
    if not any(a.get('local') == public and not a.get('tentative') and not a.get('dadfailed') for a in addresses):
        raise ValueError('The chosen IPv6 is not ready on the WAN interface')
    route = subprocess.run(['ip', '-6', 'route', 'show', 'default', 'dev', interface], check=True, capture_output=True, text=True)
    if not route.stdout.strip():
        raise ValueError('No IPv6 default route on the WAN interface')
    if Path('/proc/sys/net/ipv6/conf/all/forwarding').read_text().strip() != '1':
        raise ValueError('IPv6 forwarding is not enabled on the host')
    check_xray(root)
    check_firewall(public, interface)
    root = Path(root)
    path = root / 'config/ipv6-egress.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.ipv6-egress-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prepare')
    p.add_argument('--public', required=True)
    p.add_argument('--interface', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    prepare(root, {'enabled': True, 'public': args.public, 'interface': args.interface})
    print('Подготовка IPv6 завершена. Пересоздайте xr штатной командой vpnbot и повторите проверку узла в боте.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit('IPv6 preparation failed: ' + str(error))
