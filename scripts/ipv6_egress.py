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
        # Новые ядра используют sockopt: адаптер удаляет устаревшее поле freedom.
        # Явная небезопасная legacy-настройка не должна маскироваться sockopt.
        strategy = settings.get('domainStrategy', outbound.get('streamSettings', {}).get('sockopt', {}).get('domainStrategy'))
        if strategy != 'ForceIPv4' or not rules or rules[0].get('action') != 'block' or '::/0' not in rules[0].get('ip', []):
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
    reserved = next((item['set'].get('elem', []) for item in objects
                     if item.get('set', {}).get('name') == 'egress6_reserved'), None)
    check_forward([item['rule']['expr'] for item in objects if item.get('rule', {}).get('chain') == 'forward'],
                  interface, reserved)
    for item in objects:
        mapping = item.get('map', {})
        if mapping.get('name') == 'egress6_snat':
            for pair in mapping.get('elem', []):
                if isinstance(pair, list) and len(pair) == 2 and pair[0] == SOURCE and ipaddress.IPv6Address(pair[1]) == ipaddress.IPv6Address(public):
                    return
    raise ValueError('egress6_snat не содержит выбранный публичный IPv6')


def excludes_public_addresses(right, reserved):
    """True only if every address in this nft expression is outside the supported public range."""
    if right == '@egress6_reserved':
        if reserved is None:
            return False
        values = reserved
    else:
        values = right['set'] if isinstance(right, dict) and 'set' in right else [right]
    public = ipaddress.IPv6Network('2000::/3')
    try:
        for value in values:
            if isinstance(value, dict):
                prefix = value['prefix']
                value = (prefix['addr'], prefix['len'])
            network = ipaddress.IPv6Network(value)
            if network.overlaps(public) and not any(network.subnet_of(net) for net in RESERVED):
                return False
    except (KeyError, TypeError, ValueError):
        return False
    return True


def check_forward(rules, interface, reserved=None):
    """Verify the two paths in order; unknown earlier blocking conditions require manual review."""
    def match(left, right, op='=='):
        return {'match': {'op': op, 'left': left, 'right': right}}
    iif, oif = ({'meta': {'key': key}} for key in ('iifname', 'oifname'))
    saddr, daddr = ({'payload': {'protocol': 'ip6', 'field': field}} for field in ('saddr', 'daddr'))
    state = {'ct': {'key': 'state'}}
    established = match(state, 'established', 'in')
    public_range = match(daddr, {'prefix': {'addr': '2000::', 'len': 3}})
    def all_protocols(term):
        test = term.get('match', {})
        right = test.get('right')
        return (test.get('left') == {'meta': {'key': 'l4proto'}} and test.get('op') in ('in', '==')
                and isinstance(right, dict) and all(name in right.get('set', []) for name in ('tcp', 'udp', 'ipv6-icmp')))

    for outbound in (True, False):
        incoming, outgoing = ('br-vpnbot6', interface) if outbound else (interface, 'br-vpnbot6')
        local, remote = (saddr, daddr) if outbound else (daddr, saddr)
        required = [match(iif, incoming), match(oif, outgoing), match(local, SOURCE)]
        optional = [public_range] if outbound else [match({'ct': {'key': 'status'}}, 'seen-reply', 'in')]
        if not outbound:
            required.append(established)

        def disjoint(term):
            test = term.get('match', {})
            left, op, right = (test.get(k) for k in ('left', 'op', 'right'))
            if left in (iif, oif) and isinstance(right, str) and re.fullmatch(r'[A-Za-z0-9_.:-]+', right):
                expected = incoming if left == iif else outgoing
                return (op == '==' and right != expected) or (op == '!=' and right == expected)
            if op == '!=' and left == local and right == SOURCE:
                return True
            if left == state and op in ('in', '=='):
                states = right.get('set', []) if isinstance(right, dict) else [right]
                if states and all(isinstance(s, str) for s in states):
                    return not set(states).intersection(('new', 'established') if outbound else ('established',))
            return left == remote and op == '==' and excludes_public_addresses(right, reserved)

        for expression in rules:
            terms = [x for x in expression if 'counter' not in x and 'log' not in x]
            if not terms:
                continue
            if terms[-1] == {'accept': None}:
                conditions = terms[:-1]
                allowed = required + optional
                if all(test in conditions for test in required) and all(test in allowed or all_protocols(test) for test in conditions):
                    break
                continue
            if all(set(term) <= {'match', 'limit'} for term in terms):
                continue
            if not any(disjoint(term) for term in terms):
                raise ValueError('Предыдущее правило может закрывать IPv6 forward для контейнера Xray')
        else:
            raise ValueError('В IPv6 forward нет пропуска выделенного контейнера Xray в WAN и ответов ему')



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
