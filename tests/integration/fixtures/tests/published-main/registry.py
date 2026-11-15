"""Явный список запускаемых fixtures; новый файл требует классификации."""
from pathlib import Path
import re

CASES = (
    'wireguard', 'wireguard_extra', 'openvpn', 'openvpn_extra', 'ikev2', 'l2tp',
    'openconnect', 'adguard', 'shadowsocks', 'proxies', 'trusttunnel_native',
    'xdrive_native', 'dat_routes', 'routes_cores', 'exit_nodes', 'reality_fingerprints',
    'naive_native', 'dnstt', 'dnstt_identity', 'hysteria_extra', 'warp_network',
    'telemt', 'telemt_web', 'panel', 'ssh_host_keys', 'mptcp_listeners', 'managed_sync_failure', 'service_lifecycle',
    'classic_proxy_apply', 'protocol_regressions',
)
# Эти модули поддерживают сценарии, но не запускаются как отдельные тесты.
HELPERS = {'run', 'registry', 'proxy_helpers'}


def load_cases(base):
    if not CASES or len(set(CASES)) != len(CASES) or any(
            not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', name) for name in CASES):
        raise ValueError('invalid native case registry')
    actual = {p.stem for p in Path(base).glob('*.py')}
    if actual != set(CASES) | HELPERS or set(CASES) & HELPERS:
        raise ValueError('missing or unregistered native fixture')
    return list(CASES)


def validate_results(rows, expected):
    if not isinstance(rows, list) or len(rows) != len(expected) or any(not isinstance(r, dict) for r in rows):
        raise ValueError('incomplete native results')
    if {r.get('case') for r in rows} != set(expected):
        raise ValueError('missing or duplicate native result')
    if any(type(r.get('exit')) is not int or r['exit'] != 0
           or type(r.get('total')) is not int or r['total'] <= 0
           or type(r.get('passed')) is not int or r['passed'] != r['total'] for r in rows):
        raise ValueError('failed or incomplete native fixture')
    return True
