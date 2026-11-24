"""Required post-restore checks for the optional native clients."""

CLIENTS = {
    'anytls': ('singbox', 'mihomo'),
    'mieru': ('native', 'native-previous', 'native-3.38.1', 'mihomo'),
    'tuic': ('singbox', 'mihomo'),
    'shadowtls': ('singbox', 'mihomo'),
}


def expected_checks():
    names = set()
    for protocol, clients in CLIENTS.items():
        checks = ['restored-profile-HTTP', 'restored-profile-HTTPS', 'internal-network-isolated']
        if protocol == 'mieru':
            checks.append('restored-profile-UDP')
        names.update(f'{protocol}/{client}/{check}' for client in clients for check in checks)
    for http in ('h2', 'h3'):
        names.update((f'masque/{http}/restored-profile-TCP', f'masque/{http}/internal-network-isolated'))
    names.update('snolc/' + check for check in ('restored-profile-installs-offline', 'restored-profile-TCP',
                                               'restored-profile-UDP', 'internal-network-isolated'))
    return names


def complete(rows):
    required = expected_checks()
    return (isinstance(rows, list) and len(rows) == len(required)
            and all(isinstance(row, dict) and row.get('ok') is True and isinstance(row.get('name'), str)
                    for row in rows)
            and {row['name'] for row in rows} == required)
