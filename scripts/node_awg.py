#!/usr/bin/env python3
"""AmneziaWG 3.1 carrier for the existing VLESS listener, without host TUN."""
import base64
import ipaddress
import os
import re
import secrets

import node_wg

PORT, LISTEN_PORT = 51821, 51831
SERVER, CLIENT = '10.77.78.1', '10.77.78.2'
CLIENT_PORT = 10920
KEY_FIELDS = {'server_private', 'server_public', 'client_private', 'client_public', 'psk'}
INTEGER_FIELDS = {'Jc': (0, 10), 'Jmin': (64, 1024), 'Jmax': (64, 1024),
                  'S1': (12, 64), 'S2': (12, 64), 'S3': (12, 64), 'S4': (12, 32)}
RANGE_FIELDS = {'ContentPaddingAddition': (10, 40), 'RekeyAfterTime': (110, 130),
                'RekeyTimeout': (5, 10), 'RejectAfterTime': (170, 190),
                'KeepaliveTimeout': (10, 15), 'MaxHandshakeAttempts': (15, 25)}


def settings(value):
    # Same bounded enable/active/MTU model as the existing WireGuard reserve.
    return node_wg.settings(value)


def parameters(value):
    fields = set(INTEGER_FIELDS) | set(RANGE_FIELDS) | {'H1', 'H2', 'H3', 'H4', 'HeaderProtectionKey'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('invalid Amnezia parameters')
    for name, (low, high) in INTEGER_FIELDS.items():
        if type(value[name]) is not int or not low <= value[name] <= high:
            raise ValueError('invalid Amnezia padding')
    # Packet lengths must remain distinguishable; HPK requires >=12 bytes.
    sizes = [value['S'+str(n)]+size for n, size in enumerate((148, 92, 64, 32), 1)]
    if value['Jmin'] > value['Jmax'] or value['S1'] == value['S2'] or len(set(sizes)) != 4:
        raise ValueError('incompatible Amnezia packet sizes')
    headers = []
    for name in list(RANGE_FIELDS) + ['H1', 'H2', 'H3', 'H4']:
        if not isinstance(value[name], str) or not re.fullmatch(r'[0-9]{1,10}-[0-9]{1,10}', value[name]):
            raise ValueError('invalid Amnezia range')
        left, right = map(int, value[name].split('-'))
        low, high = RANGE_FIELDS.get(name, (1, 2**31-1))
        if not low <= left <= right <= high:
            raise ValueError('invalid Amnezia range')
        if name.startswith('H'):
            if any(left <= b and a <= right for a, b in headers):
                raise ValueError('overlapping Amnezia headers')
            headers.append((left, right))
    node_wg.key(value['HeaderProtectionKey'])
    return dict(value)


def generate(pair):
    def rand(low, high):
        return low+secrets.randbelow(high-low+1)

    # Bounds match the full bot's standard_3 profile. Signature packets are
    # deliberately optional; AWG 3.1 still uses randomized headers and padding.
    while True:
        padding = {name: rand(*bounds) for name, bounds in INTEGER_FIELDS.items() if name.startswith('S')}
        if padding['S1'] != padding['S2'] and len({padding['S'+str(n)]+size for n, size in enumerate((148, 92, 64, 32), 1)}) == 4:
            break
    params = padding | {'Jc': rand(3, 10), 'Jmin': 64, 'Jmax': 1024,
                        'HeaderProtectionKey': base64.b64encode(os.urandom(32)).decode()}
    segments = [(0x01000000, 0x1fffffff), (0x20000000, 0x3fffffff), (0x40000000, 0x5fffffff), (0x60000000, 0x7fffffff)]
    secrets.SystemRandom().shuffle(segments)
    for n, (low, high) in enumerate(segments, 1):
        width = rand(5000000, 50000000)
        start = rand(low, high-width)
        params['H'+str(n)] = f'{start}-{start+width}'
    for name, (low, high) in RANGE_FIELDS.items():
        params[name] = f'{low}-{high}'
    return node_wg.generate(pair) | {'parameters': parameters(params)}


def identity(value):
    if not isinstance(value, dict) or set(value) != KEY_FIELDS | {'parameters'}:
        raise ValueError('invalid Amnezia identity')
    return node_wg.identity({k: value[k] for k in KEY_FIELDS}) | {'parameters': parameters(value['parameters'])}


def profile(options, address, keys):
    options, keys = settings(options), identity(keys)
    return {'endpoint': address, 'port': PORT, 'private': keys['client_private'], 'public': keys['server_public'],
            'psk': keys['psk'], 'mtu': options['mtu'], 'parameters': keys['parameters']}


def validate_client(value):
    if not isinstance(value, dict) or set(value) != {'endpoint', 'port', 'private', 'public', 'psk', 'mtu', 'parameters'}:
        raise ValueError('invalid Amnezia client')
    if not isinstance(value['endpoint'], str):
        raise ValueError('invalid Amnezia endpoint')
    address = ipaddress.ip_address(value['endpoint'])
    if not address.is_global or address.is_multicast or '%' in value['endpoint'] \
            or (address.version == 6 and (address not in ipaddress.ip_network('2000::/3')
            or any(address in ipaddress.ip_network(n) for n in ('2001::/23', '2002::/16', '3fff::/20')))):
        raise ValueError('public Amnezia endpoint required')
    if type(value['port']) is not int or value['port'] != PORT:
        raise ValueError('invalid Amnezia port')
    settings({'mtu': value['mtu']})
    for name in ('private', 'public', 'psk'):
        node_wg.key(value[name])
    parameters(value['parameters'])
    return value


def common(private, mtu, params):
    lines = ['PrivateKey = '+node_wg.key(private), 'MTU = '+str(mtu)]
    lines += [str(name)+' = '+str(item) for name, item in sorted(parameters(params).items())]
    return '\n'.join(lines)+ '\nRandomTrailers = on\nDisableCookies = off\n'


def server(options, keys):
    options, keys = settings(options), identity(keys)
    return ('[Interface]\nAddress = '+SERVER+'/32\nListenPort = '+str(LISTEN_PORT)+'\n'
            +common(keys['server_private'], options['mtu'], keys['parameters'])
            +'[Peer]\nPublicKey = '+keys['client_public']+'\nPresharedKey = '+keys['psk']
            +'\nAllowedIPs = '+CLIENT+'/32\n[TCPServerTunnel]\nListenPort = 443\nTarget = 127.0.0.1:8443\n')


def client(value, index):
    value = validate_client(value)
    if type(index) is not int or not 0 <= index < 8:
        raise ValueError('invalid Amnezia slot')
    address = '['+value['endpoint']+']' if ':' in value['endpoint'] else value['endpoint']
    return ('[Interface]\nAddress = '+CLIENT+'/32\n'+common(value['private'], value['mtu'], value['parameters'])
            +'[Peer]\nPublicKey = '+value['public']+'\nPresharedKey = '+value['psk']
            +'\nAllowedIPs = '+SERVER+'/32\nEndpoint = '+address+':'+str(value['port'])
            +'\nPersistentKeepalive = 20-25\n[TCPClientTunnel]\nBindAddress = 127.0.0.1:'+str(CLIENT_PORT+index)
            +'\nTarget = '+SERVER+':443\n')
