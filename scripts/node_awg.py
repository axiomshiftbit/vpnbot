#!/usr/bin/env python3
"""Versioned AmneziaWG carrier for the existing VLESS listener, without host TUN."""
import base64
import ipaddress
import os
import re
import secrets

import node_wg
import node_dpi

SIGNATURE_FIELDS = {'I1','I2','I3','I4','I5'}


def signature(value):
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError('invalid Amnezia signature')
    if value == '':
        return
    if not re.fullmatch(r'(?:<b 0x[0-9a-fA-F]+>|<r [0-9]{1,4}>|<rc [0-9]{1,4}>|<rd [0-9]{1,4}>|<t>)+', value) or value.count('<t>') > 1:
        raise ValueError('invalid Amnezia signature')
    for count in re.findall(r'<(?:r|rc|rd) ([0-9]+)>', value):
        if int(count) > 1000:
            raise ValueError('Amnezia signature random field exceeds limit')
    node_dpi.expression(value)


PORT, LISTEN_PORT = 51821, 51831
SERVER, CLIENT = '10.77.78.1', '10.77.78.2'
CLIENT_PORT = 10920
KEY_FIELDS = {'server_private', 'server_public', 'client_private', 'client_public', 'psk'}
INTEGER_FIELDS = {'Jc': (0, 10), 'Jmin': (64, 1024), 'Jmax': (64, 1024),
                  'S1': (12, 64), 'S2': (12, 64), 'S3': (12, 64), 'S4': (12, 32)}
RANGE_FIELDS = {'ContentPaddingAddition': (10, 40), 'RekeyAfterTime': (110, 130),
                'RekeyTimeout': (5, 10), 'RejectAfterTime': (170, 190),
                'KeepaliveTimeout': (10, 15), 'MaxHandshakeAttempts': (15, 25)}


VERSIONS = ('1.5', '2.0', '3.0', '3.1')


def protocol(value):
    if not isinstance(value, str) or value not in VERSIONS:
        raise ValueError('invalid Amnezia protocol version')
    return value


def fields(version):
    protocol(version)
    integers = dict(INTEGER_FIELDS)
    if version in ('1.5', '2.0'):
        integers = {name: (0 if name.startswith('S') else low, high) for name, (low, high) in integers.items()}
    if version == '1.5':
        for name in ('S3', 'S4'): integers.pop(name)
    ranges = dict(RANGE_FIELDS) if version.startswith('3.') else {}
    ranges.update({name: (1, 2**32-1 if version == '1.5' else 2**31-1) for name in ('H1', 'H2', 'H3', 'H4')})
    return integers, ranges


def settings(value):
    if not isinstance(value, dict):
        raise ValueError('invalid Amnezia settings')
    version = protocol(value.get('version', '3.1'))
    integers, ranges = fields(version)
    common = node_wg.settings({k:v for k,v in value.items() if k not in ('parameters', 'keepalive', 'template', 'rotation_days', 'generated_at', 'version')})
    metadata = {key: value[key] for key in ('template', 'rotation_days', 'generated_at', 'version') if key in value}
    templates = ('classic_1',) if version == '1.5' else tuple(name+('_2' if version == '2.0' else '_3') for name in ('standard', 'aggressive', 'mobile'))
    if 'template' in metadata and metadata['template'] not in templates:
        raise ValueError('invalid Amnezia template')
    if 'rotation_days' in metadata and (type(metadata['rotation_days']) is not int or metadata['rotation_days'] not in (0, 1, 3, 7, 14, 30)):
        raise ValueError('invalid Amnezia generation interval')
    if 'generated_at' in metadata and (type(metadata['generated_at']) is not int or not 0 <= metadata['generated_at'] <= 2147483647):
        raise ValueError('invalid Amnezia generation time')
    keepalive = value.get('keepalive', '20-25' if version.startswith('3.') else '25')
    if not isinstance(keepalive, str) or not re.fullmatch(r'[0-9]{1,5}(?:-[0-9]{1,5})?', keepalive):
        raise ValueError('invalid Amnezia keepalive')
    limits = list(map(int, keepalive.split('-')))
    if not 0 <= limits[0] <= limits[-1] <= 65535 or (not version.startswith('3.') and len(limits) != 1):
        raise ValueError('invalid Amnezia keepalive')
    params = value.get('parameters', {})
    if not isinstance(params, dict) or set(params)-set(integers)-set(ranges)-SIGNATURE_FIELDS:
        raise ValueError('unsupported Amnezia setting')
    params = dict(params)
    for name, item in params.items():
        if name in SIGNATURE_FIELDS:
            signature(item)
        elif name in integers:
            low, high = integers[name]
            if type(item) is not int or not low <= item <= high:
                raise ValueError('invalid Amnezia padding')
        else:
            if version == '1.5' and name.startswith('H'):
                if type(item) is int: item = str(item)
                if not isinstance(item, str) or not re.fullmatch(r'[0-9]{1,10}', item) or not 1 <= int(item) <= 2**32-1:
                    raise ValueError('Amnezia 1.5 requires fixed headers')
                params[name] = item
                continue
            if isinstance(item, str) and re.fullmatch(r'[0-9]{1,10}', item):
                item = item+'-'+item
                params[name] = item
            if not isinstance(item, str) or not re.fullmatch(r'[0-9]{1,10}-[0-9]{1,10}', item):
                raise ValueError('invalid Amnezia range')
            left, right = map(int, item.split('-'))
            low, high = ranges[name]
            if not low <= left <= right <= high:
                raise ValueError('invalid Amnezia range')
    return common | metadata | {'keepalive': keepalive, 'parameters': dict(params)}


def parameters(value, version='3.1'):
    integers, ranges = fields(version)
    required = set(integers) | set(ranges) | ({'HeaderProtectionKey'} if version.startswith('3.') else set())
    if not isinstance(value, dict) or set(value)-SIGNATURE_FIELDS != required:
        raise ValueError('invalid Amnezia parameters')
    normalized = settings({'version': version, 'parameters': {k:v for k,v in value.items() if k != 'HeaderProtectionKey'}})['parameters']
    sizes = [normalized.get('S'+str(n), 0)+size for n, size in enumerate((148, 92, 64, 32), 1)]
    if normalized['Jmin'] > normalized['Jmax'] or normalized['S1'] == normalized['S2'] or len(set(sizes)) != 4:
        raise ValueError('incompatible Amnezia packet sizes')
    headers = []
    for name in ('H1', 'H2', 'H3', 'H4'):
        limits = list(map(int, normalized[name].split('-')))
        left, right = limits[0], limits[-1]
        if any(left <= b and a <= right for a, b in headers):
            raise ValueError('overlapping Amnezia headers')
        headers.append((left, right))
    if version.startswith('3.'):
        node_wg.key(value['HeaderProtectionKey'])
        normalized['HeaderProtectionKey'] = value['HeaderProtectionKey']
    return normalized


def effective(options, keys):
    version = options.get('version', '3.1')
    integers, ranges = fields(version)
    allowed = set(integers) | set(ranges) | SIGNATURE_FIELDS | ({'HeaderProtectionKey'} if version.startswith('3.') else set())
    value = {k:v for k,v in keys['parameters'].items() if k in allowed}
    if version == '1.5':
        for name in ('H1', 'H2', 'H3', 'H4'): value[name] = value[name].split('-')[0]
    return parameters(value | options['parameters'], version)


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


def profile(options, address, keys, slot=0):
    options, keys = settings(options), identity(keys)
    node_wg.addresses(slot)
    return {'endpoint': address, 'port': PORT, 'private': keys['client_private'], 'public': keys['server_public'],
            'psk': keys['psk'], 'mtu': options['mtu'], 'keepalive': options['keepalive'], 'version': options.get('version', '3.1'),
            'slot': slot, 'parameters': effective(options, keys)}


def validate_client(value):
    if not isinstance(value, dict) or set(value)-{'keepalive', 'version', 'slot'} != {'endpoint', 'port', 'private', 'public', 'psk', 'mtu', 'parameters'}:
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
    version = protocol(value.get('version', '3.1'))
    node_wg.addresses(value.get('slot', 0))
    settings({'version': version, 'mtu': value['mtu'], 'keepalive': value.get('keepalive', '20-25' if version.startswith('3.') else '25')})
    for name in ('private', 'public', 'psk'):
        node_wg.key(value[name])
    parameters(value['parameters'], version)
    return value


def common(private, mtu, params, version='3.1'):
    lines = ['PrivateKey = '+node_wg.key(private), 'MTU = '+str(mtu)]
    lines += [str(name)+' = '+str(item) for name, item in sorted(parameters(params, version).items()) if item != '']
    # amneziawg-go#186: broad handshake headers can misclassify data with
    # random trailers. Use the same safe value on the server and every client.
    trailers = version == '3.1' and all(len(set(str(params[k]).split('-'))) == 1 for k in ('H1', 'H2', 'H3'))
    return '\n'.join(lines)+ '\nRandomTrailers = '+('on' if trailers else 'off')+'\nDisableCookies = off\n'


def server(options, keys, external_peers=()):
    options, keys = settings(options), identity(keys)
    peers = ('[Peer]\nPublicKey = '+keys['client_public']+'\nPresharedKey = '+keys['psk']+'\nAllowedIPs = '+CLIENT+'/32\n')
    for entry in external_peers:
        node_wg.addresses(entry['slot'])
        peers += ('[Peer]\nPublicKey = '+node_wg.key(entry['public'])+'\nPresharedKey = '+node_wg.key(entry['psk'])
                  +'\nAllowedIPs = 10.77.78.'+str(entry['slot']+2)+'/32\n')
    return ('[Interface]\nAddress = '+SERVER+'/32\nListenPort = '+str(LISTEN_PORT)+'\n'
            +common(keys['server_private'], options['mtu'], effective(options, keys), options.get('version', '3.1'))
            +peers+'[TCPServerTunnel]\nListenPort = 443\nTarget = 127.0.0.1:8443\n')


def client(value, index):
    value = validate_client(value)
    if type(index) is not int or not 0 <= index < 8:
        raise ValueError('invalid Amnezia slot')
    address = '['+value['endpoint']+']' if ':' in value['endpoint'] else value['endpoint']
    return ('[Interface]\nAddress = 10.77.78.'+str(value.get('slot',0)+2)+'/32\n'+common(value['private'], value['mtu'], value['parameters'], value.get('version', '3.1'))
            +'[Peer]\nPublicKey = '+value['public']+'\nPresharedKey = '+value['psk']
            +'\nAllowedIPs = '+SERVER+'/32\nEndpoint = '+address+':'+str(value['port'])
            +'\nPersistentKeepalive = '+value.get('keepalive', '20-25' if value.get('version', '3.1').startswith('3.') else '25')+'\n[TCPClientTunnel]\nBindAddress = 127.0.0.1:'+str(CLIENT_PORT+index)
            +'\nTarget = '+SERVER+':443\n')
