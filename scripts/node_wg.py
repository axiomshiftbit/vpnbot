#!/usr/bin/env python3
"""Optional userspace WireGuard backup, confined by the node's normal egress."""
import base64
import copy
import os

PORT = 51820
LISTEN_PORT = 51830
ADDRESSES = ['10.77.77.2/32', 'fd42:7662:77::2/128']


def settings(value):
    if not isinstance(value, dict) or set(value)-{'enabled', 'active', 'mtu'}:
        raise ValueError('invalid WireGuard settings')
    value = {'enabled': False, 'active': False, 'mtu': 1280} | value
    if type(value['enabled']) is not bool or type(value['active']) is not bool \
            or type(value['mtu']) is not int or not 1280 <= value['mtu'] <= 1420 \
            or value['active'] and not value['enabled']:
        raise ValueError('incompatible WireGuard settings')
    return value


def key(value):
    if not isinstance(value, str) or len(value) != 44:
        raise ValueError('invalid WireGuard key')
    raw = base64.b64decode(value, validate=True)
    if len(raw) != 32 or base64.b64encode(raw).decode() != value or raw == b'\x00'*32:
        raise ValueError('invalid WireGuard key')
    return value


def identity(value):
    fields = {'server_private', 'server_public', 'client_private', 'client_public', 'psk'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('invalid WireGuard identity')
    return {name: key(item) for name, item in value.items()}


def generate(pair):
    result = {}
    for side in ('server', 'client'):
        value = pair()
        for name in ('private', 'public'):
            result[side+'_'+name] = base64.b64encode(base64.urlsafe_b64decode(value[name]+'=')).decode()
    result['psk'] = base64.b64encode(os.urandom(32)).decode()
    return identity(result)


def inbound(options, address, keys, sniffing=None):
    value, keys = settings(options), identity(keys)
    # A wildcard UDP listener may answer from another local address, breaking
    # conntrack's reverse DNAT (notably IPv6 REDIRECT choosing link-local).
    result = {'tag': 'node-wg6' if ':' in address else 'node-wg4', 'listen': address, 'port': LISTEN_PORT,
              'protocol': 'wireguard', 'settings': {'secretKey': keys['server_private'], 'mtu': value['mtu'],
              'peers': [{'publicKey': keys['client_public'], 'preSharedKey': keys['psk'],
                         'allowedIPs': ADDRESSES, 'email': 'controller-wg', 'keepAlive': 0}]}}
    if sniffing:
        result['sniffing'] = copy.deepcopy(sniffing)
    return result


def outbound(options, address, keys, tag='node', family=4):
    value, keys = settings(options), identity(keys)
    endpoint = ('['+address+']' if ':' in address else address)+':'+str(PORT)
    return {'tag': tag, 'protocol': 'wireguard', 'settings': {
        'secretKey': keys['client_private'], 'address': [ADDRESSES[family == 6]], 'mtu': value['mtu'], 'noKernelTun': True,
        'peers': [{'publicKey': keys['server_public'], 'preSharedKey': keys['psk'], 'endpoint': endpoint,
                   'allowedIPs': ['0.0.0.0/0', '::/0'], 'keepAlive': 25}],
        'remoteDNS': ['1.1.1.1', '9.9.9.9'] if family == 4 else ['2606:4700:4700::1111', '2620:fe::fe']}}
