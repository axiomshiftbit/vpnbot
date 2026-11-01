#!/usr/bin/env python3
"""Optional userspace WireGuard backup, confined by the node's normal egress."""
import base64
import copy
import os
import uuid

PORT = 51820
LISTEN_PORT = 51830
ADDRESSES = ['10.77.77.2/32', 'fd42:7662:77::2/128']


def settings(value):
    if not isinstance(value, dict) or set(value)-{'enabled', 'active', 'mtu', 'keepalive'}:
        raise ValueError('invalid WireGuard settings')
    value = {'enabled': False, 'active': False, 'mtu': 1280, 'keepalive': 25} | value
    if type(value['enabled']) is not bool or type(value['active']) is not bool \
            or type(value['mtu']) is not int or not 1280 <= value['mtu'] <= 1420 \
            or type(value['keepalive']) is not int or not 0 <= value['keepalive'] <= 65535 \
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


def external(value):
    """Private per-panel keys; slots cannot overlap the controller's address."""
    if not isinstance(value, dict) or len(value) > 32:
        raise ValueError('invalid external channel identities')
    result, slots = {}, set()
    for identifier, entry in value.items():
        if not isinstance(identifier, str) or str(uuid.UUID(identifier)) != identifier \
                or not isinstance(entry, dict) or set(entry) != {'slot', 'channel', 'private', 'public', 'psk'} \
                or type(entry['slot']) is not int or not 1 <= entry['slot'] <= 32 or entry['slot'] in slots \
                or entry['channel'] not in ('wireguard', 'amnezia'):
            raise ValueError('invalid external channel identity')
        slots.add(entry['slot'])
        result[identifier] = entry | {name:key(entry[name]) for name in ('private', 'public', 'psk')}
    return result


def addresses(slot=0):
    if type(slot) is not int or not 0 <= slot <= 32:
        raise ValueError('invalid channel slot')
    return [f'10.77.77.{slot+2}/32', f'fd42:7662:77::{slot+2:x}/128']


def peer_keys(keys, entry):
    return identity(keys) | {'client_private':key(entry['private']), 'client_public':key(entry['public']), 'psk':key(entry['psk'])}


def inbound(options, address, keys, sniffing=None, external_peers=()):
    value, keys = settings(options), identity(keys)
    # A wildcard UDP listener may answer from another local address, breaking
    # conntrack's reverse DNAT (notably IPv6 REDIRECT choosing link-local).
    result = {'tag': 'node-wg6' if ':' in address else 'node-wg4', 'listen': address, 'port': LISTEN_PORT,
              'protocol': 'wireguard', 'settings': {'secretKey': keys['server_private'], 'mtu': value['mtu'],
              'peers': [{'publicKey': keys['client_public'], 'preSharedKey': keys['psk'],
                         'allowedIPs': ADDRESSES, 'email': 'controller-wg', 'keepAlive': 0}]}}
    if sniffing:
        result['sniffing'] = copy.deepcopy(sniffing)
    for entry in external_peers:
        result['settings']['peers'].append({'publicKey':key(entry['public']), 'preSharedKey':key(entry['psk']),
            'allowedIPs':addresses(entry['slot']), 'email':'external-wg-'+str(entry['slot']), 'keepAlive':0})
    return result


def outbound(options, address, keys, tag='node', family=4, slot=0):
    value, keys = settings(options), identity(keys)
    endpoint = ('['+address+']' if ':' in address else address)+':'+str(PORT)
    return {'tag': tag, 'protocol': 'wireguard', 'settings': {
        'secretKey': keys['client_private'], 'address': [addresses(slot)[family == 6]], 'mtu': value['mtu'], 'noKernelTun': True,
        'peers': [{'publicKey': keys['server_public'], 'preSharedKey': keys['psk'], 'endpoint': endpoint,
                   'allowedIPs': ['0.0.0.0/0', '::/0'], 'keepAlive': value['keepalive']}],
        'remoteDNS': ['1.1.1.1', '9.9.9.9'] if family == 4 else ['2606:4700:4700::1111', '2620:fe::fe']}}
