#!/usr/bin/env python3
"""Typed VLESS/REALITY/SMUX options shared by node server and exported clients."""
import base64
import copy
import re
import node_dpi


DEFAULTS = {
    'fingerprint': 'chrome',
    'encryption': {'auth': 'off', 'mode': 'native'},
    'reality': {'mldsa': False, 'requireMlkem': False, 'maxTimeDiff': 0,
                'minClientVer': '0.0.0', 'maxClientVer': '', 'xver': 0, 'spiderX': ''},
    'smux': {'enabled': False, 'protocol': 'smux', 'max_connections': 3, 'min_streams': 4,
             'max_streams': 0, 'padding': True, 'only_tcp': False, 'half_close': 'off',
             'h2mux_frame': 0, 'brutal': {'enabled': False, 'up': '100 Mbps', 'down': '100 Mbps'}},
    'xhttp': {'mode': 'auto', 'mux': False},
    'finalmask': {'fragment': node_dpi.FRAGMENT, 'noise': node_dpi.NOISE},
    'dpi': {'fragment': node_dpi.FRAGMENT, 'noise': node_dpi.NOISE},
    'sniffing': node_dpi.SNIFFING,
    'block_torrent': False,
}


def merge(value, defaults):
    if not isinstance(value, dict) or set(value)-set(defaults):
        raise ValueError('unsupported Xray option')
    result = copy.deepcopy(defaults)
    for key, item in value.items():
        if isinstance(defaults[key], dict):
            result[key] = merge(item, defaults[key])
        else:
            if type(item) is not type(defaults[key]):
                raise ValueError('invalid Xray option type')
            result[key] = item
    return result


def bounded(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('Xray option outside permitted range')


def rate(value):
    match = re.fullmatch(r'([1-9][0-9]{0,5}) (Kbps|Mbps|Gbps)', value)
    if not match:
        raise ValueError('invalid Brutal rate')
    bits = int(match[1])*{'Kbps': 1000, 'Mbps': 1000000, 'Gbps': 1000000000}[match[2]]
    # The fork measures the minimum in bytes/s, the UI rates are bits/s.
    if not 65536*8 <= bits <= 100000000000:
        raise ValueError('Brutal rate outside permitted range')
    return value


def settings(value, core, transport):
    result = merge(value, DEFAULTS)
    if result['fingerprint'] not in ('chrome', 'firefox', 'safari', 'ios', 'edge', 'qq', 'random', 'randomized', 'android', '360'):
        raise ValueError('unsupported fingerprint')
    enc, reality, smux, xhttp = (result[key] for key in ('encryption', 'reality', 'smux', 'xhttp'))
    if enc['auth'] not in ('off', 'x25519', 'mlkem768') or enc['mode'] not in ('native', 'xorpub', 'random'):
        raise ValueError('unsupported VLESS encryption')
    bounded(reality['maxTimeDiff'], 0, 86400000)
    bounded(reality['xver'], 0, 2)
    for key in ('minClientVer', 'maxClientVer'):
        if reality[key] and not re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}', reality[key]):
            raise ValueError('invalid Reality client version')
    if len(reality['spiderX']) > 256 or any(ord(c) < 32 or ord(c) > 126 for c in reality['spiderX']):
        raise ValueError('invalid Reality spider path')
    if reality['requireMlkem'] and core != 'fork':
        raise ValueError('configurable ML-KEM requirement is fork-only')
    if smux['protocol'] not in ('smux', 'h2mux') or smux['half_close'] not in ('off', 'auto', 'require'):
        raise ValueError('unsupported SMUX protocol or half-close mode')
    for key in ('max_connections', 'min_streams', 'max_streams'):
        bounded(smux[key], 0, 4096)
    if smux['h2mux_frame'] != 0:
        bounded(smux['h2mux_frame'], 16384, 16777215)
    rate(smux['brutal']['up'])
    rate(smux['brutal']['down'])
    if smux['enabled'] and (core != 'fork' or (smux['protocol'] == 'h2mux' and smux['half_close'] != 'off')):
        raise ValueError('SMUX options incompatible with selected core or protocol')
    if xhttp['mode'] not in ('auto', 'packet-up', 'stream-up', 'stream-one'):
        raise ValueError('unsupported XHTTP mode')
    if xhttp['mux'] and (core != 'fork' or transport != 'xhttp'):
        raise ValueError('XHTTP Mux.Cool requires the fork and XHTTP')
    if transport == 'reality':
        # The original versions bundled as origin/origin2 require hybrid ML-KEM.
        # origin3 and the fork without requireMlkem accept other TLS 1.3 samples.
        if result['fingerprint'] in ('android', '360') or ((core in ('origin', 'origin2') or reality['requireMlkem'])
                and result['fingerprint'] not in ('chrome', 'firefox', 'safari')):
            raise ValueError('fingerprint incompatible with Reality ML-KEM requirements')
    for field in ('finalmask', 'dpi'):
        node_dpi.mask(result[field])
        if core == 'origin3' and result[field]['noise']['enabled'] and any(p['type'] == 'exp' for p in result[field]['noise']['list']):
            raise ValueError('noise expressions require Xray 26.9.30 or newer')
    node_dpi.sniffing(result['sniffing'], result['block_torrent'])
    return result


def raw_key(value, length):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise ValueError('invalid key encoding')
    data = base64.urlsafe_b64decode(value+'='*((-len(value)) % 4))
    if len(data) != length or base64.urlsafe_b64encode(data).decode().rstrip('=') != value:
        raise ValueError('invalid key length or encoding')
    return value


def encryption_identity(value):
    if not isinstance(value, dict) or set(value) != {'auth', 'encryption', 'decryption'} \
            or not isinstance(value['auth'], str) or value['auth'] not in ('x25519', 'mlkem768'):
        raise ValueError('invalid encryption identity')
    lengths = {'x25519': (32, 32), 'mlkem768': (64, 1184)}[value['auth']]
    for index, (field, time) in enumerate((('decryption', '600s'), ('encryption', '0rtt'))):
        prefix = 'mlkem768x25519plus.native.'+time+'.'
        if not isinstance(value[field], str) or not value[field].startswith(prefix):
            raise ValueError('invalid VLESS encryption key')
        raw_key(value[field][len(prefix):], lengths[index])
    return dict(value)


def mldsa_identity(value):
    if not isinstance(value, dict) or set(value) != {'seed', 'verify'}:
        raise ValueError('invalid ML-DSA identity')
    return {'seed': raw_key(value['seed'], 32), 'verify': raw_key(value['verify'], 1952)}


def encryption_pair(options, keys):
    enc = options['encryption']
    if enc['auth'] == 'off':
        return {'encryption': 'none', 'decryption': 'none'}
    pair = encryption_identity(keys.get('encryption'))
    if pair['auth'] != enc['auth']:
        raise ValueError('VLESS encryption keys do not match settings')
    return {field: pair[field].replace('.native.', '.'+enc['mode']+'.') for field in ('encryption', 'decryption')}


def parse_encryption_output(output, auth):
    for label, decrypt, encrypt in re.findall(r'^Authentication: (X25519|ML-KEM-768)[^\r\n]*\r?\n'
            r'"decryption": "([^"\r\n]+)"\r?\n"encryption": "([^"\r\n]+)"', output, re.M):
        selected = 'x25519' if label == 'X25519' else 'mlkem768'
        if selected == auth:
            return encryption_identity({'auth': auth, 'decryption': decrypt, 'encryption': encrypt})
    raise ValueError('core did not generate the requested encryption identity')


def smux_client(settings):
    maximum = settings['max_streams']
    result = dict(enabled=True, protocol=settings['protocol'], maxStreams=maximum,
                  maxConnections=0 if maximum else settings['max_connections'],
                  minStreams=0 if maximum else settings['min_streams'],
                  padding=settings['padding'], onlyTcp=settings['only_tcp'])
    if settings['protocol'] == 'smux' and settings['half_close'] != 'off':
        result['logicalHalfClose'] = settings['half_close']
    if settings['brutal']['enabled']:
        result['brutal-opts'] = settings['brutal'].copy()
    return result


def apply_server(inbound, options, keys):
    advanced = settings(options.get('xray', {}), options['core'], options['transport'])
    inbound['settings']['decryption'] = encryption_pair(advanced, keys)['decryption']
    stream = inbound['streamSettings']
    inbound['sniffing'] = node_dpi.sniffing(advanced['sniffing'], advanced['block_torrent'])
    mask = node_dpi.mask(advanced['finalmask'])
    if mask:
        stream['finalmask'] = mask
    reality = advanced['reality']
    if options['transport'] == 'reality':
        stream['realitySettings'].update({field: reality[field] for field in ('maxTimeDiff', 'minClientVer', 'maxClientVer', 'xver')})
        if reality['mldsa']:
            stream['realitySettings']['mldsa65Seed'] = mldsa_identity(keys.get('mldsa'))['seed']
        if reality['requireMlkem']:
            stream['realitySettings']['requireMlkem'] = True
    if options['transport'] == 'xhttp':
        stream['xhttpSettings']['mode'] = advanced['xhttp']['mode']
        if advanced['xhttp']['mux']:
            stream['xhttpSettings']['extra'] = {'muxKeepAliveSecs': '20-40', 'muxKeepAliveBytes': '64-512'}
    smux = advanced['smux']
    block = {}
    if smux['enabled']:
        if smux['h2mux_frame']:
            block['h2muxMaxReadFrameSize'] = smux['h2mux_frame']
        if smux['brutal']['enabled']:
            block['brutal-opts'] = smux['brutal'].copy()
    if block:
        inbound['smux'] = block


def apply_client(outbound, options, keys):
    advanced = settings(options.get('xray', {}), options['core'], options['transport'])
    outbound['settings']['encryption'] = encryption_pair(advanced, keys)['encryption']
    stream = outbound['streamSettings']
    mask = node_dpi.mask(advanced['dpi'])
    if mask:
        stream['finalmask'] = mask
    security = stream['realitySettings'] if options['transport'] == 'reality' else stream['tlsSettings']
    security['fingerprint'] = advanced['fingerprint']
    if options['transport'] == 'reality':
        if advanced['reality']['mldsa']:
            security['mldsa65Verify'] = mldsa_identity(keys.get('mldsa'))['verify']
        if advanced['reality']['spiderX']:
            security['spiderX'] = advanced['reality']['spiderX']
    if advanced['smux']['enabled']:
        outbound['smux'] = smux_client(advanced['smux'])
    if options['transport'] == 'xhttp':
        stream['xhttpSettings']['mode'] = advanced['xhttp']['mode']
        if advanced['xhttp']['mux']:
            outbound['mux'] = {'enabled': True, 'concurrency': 8, 'xudpConcurrency': 16, 'xudpProxyUDP443': 'allow'}


def link_parameters(options, keys):
    advanced = settings(options.get('xray', {}), options['core'], options['transport'])
    result = {'encryption': encryption_pair(advanced, keys)['encryption'], 'fp': advanced['fingerprint']}
    if options['transport'] == 'reality':
        if advanced['reality']['mldsa']:
            result['pqv'] = mldsa_identity(keys.get('mldsa'))['verify']
        if advanced['reality']['spiderX']:
            result['spx'] = advanced['reality']['spiderX']
    if options['transport'] == 'xhttp':
        result['mode'] = advanced['xhttp']['mode']
    # SMUX and Mux.Cool have no standard vless URI representation. JSON carries them.
    return result
