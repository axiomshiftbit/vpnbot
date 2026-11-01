#!/usr/bin/env python3
"""Bounded fragmentation, noise and sniffing; no arbitrary core configuration."""
import base64
import ipaddress
import re


FRAGMENT = {'enabled': False, 'packets': 'tlshello', 'length': '100-200', 'delay': '10-20', 'maxSplit': ''}
NOISE = {'enabled': False, 'reset': '5-10', 'list': []}
SNIFFING = {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'metadataOnly': False,
            'routeOnly': False, 'ipsExcluded': [], 'domainsExcluded': []}


def span(value, minimum, maximum):
    if not isinstance(value, str):
        raise ValueError('range must be a string')
    match = re.fullmatch(r'([0-9]{1,5})(?:-([0-9]{1,5}))?', value)
    if not match or not minimum <= int(match[1]) <= int(match[2] or match[1]) <= maximum:
        raise ValueError('invalid range')
    return int(match[2] or match[1])


def expression(value):
    if len(value) > 4096:
        raise ValueError('noise expression is too long')
    end, length = 0, 0
    for match in re.finditer(r'<\s*([a-z]+)(?:\s+([^>]*?))?\s*>', value):
        if value[end:match.start()].strip():
            raise ValueError('text outside noise expression')
        end, kind, argument = match.end(), match[1], (match[2] or '').strip()
        if kind == 'b':
            packet = re.sub(r'\s+', '', argument)
            packet = re.sub(r'^0[xX]', '', packet)
            if not re.fullmatch(r'(?:[a-fA-F0-9]{2})+', packet):
                raise ValueError('invalid noise hex bytes')
            length += len(packet)//2
        elif kind in ('r', 'rc', 'rd'):
            length += span(argument, 0, 1400)
        elif kind in ('t', 'c', 'n') and not argument:
            length += 8 if kind == 'n' else 4
        else:
            raise ValueError('unsupported noise expression')
    if value[end:].strip() or not 1 <= length <= 1400:
        raise ValueError('noise expression exceeds packet bounds')


def noise(options):
    span(options['reset'], 1, 86400)
    if len(options['list']) > 8:
        raise ValueError('too many noise packets')
    packets = []
    for item in options['list']:
        if not isinstance(item, dict) or set(item) != {'type', 'packet', 'delay'} or not all(isinstance(v, str) for v in item.values()):
            raise ValueError('invalid noise packet')
        kind, packet, delay = item['type'], item['packet'], item['delay']
        span(delay, 0, 1000)
        if kind == 'rand':
            span(packet, 1, 1400)
            packets.append({'rand': packet, 'randRange': '0-255', 'delay': delay})
            continue
        if kind == 'exp':
            expression(packet)
        else:
            if kind == 'str':
                body = packet.encode()
            elif kind == 'hex' and re.fullmatch(r'(?:[a-fA-F0-9]{2})+', packet):
                body = bytes.fromhex(packet)
            elif kind == 'base64':
                body = base64.b64decode(packet, validate=True)
            else:
                raise ValueError('unsupported noise packet')
            if not 1 <= len(body) <= 1400:
                raise ValueError('noise packet exceeds bounds')
        packets.append(dict(type=kind, packet=packet, delay=delay))
    return {'reset': options['reset'], 'noise': packets or [{'rand': '10-20', 'randRange': '0-255', 'delay': '10-16'}]}


def fragment(options):
    if options['packets'] != 'tlshello':
        span(options['packets'], 1, 65535)
    span(options['length'], 1, 16384)
    span(options['delay'], 0, 1000)
    if options['maxSplit']:
        span(options['maxSplit'], 1, 4096)
    result = {key: options[key] for key in ('packets', 'length', 'delay')}
    if options['maxSplit']:
        result['maxSplit'] = options['maxSplit']
    return result


def mask(options):
    # Validate disabled options too, before they can be enabled by a toggle.
    tcp, udp = fragment(options['fragment']), noise(options['noise'])
    result = {}
    if options['fragment']['enabled']:
        result['tcp'] = [{'type': 'fragment', 'settings': tcp}]
    if options['noise']['enabled']:
        result['udp'] = [{'type': 'noise', 'settings': udp}]
    return result


def sniffing(options, torrent):
    if len(options['destOverride']) > 3 or any(value not in ('http', 'tls', 'quic') for value in options['destOverride']):
        raise ValueError('unsupported sniffing protocol')
    for field in ('ipsExcluded', 'domainsExcluded'):
        if len(options[field]) > 128 or any(not isinstance(v, str) or len(v) > 253 or any(ord(c) < 32 for c in v) for v in options[field]):
            raise ValueError('invalid sniffing exclusion')
    for value in options['ipsExcluded']:
        ipaddress.ip_network(value, strict=False)
    if torrent and (not options['enabled'] or options['metadataOnly']):
        raise ValueError('torrent detection requires payload sniffing')
    return dict(options)
