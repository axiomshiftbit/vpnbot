#!/usr/bin/env python3
"""Closed configuration format for a standalone VPNBot exit node."""
import base64
import ipaddress
import re
import uuid
from urllib.parse import urlencode
import node_xray
import node_cover
import node_wg
import node_awg


TRANSPORTS = ('reality', 'ws', 'grpc', 'xhttp')
CORES = {'origin': '/usr/bin/xray', 'origin2': '/usr/bin/xray-2', 'origin3': '/usr/bin/xray-3', 'fork': '/usr/bin/xray-smux'}
PRIVATE4 = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
            '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
            '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15',
            '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4']
PRIVATE6 = ['::/96', '::ffff:0:0/96', '64:ff9b::/96', '64:ff9b:1::/48',
            '100::/64', '2001::/23', '2001:db8::/32', '2002::/16',
            '3fff::/20', 'fc00::/7', 'fe80::/10', 'ff00::/8']


def public_ip(value, family=None):
    if not isinstance(value, str) or '%' in value:
        raise ValueError('invalid public address')
    address = ipaddress.ip_address(value)
    reserved = PRIVATE4 if address.version == 4 else PRIVATE6
    if (family and address.version != family) or not address.is_global or address.is_multicast \
            or any(address in ipaddress.ip_network(net) for net in reserved):
        raise ValueError('a public unicast address is required')
    return str(address)


def hostname(value):
    if not isinstance(value, str) or len(value) > 253 or '.' not in value \
            or not all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', label)
                       for label in value.split('.')):
        raise ValueError('invalid hostname')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value.lower()
    raise ValueError('a DNS hostname is required')


def settings(value):
    """Remote callers can change only these settings, never a core config."""
    if not isinstance(value, dict) or set(value) - {'connect_family', 'xray', 'cover', 'wireguard', 'amnezia', 'domain_aliases'} != {'transport', 'family', 'core', 'domain', 'mask'}:
        raise ValueError('invalid settings fields')
    if not isinstance(value['transport'], str) or not isinstance(value['core'], str) \
            or value['transport'] not in TRANSPORTS or value['core'] not in CORES \
            or type(value['family']) is not int or value['family'] not in (4, 6):
        raise ValueError('unsupported transport, address family or core')
    result = dict(value)
    if 'wireguard' in value:
        result['wireguard'] = node_wg.settings(value['wireguard'])
    if 'amnezia' in value:
        result['amnezia'] = node_awg.settings(value['amnezia'])
    if result.get('wireguard', {}).get('active') and result.get('amnezia', {}).get('active'):
        raise ValueError('only one controller channel can be active')
    if 'cover' in value and type(value['cover']) is not bool:
        raise ValueError('invalid cover site flag')
    if 'connect_family' in value and (type(value['connect_family']) is not int or value['connect_family'] not in (4, 6)):
        raise ValueError('invalid node connection family')
    result['mask'] = hostname(value['mask'])
    result['domain'] = hostname(value['domain']) if value['domain'] else ''
    if 'domain_aliases' in value:
        aliases = value['domain_aliases']
        if not isinstance(aliases, list) or len(aliases) > 12:
            raise ValueError('at most twelve additional certificate names are supported')
        result['domain_aliases'] = list(dict.fromkeys(hostname(name) for name in aliases))
        result['domain_aliases'] = [name for name in result['domain_aliases'] if name != result['domain']]
        if result['domain_aliases'] and not result['domain']:
            raise ValueError('additional domains require a primary domain')
    if (value['transport'] != 'reality' or value.get('cover')) and not result['domain']:
        raise ValueError('TLS transports require the node domain')
    if value.get('cover') and value['transport'] == 'reality':
        result['mask'] = result['domain']
    if 'xray' in value:
        result['xray'] = node_xray.settings(value['xray'], value['core'], value['transport'])
    return result


def deployment(value):
    if not isinstance(value, dict) or set(value) - {'ssh_networks', 'cover_uid', 'awg_uid'} != {'public4', 'public6', 'sources', 'admins', 'routers', 'ssh_ports', 'interface', 'uid', 'gid'}:
        raise ValueError('invalid deployment fields')
    result = dict(value)
    if 'cover_uid' in value and (type(value['cover_uid']) is not int or not 100 <= value['cover_uid'] <= 60000 or value['cover_uid'] == value['uid']):
        raise ValueError('cover site requires a separate service user')
    if 'awg_uid' in value and (type(value['awg_uid']) is not int or not 100 <= value['awg_uid'] <= 60000
                             or value['awg_uid'] in (value['uid'], value.get('cover_uid'))):
        raise ValueError('Amnezia requires a separate service user')
    for key, family in [('public4', 4), ('public6', 6)]:
        result[key] = public_ip(value[key], family) if value[key] else ''
    if not (result['public4'] or result['public6']):
        raise ValueError('a public node address is required')
    for key in ('sources', 'admins'):
        if not isinstance(value[key], list) or not 1 <= len(value[key]) <= 32:
            raise ValueError('trusted address lists must be nonempty and bounded')
        result[key] = sorted(set(public_ip(ip) for ip in value[key]))
    if not isinstance(value['routers'], list) or len(value['routers']) > 8:
        raise ValueError('invalid trusted routers')
    routers = []
    for router in value['routers']:
        if not isinstance(router, str) or '%' in router or not ipaddress.IPv6Address(router).is_link_local:
            raise ValueError('trusted routers must be link-local IPv6 addresses')
        routers.append(str(ipaddress.IPv6Address(router)))
    result['routers'] = sorted(set(routers))
    if not isinstance(value['ssh_ports'], list) or not 1 <= len(value['ssh_ports']) <= 8 \
            or any(type(p) is not int or not 1 <= p <= 65535 or p in (80, 443) for p in value['ssh_ports']):
        raise ValueError('invalid SSH ports')
    if not isinstance(value['interface'], str) or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', value['interface']):
        raise ValueError('invalid network interface')
    for key in ('uid', 'gid'):
        if type(value[key]) is not int or not 100 <= value[key] <= 60000:
            raise ValueError('a dedicated unprivileged identity is required')
    networks = value.get('ssh_networks', [])
    if not isinstance(networks, list) or len(networks) > 100000:
        raise ValueError('invalid SSH network list')
    result['ssh_networks'] = []
    for network in networks:
        if not isinstance(network, str):
            raise ValueError('invalid SSH network')
        subnet = ipaddress.ip_network(network, strict=True)
        if subnet.prefixlen == 0 or any(subnet.overlaps(ipaddress.ip_network(denied))
                                        for denied in (PRIVATE4 if subnet.version == 4 else PRIVATE6)):
            raise ValueError('SSH networks must contain only public unicast addresses')
        result['ssh_networks'].append(str(subnet))
    return result


def needs_certificate(options):
    return options['transport'] != 'reality' or bool(options.get('cover'))


def identity(value):
    if not isinstance(value, dict) or set(value)-{'encryption', 'mldsa', 'cover_auth', 'wireguard', 'amnezia', 'external'} != {'uuid', 'private', 'public', 'short_id', 'path'}:
        raise ValueError('invalid node identity')
    if not isinstance(value['uuid'], str) or str(uuid.UUID(value['uuid'])) != value['uuid']:
        raise ValueError('invalid client identity')
    for key in ('private', 'public'):
        if not isinstance(value[key], str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', value[key]):
            raise ValueError('invalid Reality identity')
    if not isinstance(value['short_id'], str) or not isinstance(value['path'], str) \
            or not re.fullmatch(r'[a-f0-9]{16}', value['short_id']) or not re.fullmatch(r'[a-f0-9]{32}', value['path']):
        raise ValueError('invalid transport identity')
    result = dict(value)
    if 'external' in value:
        result['external'] = node_wg.external(value['external'])
    if 'wireguard' in value:
        result['wireguard'] = node_wg.identity(value['wireguard'])
    if 'amnezia' in value:
        result['amnezia'] = node_awg.identity(value['amnezia'])
    if 'encryption' in value:
        result['encryption'] = node_xray.encryption_identity(value['encryption'])
    if 'mldsa' in value:
        result['mldsa'] = node_xray.mldsa_identity(value['mldsa'])
    if 'cover_auth' in value:
        result['cover_auth'] = node_cover.password_hash(value['cover_auth'])
    return result


def peers(value):
    if not isinstance(value, list) or len(value) > 32:
        raise ValueError('invalid peer list')
    result, seen = [], set()
    for peer in value:
        if not isinstance(peer, dict) or set(peer)-{'channel'} != {'id', 'name', 'enabled'} \
                or not isinstance(peer['id'], str) or str(uuid.UUID(peer['id'])) != peer['id'] \
                or peer['id'] in seen or type(peer['enabled']) is not bool \
                or not isinstance(peer['name'], str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,40}', peer['name']):
            raise ValueError('invalid peer')
        if peer.get('channel', 'vless') not in ('vless', 'wireguard', 'amnezia'):
            raise ValueError('invalid external channel')
        seen.add(peer['id'])
        result.append(dict(peer))
    return result


def external_peers(keys, external, channel):
    result=[]
    for peer in peers(external or []):
        if peer.get('channel','vless') != channel or not peer['enabled']:
            continue
        entry=keys.get('external',{}).get(peer['id'])
        if entry is None or entry['channel'] != channel:
            raise ValueError('external channel identity missing')
        result.append(entry)
    return result


def core_config(options, host, keys, external=None):
    options, host, keys = settings(options), deployment(host), identity(keys)
    family = options['family']
    source = host['public4' if family == 4 else 'public6']
    if not source:
        raise ValueError('the selected egress family is not configured')
    strategy = 'ForceIPv4' if family == 4 else 'ForceIPv6'
    # Xray normalizes IPv4-mapped addresses to IPv4 before evaluating IP rules;
    # its CIDR parser rejects the mapped /96. NFTables keeps that range below.
    denied = PRIVATE4 + [ip for ip in PRIVATE6 if ip != '::ffff:0:0/96'] + [ip for ip in (host['public4'], host['public6']) if ip]
    denied.append('::/0' if family == 4 else '0.0.0.0/0')
    client = {'id': keys['uuid'], 'email': 'controller'}
    transport = options['transport']
    stream = {'network': 'tcp' if transport == 'reality' else transport,
              'security': 'reality' if transport == 'reality' else 'tls', 'sockopt': {'tcpMptcp': False}}
    if transport == 'reality':
        client['flow'] = 'xtls-rprx-vision'
        stream['realitySettings'] = {'show': False, 'dest': options['mask'] + ':443',
                                    'serverNames': [options['mask']], 'privateKey': keys['private'],
                                    'shortIds': [keys['short_id']]}
    else:
        stream['tlsSettings'] = {'minVersion': '1.2', 'alpn': ['http/1.1'] if transport == 'ws' else ['h2', 'http/1.1'],
                                 'certificates': [{'certificateFile': '/node/fullchain.pem', 'keyFile': '/node/privkey.pem'}]}
        if transport == 'grpc':
            stream['grpcSettings'] = {'serviceName': keys['path']}
        elif transport == 'ws':
            stream['wsSettings'] = {'path': '/' + keys['path']}
        else:
            stream['xhttpSettings'] = {'path': '/' + keys['path'], 'mode': 'auto'}
    clients = [client]
    for peer in peers(external or []):
        if peer['id'] == keys['uuid']:
            raise ValueError('peer conflicts with controller identity')
        if peer['enabled'] and peer.get('channel', 'vless') != 'wireguard':
            clients.append({'id': peer['id'], 'email': peer['name'],
                            **({'flow': 'xtls-rprx-vision'} if transport == 'reality' else {})})
    result = {
        'log': {'loglevel': 'none'},
        'dns': {'servers': ['1.1.1.1', '9.9.9.9'] if family == 4 else ['2606:4700:4700::1111', '2620:fe::fe'],
                'queryStrategy': 'UseIPv4' if family == 4 else 'UseIPv6'},
        'inbounds': [{'tag': 'node', 'listen': '::' if host['public6'] else '0.0.0.0', 'port': 8443,
                      'protocol': 'vless', 'settings': {'decryption': 'none', 'clients': clients},
                      'streamSettings': stream}],
        'outbounds': [{'tag': 'direct', 'protocol': 'freedom', 'sendThrough': source,
                       'settings': {'domainStrategy': strategy, 'finalRules': [
                           {'action': 'block', 'ip': denied, 'blockDelay': 0},
                           {'action': 'allow', 'ip': ['0.0.0.0/0' if family == 4 else '2000::/3']},
                           {'action': 'block', 'ip': ['::/0', '0.0.0.0/0'], 'blockDelay': 0}]},
                       'streamSettings': {'sockopt': {'domainStrategy': strategy}}}],
    }
    node_xray.apply_server(result['inbounds'][0], options, keys)
    if options.get('cover'):
        if 'cover_uid' not in host:
            raise ValueError('cover site account is not installed')
        if transport == 'reality':
            stream['realitySettings']['dest'] = '127.0.0.1:9443'
            stream['realitySettings']['serverNames'] = [options['domain'], *options.get('domain_aliases', [])]
        else:
            result['inbounds'][0].update(listen='127.0.0.1', port=9444)
            stream['security'] = 'none'
            stream.pop('tlsSettings')
    if options.get('xray', {}).get('block_torrent'):
        result['outbounds'].append({'tag': 'block', 'protocol': 'blackhole'})
        result['routing'] = {'rules': [{'type': 'field', 'inboundTag': ['node'], 'protocol': ['bittorrent'], 'outboundTag': 'block'}]}
    if options.get('wireguard', {}).get('enabled'):
        for address in (host['public4'], host['public6']):
            if address:
                inbound = node_wg.inbound(options['wireguard'], address, keys['wireguard'], result['inbounds'][0].get('sniffing'),
                    external_peers(keys, external, 'wireguard'))
                result['inbounds'].append(inbound)
                if options.get('xray', {}).get('block_torrent'):
                    result['routing']['rules'][0]['inboundTag'].append(inbound['tag'])
    return result


def client_link(options, host, keys):
    options, host, keys = settings(options), deployment(host), identity(keys)
    address = endpoint(options, host)
    if ':' in address:
        address = '[' + address + ']'
    transport = options['transport']
    params = {'encryption': 'none', 'type': 'tcp' if transport == 'reality' else transport,
              'security': 'reality' if transport == 'reality' else 'tls',
              'sni': options['mask'] if transport == 'reality' else options['domain'], 'fp': 'chrome'}
    if transport == 'reality':
        params.update(pbk=keys['public'], sid=keys['short_id'], flow='xtls-rprx-vision')
    elif transport == 'grpc':
        params['serviceName'] = keys['path']
    else:
        params['path'] = '/' + keys['path']
        if transport == 'xhttp':
            params['mode'] = 'auto'
    params.update(node_xray.link_parameters(options, keys))
    return 'vless://' + keys['uuid'] + '@' + address + ':443?' + urlencode(params)


def endpoint(options, host):
    family = options.get('connect_family', 4 if host['public4'] else 6)
    address = host['public'+str(family)]
    if not address:
        raise ValueError('the selected connection family is not configured')
    return address


def client_outbound(options, host, keys, tag='node'):
    """Native Xray/3x-ui outbound; never contains a server private key."""
    options, host, keys = settings(options), deployment(host), identity(keys)
    if not isinstance(tag, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,40}', tag):
        raise ValueError('invalid outbound tag')
    transport = options['transport']
    stream = {'network': 'tcp' if transport == 'reality' else transport,
              'security': 'reality' if transport == 'reality' else 'tls'}
    config = {'tag': tag, 'protocol': 'vless',
              'settings': {'address': endpoint(options, host), 'port': 443,
                           'id': keys['uuid'], 'encryption': 'none'}, 'streamSettings': stream}
    if transport == 'reality':
        config['settings']['flow'] = 'xtls-rprx-vision'
        stream['realitySettings'] = {'serverName': options['mask'], 'publicKey': keys['public'],
                                     'shortId': keys['short_id'], 'fingerprint': 'chrome'}
    else:
        stream['tlsSettings'] = {'serverName': options['domain'], 'fingerprint': 'chrome',
                                 'alpn': ['http/1.1'] if transport == 'ws' else ['h2', 'http/1.1']}
        if transport == 'grpc':
            stream['grpcSettings'] = {'serviceName': keys['path']}
        elif transport == 'ws':
            stream['wsSettings'] = {'path': '/' + keys['path']}
        else:
            stream['xhttpSettings'] = {'path': '/' + keys['path'], 'mode': 'auto'}
    node_xray.apply_client(config, options, keys)
    return config


def export_profile(options, host, keys, peer=None):
    keys = identity(keys)
    name = 'node'
    if peer is not None:
        peer = peers([peer])[0]
        if not peer['enabled'] or peer['id'] == keys['uuid']:
            raise ValueError('peer is disabled or conflicts with controller')
        keys['uuid'], name = peer['id'], peer['name']
    link = client_link(options, host, keys) + '#' + name
    result = {'link': link, 'outbound': client_outbound(options, host, keys, name),
              'subscription': base64.b64encode((link + '\n').encode()).decode()}
    channel = peer.get('channel', 'vless') if peer else ('wireguard' if options.get('wireguard', {}).get('active') else 'amnezia' if options.get('amnezia', {}).get('active') else 'vless')
    entry = external_peers(keys, [peer], channel)[0] if peer and channel != 'vless' else None
    if channel == 'wireguard':
        if not options.get('wireguard', {}).get('enabled'): raise ValueError('WireGuard channel disabled')
        result['channel'] = 'wireguard'
        result['outbound'] = node_wg.outbound(options['wireguard'], endpoint(options, host),
            node_wg.peer_keys(keys['wireguard'],entry) if entry else keys['wireguard'], family=options['family'], slot=entry['slot'] if entry else 0)
    if channel == 'amnezia':
        if not options.get('amnezia', {}).get('enabled'): raise ValueError('Amnezia channel disabled')
        result['channel'] = 'amnezia'
        result['amnezia'] = node_awg.profile(options['amnezia'], endpoint(options, host),
            (node_wg.peer_keys({k:v for k,v in keys['amnezia'].items() if k != 'parameters'},entry) | {'parameters':keys['amnezia']['parameters']}) if entry else keys['amnezia'],
            slot=entry['slot'] if entry else 0)
    return result


def firewall(options, host):
    options, host = settings(options), deployment(host)
    if options.get('amnezia', {}).get('enabled') and 'awg_uid' not in host:
        raise ValueError('Amnezia service account is not installed')
    family, uid, interface = options['family'], host['uid'], host['interface']
    lines = ['table inet vpnbot_node {']
    for name, values in [('my_server', host['sources']), ('admins', sorted(set(host['admins'] + host['sources'])))]:
        for version in (4, 6):
            addresses = [ip for ip in values if ipaddress.ip_address(ip).version == version]
            elements = ' elements = { ' + ', '.join(addresses) + ' };' if addresses else ''
            lines.append(f' set {name}{version} {{ type ipv{version}_addr;{elements} }}')
    for version in (4, 6):
        networks = [ipaddress.ip_network(net) for net in host['ssh_networks'] if ipaddress.ip_network(net).version == version]
        values = ', '.join(map(str, ipaddress.collapse_addresses(networks)))
        lines.append(f' set ssh_asn{version} {{ type ipv{version}_addr; flags interval;' + (' elements = { '+values+' };' if values else '') + ' }')
    lines += [' set acme_http { type inet_service; flags timeout; timeout 10m; }',
              ' set ipv6_routers { type ipv6_addr;' + (' elements = { ' + ', '.join(host['routers']) + ' };' if host['routers'] else '') + ' }',
              ' chain ingress_options { type filter hook prerouting priority -450; policy accept;',
              # CVE-2026-98432 mitigation; a patched Linux kernel is still required.
              '  iifname != "lo" ip hdrlength != 5 counter drop',
              ' }',
              ' chain prerouting { type nat hook prerouting priority -110; policy accept;',
              f'  iifname "{interface}" ip saddr @my_server4 tcp dport 443 redirect to :8443',
              f'  iifname "{interface}" ip6 saddr @my_server6 tcp dport 443 redirect to :8443',
              f'  iifname "{interface}" tcp dport @acme_http redirect to :8080',
              ' }',
              ' chain input { type filter hook input priority -20; policy drop;',
              '  iifname "lo" accept',
              '  ip saddr 127.0.0.0/8 drop',
              '  ip6 saddr ::1 drop',
              '  ct state invalid drop',
              '  icmpv6 type nd-redirect drop',
              f'  iifname "{interface}" ip6 hoplimit 255 icmpv6 code 0 icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} accept',
              '  ct state established,related accept',
              f'  iifname "{interface}" ip6 saddr @ipv6_routers ip6 hoplimit 255 icmpv6 code 0 icmpv6 type nd-router-advert accept',
              f'  iifname "{interface}" icmpv6 type {{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem }} accept',
              f'  iifname "{interface}" icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} accept']
    ports = ', '.join(map(str, sorted(set(host['ssh_ports']))))
    for version in (4, 6):
        proto = 'ip' if version == 4 else 'ip6'
        lines += [f'  {proto} saddr @admins{version} tcp dport {{ {ports} }} ct state new tcp flags & (fin|syn|rst|ack) == syn accept',
                  f'  {proto} saddr @ssh_asn{version} tcp dport {{ {ports} }} ct state new tcp flags & (fin|syn|rst|ack) == syn accept',
                  f'  {proto} saddr @my_server{version} tcp dport 8443 ct status dnat ct original proto-dst 443 ct state new tcp flags & (fin|syn|rst|ack) == syn jump syn{version}']
    lines += ['  tcp dport 8080 ct status dnat ct original proto-dst @acme_http ct state new tcp flags & (fin|syn|rst|ack) == syn accept',
              '  limit rate 5/second burst 10 packets log prefix "INPUT-NODE-DROP: "',
              '  counter drop', ' }',
              ' chain syn4 { meter node_syn4 size 65535 { ip saddr timeout 1m limit rate 50/second burst 100 packets } counter accept; counter drop; }',
              ' chain syn6 { meter node_syn6 size 65535 { ip6 saddr timeout 1m limit rate 50/second burst 100 packets } counter accept; counter drop; }',
              ' chain forward { type filter hook forward priority -20; policy drop; }',
              ' chain output { type filter hook output priority -20; policy accept;',
              '  ct state invalid drop', f'  meta skuid {uid} jump core_egress']
    if 'awg_uid' in host:
        awg_uid = host['awg_uid']
        if options.get('amnezia', {}).get('enabled'):
            lines += [f'  meta skuid {awg_uid} oifname "lo" ip daddr 127.0.0.1 tcp dport 8443 accept']
            for version in (4, 6):
                proto = 'ip' if version == 4 else 'ip6'
                lines += [f'  meta skuid {awg_uid} oifname "{interface}" {proto} daddr @my_server{version} udp sport {node_awg.LISTEN_PORT} accept']
        lines += [f'  meta skuid {awg_uid} counter drop']
    if 'cover_uid' in host:
        lines += [f'  meta skuid {host["cover_uid"]} ct direction reply ct state established accept']
        if options.get('cover'):
            lines += [f'  meta skuid {host["cover_uid"]} oifname "lo" ip daddr 127.0.0.1 tcp dport 9444 accept']
        lines += [f'  meta skuid {host["cover_uid"]} counter drop']
    lines += [' }',
              ' chain core_egress {', '  ct direction reply ct state established accept']
    if options.get('cover'):
        lines += ['  oifname "lo" ip daddr 127.0.0.1 tcp dport 9443 accept']
    for version, ranges in [(4, PRIVATE4), (6, PRIVATE6)]:
        proto = 'ip' if version == 4 else 'ip6'
        denied = ranges + ([host['public4' if version == 4 else 'public6']] if host['public4' if version == 4 else 'public6'] else [])
        lines.append(f'  {proto} daddr {{ ' + ', '.join(denied) + ' } counter drop')
    network = 'ip daddr 0.0.0.0/0' if family == 4 else 'ip6 daddr 2000::/3'
    lines += [f'  oifname "{interface}" {network} meta l4proto {{ tcp, udp }} accept',
              '  counter drop', ' }', '}', '']
    result = '\n'.join(lines)
    for name, module in [('wireguard', node_wg), ('amnezia', node_awg)]:
        if not options.get(name, {}).get('enabled'):
            continue
        nat, allow = [], []
        for version in (4, 6):
            proto = 'ip' if version == 4 else 'ip6'
            address = host['public'+str(version)]
            if not address:
                continue
            target = '['+address+']' if version == 6 else address
            nat.append(f'  iifname "{interface}" {proto} saddr @my_server{version} {proto} daddr {address} udp dport {module.PORT} dnat {proto} to {target}:{module.LISTEN_PORT}')
            allow.append(f'  iifname "{interface}" {proto} saddr @my_server{version} udp dport {module.LISTEN_PORT} ct status dnat ct original proto-dst {module.PORT} counter accept')
        result = result.replace(' chain prerouting { type nat hook prerouting priority -110; policy accept;',
                                ' chain prerouting { type nat hook prerouting priority -110; policy accept;\n'+'\n'.join(nat))
        result = result.replace('  tcp dport 8080 ct status dnat', '\n'.join(allow)+'\n  tcp dport 8080 ct status dnat')
    return result
