"""Build the managed node's WARP outbound using its own persistent account."""
import base64
import hmac
import ipaddress
import json
from pathlib import Path
import re
import socket

import node_config
import node_state


def masque_supported(version):
    # Older MASQUE implementations can parse the config while ignoring warp.
    match = re.match(rb'Xray\s+v?(\d+)\.(\d+)\.(\d+)(?=[-+\s])', version)
    return bool(match and tuple(map(int, match.groups())) >= (26, 10, 10))


def wireguard(profile):
    # wgcf can write an Address line for each address family.
    fields = {}
    for line in profile.splitlines():
        name, sep, value = line.partition('=')
        if sep:
            fields.setdefault(name.strip(), []).append(value.strip())
    try:
        private, = fields['PrivateKey']
        public, = fields['PublicKey']
        endpoint, = fields['Endpoint']
        addresses = [ipaddress.ip_interface(ip.strip()) for line in fields['Address'] for ip in line.split(',')]
        if not all(len(base64.b64decode(key, validate=True)) == 32 for key in (private, public)):
            raise ValueError()
        address, = [ip for ip in addresses if ip.version == 4]
        host, port = endpoint.rsplit(':', 1)
        if not re.fullmatch(r'[1-9][0-9]{0,4}', port) or int(port) > 65535:
            raise ValueError()
        if host != 'engage.cloudflareclient.com':
            node_config.public_ip(host, 4)
    except (ValueError, KeyError):
        raise ValueError('invalid generated WARP profile') from None
    return {'protocol': 'wireguard', 'settings': {'secretKey': private, 'address': [str(address)],
            'mtu': 1280, 'noKernelTun': True, 'domainStrategy': 'ForceIPv4',
            'peers': [{'publicKey': public, 'endpoint': endpoint, 'allowedIPs': ['0.0.0.0/0'], 'keepAlive': 25}]}}


def bootstrap_wireguard(warp, directory):
    # Resolve only the provider endpoint before starting Xray. Resolving it
    # through the tunnel itself would deadlock on a cold start.
    peer, = warp['settings']['peers']
    hostname, port = peer['endpoint'].rsplit(':', 1)
    if hostname != 'engage.cloudflareclient.com':
        return
    saved = directory/'bootstrap-v4'
    node_state.trusted(saved)
    try:
        answers = socket.getaddrinfo(hostname, int(port), socket.AF_INET, socket.SOCK_DGRAM)
        address = node_config.public_ip(answers[0][4][0], 4)
    except (OSError, IndexError):
        if not saved.is_file():
            raise ValueError('WARP endpoint bootstrap unavailable') from None
        address = node_config.public_ip(saved.read_text().strip(), 4)
    node_state.atomic(saved, address.encode('ascii'))
    peer['endpoint'] = address + ':' + port


def isolate_resolver(main, warp_id):
    """Move WARP resolution + destination ACL and tunnel into their own DNS context."""
    warp = next(o for o in main['outbounds'] if o['tag'] == 'warp')
    resolve = next(o for o in main['outbounds'] if o['tag'] == 'warp-resolve')
    rules = main['routing']['rules']
    checks = [r for r in rules if r.get('inboundTag') == ['warp-resolved']]
    # The local hop preserves the destination name until the strict core can
    # resolve it. The node UID guard and an independent login protect the hop.
    password = hmac.digest(warp_id.encode('ascii'), b'vpnbot/node-warp-relay/v1', 'sha256').hex()
    address, port = '127.0.0.1', node_config.WARP_CORE_PORT
    main['outbounds'] = [o for o in main['outbounds'] if o['tag'] not in ('warp', 'warp-resolve')]
    main['outbounds'].append({'tag': 'warp', 'protocol': 'trojan',
                              'settings': {'servers': [{'address': address, 'port': port, 'password': password}]}})
    main['routing']['rules'] = [r for r in rules if r not in checks]
    for rule in main['routing']['rules']:
        if rule.get('outboundTag') == 'warp-resolve':
            rule['outboundTag'] = 'warp'
    dns = {'servers': ['1.1.1.1'], 'queryStrategy': 'UseIPv4', 'disableFallback': True,
           'disableCache': True, 'tag': 'warp-internal-dns'}
    outbounds = [{'tag': 'block', 'protocol': 'blackhole'}, resolve, warp]
    return {'log': {'loglevel': 'none'}, 'dns': dns,
            'inbounds': [{'tag': 'warp-handoff', 'listen': address, 'port': port, 'protocol': 'trojan',
                          'settings': {'clients': [{'password': password}]}}],
            'outbounds': outbounds, 'routing': {'domainStrategy': 'AsIs', 'rules': [
                {'type': 'field', 'inboundTag': ['warp-internal-dns'], 'outboundTag': 'warp'},
                *checks, {'type': 'field', 'inboundTag': ['warp-handoff'], 'outboundTag': 'warp-resolve'}]}}


def outbound(mode, image, root, command):
    directory = root/'warp'
    node_state.trusted(directory)
    directory.mkdir(mode=0o700, exist_ok=True)
    args = ['docker', 'run', '--rm', '--log-driver', 'none', '--network', 'host', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--pids-limit', '64', '--memory', '128m',
            '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=8m', '--env', 'HOME=/tmp',
            '--mount', f'type=bind,src={directory},dst=/account', '--workdir', '/account']
    if mode == 'wireguard':
        script = """
            set -eu
            umask 077
            if [ ! -s wgcf-profile.conf ]; then
                if [ ! -s wgcf-account.toml ]; then
                    rm -f wgcf-account.new.toml
                    wgcf register --accept-tos --config wgcf-account.new.toml >/dev/null 2>&1
                    mv wgcf-account.new.toml wgcf-account.toml
                fi
                wgcf generate --profile wgcf-profile.tmp >/dev/null 2>&1
                mv wgcf-profile.tmp wgcf-profile.conf
            fi
            cat wgcf-profile.conf
        """
        warp = wireguard(command([*args, '--entrypoint', 'timeout', image, '100', 'sh', '-c', script], timeout=120).stdout.decode())
        bootstrap_wireguard(warp, directory)
        return warp
    if mode != 'masque':
        raise ValueError('unknown WARP mode')
    helper = Path(__file__).resolve().with_name('warp_masque.sh')
    script = """
        set -eu
        if ! sh /helper exists; then
            sh /helper register >/dev/null
            sh /helper commit >/dev/null
        fi
        sh /helper config 1080 h3 '' 127.0.0.1
    """
    result = command([*args, '--mount', f'type=bind,src={helper},dst=/helper,readonly',
                      '--env', 'WARP_MASQUE_DIR=/account/masque', '--entrypoint', 'timeout', image, '100', 'sh', '-c', script], timeout=120)
    return json.loads(result.stdout)['outbounds'][0]
