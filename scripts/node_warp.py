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


LICENSE = re.compile(r'[A-Za-z0-9-]{8,64}')


def account_directory(root, account=None):
    """The account a generation names; without a name, the account kept from before names existed."""
    directory = root/'warp'
    node_state.trusted(directory)
    directory.mkdir(mode=0o700, exist_ok=True)
    if account is None:
        return directory
    if not isinstance(account, str) or not re.fullmatch(r'[a-f0-9]{16}', account):
        raise ValueError('invalid WARP account')
    for directory in (directory/'accounts', directory/'accounts'/account):
        node_state.trusted(directory)
        directory.mkdir(mode=0o700, exist_ok=True)
    return directory


HELPER = Path(__file__).resolve().with_name('warp_masque.sh')


def container(image, directory, mode='wireguard'):
    """docker run arguments up to the command; MASQUE also mounts its helper."""
    masque = ['--mount', f'type=bind,src={HELPER},dst=/helper,readonly', '--env', 'WARP_MASQUE_DIR=/account/masque'] if mode == 'masque' else []
    return ['docker', 'run', '--rm', '--log-driver', 'none', '--network', 'host', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--pids-limit', '64', '--memory', '128m',
            '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=8m', '--env', 'HOME=/tmp',
            '--mount', f'type=bind,src={directory},dst=/account', '--workdir', '/account', *masque,
            '--entrypoint', 'timeout', image, '100']
# Registration reads a WARP+ key from this file and removes it at once: the key never
# appears in process arguments. Without the file the account stays free. Both kinds are
# registered with the key, so switching the mode later keeps WARP+: the current mode
# must succeed, the other one is best effort (an older image may lack MASQUE).
REGISTER = """
    set -eu
    umask 077
    key=''
    if [ -f license.key ]; then key=$(cat license.key); rm -f license.key; fi
    wireguard() {
        rm -f wgcf-account.toml wgcf-account.new.toml wgcf-account.key.toml wgcf-profile.conf wgcf-profile.tmp bootstrap-v4
        wgcf register --accept-tos --config wgcf-account.new.toml >/dev/null 2>&1 || return 1
        if [ -n "$key" ]; then
            LK="$key" awk '/^license_key/ { printf "license_key = \\"%s\\"\\n", ENVIRON["LK"]; next } { print }' \\
                wgcf-account.new.toml > wgcf-account.key.toml || return 1
            mv wgcf-account.key.toml wgcf-account.new.toml
            # A rejected key must fail the change, never leave a free account in its place.
            wgcf update --config wgcf-account.new.toml >/dev/null 2>&1 || return 1
        fi
        mv wgcf-account.new.toml wgcf-account.toml
        wgcf generate --profile wgcf-profile.tmp >/dev/null 2>&1 || return 1
        mv wgcf-profile.tmp wgcf-profile.conf
    }
    masque() {
        rm -rf masque masque.new
        if [ -n "$key" ]; then export WARP_LICENSE_KEY="$key" WARP_LICENSE_STRICT=1; fi
        sh /helper register >/dev/null && sh /helper commit >/dev/null
    }
    if [ "$1" = masque ]; then
        masque
        wireguard || rm -f wgcf-account.toml wgcf-account.new.toml wgcf-account.key.toml wgcf-profile.conf wgcf-profile.tmp
    else
        wireguard
        masque || rm -rf masque masque.new
    fi
"""


def register(mode, image, root, account, key, command):
    """Create a new account in its own directory; the running one stays untouched for rollback."""
    if mode not in ('wireguard', 'masque'):
        raise ValueError('unknown WARP mode')
    if key is not None and (not isinstance(key, str) or not LICENSE.fullmatch(key)):
        raise ValueError('invalid WARP+ key')
    directory = account_directory(root, account)
    if any(directory.iterdir()):
        raise ValueError('WARP account directory is not empty')
    if key is not None:
        node_state.atomic(directory/'license.key', key.encode('ascii'))
    try:
        command([*container(image, directory, 'masque'), 'sh', '-c', REGISTER, 'register', mode], timeout=180)
    finally:
        (directory/'license.key').unlink(missing_ok=True)


def outbound(mode, image, root, command, account=None, port=None, http='h3'):
    directory = account_directory(root, account)
    args = container(image, directory, mode)
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
        warp = wireguard(command([*args, 'sh', '-c', script], timeout=120).stdout.decode())
        if port is not None:
            peer, = warp['settings']['peers']
            peer['endpoint'] = peer['endpoint'].rsplit(':', 1)[0] + ':' + str(port)
        bootstrap_wireguard(warp, directory)
        return warp
    if mode != 'masque':
        raise ValueError('unknown WARP mode')
    if http not in ('h3', 'h2'):
        raise ValueError('invalid WARP MASQUE transport')
    script = """
        set -eu
        if ! sh /helper exists; then
            sh /helper register >/dev/null
            sh /helper commit >/dev/null
        fi
        sh /helper config 1080 "$1" '' 127.0.0.1
    """
    result = command([*args, 'sh', '-c', script, 'masque', http], timeout=120)
    warp = json.loads(result.stdout)['outbounds'][0]
    if port is not None:
        warp['settings']['port'] = port
    return warp


SECRET = ('private_key', 'access_token', 'license_key', 'PrivateKey')
# Only these fields leave the node; secrets are masked to their last characters.
ACCOUNT_FIELDS = ('device_id', 'license_key', 'private_key', 'access_token')
PROFILE_FIELDS = ('PrivateKey', 'Address', 'DNS', 'MTU', 'PublicKey', 'AllowedIPs', 'Endpoint')
DEVICE_FIELDS = ('id', 'endpoint_v4', 'address_v4', 'account_type', 'warp_plus', 'registered')


def mask(value):
    return '…' + value[-4:] if isinstance(value, str) and len(value) > 8 else ('…' if value else '')


def fields(path, allowed):
    """key = value lines of a wgcf file, whitelisted; repeated keys (Address) keep every value."""
    result = []
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 65536:
        return result
    for line in path.read_text(errors='replace').splitlines():
        name, sep, value = line.partition('=')
        name, value = name.strip(), value.strip().strip('\'"')
        if sep and name in allowed:
            result.append([name, mask(value) if name in SECRET else value[:200]])
    return result


def info(options, root, account):
    """WARP details for the controller's card: whitelisted, secrets masked on the node."""
    mode = options.get('warp_mode', 'off')
    result = {'mode': mode, 'http': options.get('warp_http', 'h3'), 'account': account or 'legacy',
              'port': options.get('warp_port'), 'default_port': node_config.WARP_PORTS[mode][0] if mode in node_config.WARP_PORTS else None}
    if mode == 'off':
        return result
    directory = root/'warp' if account is None else root/'warp'/'accounts'/account
    if account is not None and not re.fullmatch(r'[a-f0-9]{16}', account):
        raise ValueError('invalid WARP account')
    node_state.trusted(directory)
    if mode == 'wireguard':
        result['account_fields'] = fields(directory/'wgcf-account.toml', ACCOUNT_FIELDS)
        result['profile'] = fields(directory/'wgcf-profile.conf', PROFILE_FIELDS)
        if result['port'] is not None:
            result['profile'] = [[k, v.rsplit(':', 1)[0] + ':' + str(result['port']) if k == 'Endpoint' else v] for k, v in result['profile']]
    else:
        device = directory/'masque'/'device.json'
        try:
            data = json.loads(device.read_text()) if device.is_file() and not device.is_symlink() and device.stat().st_size <= 65536 else {}
        except (OSError, ValueError):
            data = {}
        result['device'] = {key: (str(data[key])[:8] if key == 'id' else data[key]) for key in DEVICE_FIELDS
                            if isinstance(data, dict) and isinstance(data.get(key), (str, int, bool))}
        result['account_fields'] = fields(directory/'masque'/'wgcf-account.toml', ACCOUNT_FIELDS)
    return result
