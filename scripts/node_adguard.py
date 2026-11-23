"""Private networks and fixed DNS paths for the managed node's AdGuard Home."""
import ipaddress
import json
import uuid
from urllib.parse import urlsplit

CONTAINER = 'vpnbot-node-adguard'
LABEL = 'org.vpnbot.node-adguard'
DNS_PORT = 5353
UPSTREAM_PORT = 15553
FILTER_PROXY_PORT = 15080
PANEL_PORT = 13000
BRIDGES = {'node': 'vpb-dns0', 'warp': 'vpb-dns1'}
VIRTUAL_DNS = '100.64.0.53'


def settings(value):
    if not isinstance(value, dict) or set(value) - {'enabled', 'controller', 'peers'}:
        raise ValueError('invalid DNS filter options')
    for flag in ('enabled', 'controller'):
        if type(value.get(flag, False)) is not bool:
            raise ValueError('invalid DNS filter switch')
    peers = value.get('peers', [])
    if not isinstance(peers, list) or len(peers) > 32 or not all(isinstance(p, str) and str(uuid.UUID(p)) == p for p in peers):
        raise ValueError('invalid DNS filter clients')
    return {'enabled': value.get('enabled', False), 'controller': value.get('controller', False), 'peers': sorted(set(peers))}


def networks(command):
    """Reuse only node-owned, isolated, IPv4-only bridges. No ports or host forwarding."""
    result = {}
    for mode, bridge in BRIDGES.items():
        name = CONTAINER + '-' + mode
        listing = command(['docker', 'network', 'ls', '--format', '{{.Name}}']).stdout.decode().splitlines()
        if name not in listing:
            command(['docker', 'network', 'create', '--driver', 'bridge', '--internal', '--label', LABEL+'='+mode,
                     '--opt', 'com.docker.network.bridge.name='+bridge, '--opt', 'com.docker.network.bridge.enable_icc=false',
                     '--opt', 'com.docker.network.bridge.enable_ip_masquerade=false', name])
        item, = json.loads(command(['docker', 'network', 'inspect', name]).stdout)
        options = item.get('Options') or {}
        if item.get('Labels', {}).get(LABEL) != mode or item.get('Driver') != 'bridge' or not item.get('Internal') or item.get('EnableIPv6') \
                or options.get('com.docker.network.bridge.name') != bridge \
                or options.get('com.docker.network.bridge.enable_icc') != 'false' \
                or options.get('com.docker.network.bridge.enable_ip_masquerade') != 'false' \
                or any(ep.get('Name') != CONTAINER for ep in (item.get('Containers') or {}).values()):
            raise ValueError('DNS bridge has unexpected ownership or endpoints')
        entry, = item['IPAM']['Config']
        subnet = ipaddress.IPv4Network(entry['Subnet'])
        gateway = ipaddress.IPv4Address(entry['Gateway'])
        service = subnet.broadcast_address - 1
        private = any(subnet.subnet_of(ipaddress.IPv4Network(net)) for net in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
        if not private or subnet.prefixlen > 28 or gateway not in subnet or service == gateway:
            raise ValueError('unsuitable private DNS bridge')
        result[mode] = {'network': name, 'gateway': str(gateway), 'service': str(service)}
    return result


def initial_config(links, password_hash):
    """All upstream DNS is carried by the node core over the two internal bridges."""
    upstream = lambda mode: f"tcp://{links[mode]['gateway']}:{UPSTREAM_PORT}"
    clients = [{'name': mode, 'ids': [link['gateway']], 'upstreams': [upstream(mode)], 'use_global_settings': True}
               for mode, link in links.items()]
    return {'schema_version': 35, 'users': [{'name': 'admin', 'password': password_hash}],
            'http': {'address': f'127.0.0.1:{PANEL_PORT}', 'session_ttl': '15m'},
            'http_proxy': f"http://{links['node']['gateway']}:{FILTER_PROXY_PORT}",
            'dns': {'bind_hosts': [v['service'] for v in links.values()], 'port': DNS_PORT,
                    'allowed_clients': [v['gateway'] for v in links.values()], 'upstream_dns': [upstream('node')],
                    'bootstrap_dns': [], 'fallback_dns': [], 'use_private_ptr_resolvers': False,
                    'serve_plain_dns': True, 'cache_enabled': False, 'cache_size': 0, 'anonymize_client_ip': True},
            'clients': {'persistent': clients, 'runtime_sources': {'rdns': False, 'arp': False, 'whois': False}},
            'querylog': {'enabled': False, 'file_enabled': False, 'interval': '24h'},
            'statistics': {'enabled': False, 'interval': '24h'}, 'dhcp': {'enabled': False},
            'filtering': {'filtering_enabled': True, 'protection_enabled': True, 'filters_update_interval': 24},
            'filters': [{'enabled': True, 'id': 1, 'name': 'AdGuard DNS filter',
                         'url': 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt'}]}


def route(core, value, links):
    import node_policy

    options = value['options']['adguard']
    rules = core.setdefault('routing', {}).setdefault('rules', [])
    incoming = [i['tag'] for i in core['inbounds'] if i['tag'] in ('node', 'node-wg4', 'node-wg6')]
    guards = []
    if not any(o['tag'] == 'block' for o in core['outbounds']):
        core['outbounds'].append({'tag': 'block', 'protocol': 'blackhole'})
    # A WireGuard peer and a VLESS account may have the same display name.
    # Bind each grant to the transport which authenticated its identity.
    wg_inlets = [tag for tag in incoming if tag != 'node']
    allowed = {'node': [], 'warp': []}
    allowed_wg = []
    if any(out['tag'] == 'warp' for out in core['outbounds']):
        health = {'type': 'field', 'inboundTag': ['node'], 'user': ['vpnbot/warp-health']}
        guards.extend([health | {'network': 'udp', 'ip': ['1.1.1.1/32'], 'port': '53', 'outboundTag': 'warp'},
                       health | {'network': 'tcp', 'domain': ['full:www.cloudflare.com'], 'port': '443', 'outboundTag': 'warp-resolve'},
                       health | {'outboundTag': 'block'}])
    if options['controller']:
        for scope, role, mode, _ in node_policy.accounts(value) if value['options'].get('policy') else ():
            allowed['node' if mode == 'direct' else 'warp'].append(f'vpnbot/{scope}/{role}')
        allowed['node'].append('controller')
        allowed_wg.append('controller-wg')
        allowed['warp'].append('vpnbot/warp')
    for peer in value['peers']:
        if not peer['enabled'] or peer['id'] not in options['peers']:
            continue
        if peer.get('channel') == 'wireguard':
            slot = value['identity']['external'][peer['id']]['slot']
            allowed_wg.append(f'external-wg-{slot}')
        else:
            allowed['node'].append(peer['name'])
    for mode, link in links.items():
        tag = 'adguard-' + mode
        core['outbounds'].append({'tag': tag, 'protocol': 'freedom', 'sendThrough': link['gateway'],
                                  'settings': {'redirect': f"{link['service']}:{DNS_PORT}", 'finalRules': [
                                      {'action': 'allow', 'ip': [link['service']+'/32'], 'port': str(DNS_PORT)},
                                      {'action': 'block', 'ip': ['0.0.0.0/0', '::/0'], 'blockDelay': 0}]}})
        upstream = '2606:4700:4700::1111' if mode == 'node' and value['options']['family'] == 6 else '1.1.1.1'
        core['inbounds'].append({'tag': tag+'-up', 'listen': link['gateway'], 'port': UPSTREAM_PORT,
                                 'protocol': 'dokodemo-door', 'settings': {'address': upstream, 'port': 53, 'network': 'tcp'}})
        exit_tag = 'direct' if mode == 'node' else ('warp' if any(o['tag'] == 'warp' for o in core['outbounds']) else 'block')
        guards.append({'type': 'field', 'inboundTag': [tag+'-up'], 'outboundTag': exit_tag})
        if mode == 'node' and wg_inlets and allowed_wg:
            guards.append({'type': 'field', 'inboundTag': wg_inlets, 'user': allowed_wg, 'network': 'tcp,udp',
                           'port': '53', 'outboundTag': tag})
        if allowed[mode]:
            guards.append({'type': 'field', 'inboundTag': ['node'], 'user': allowed[mode], 'network': 'tcp,udp',
                           'port': '53', 'outboundTag': tag})
    guards.append({'type': 'field', 'inboundTag': incoming, 'port': '53', 'outboundTag': 'block'})
    core['dns'] = {'servers': [{'address': links['node']['service'], 'port': DNS_PORT}],
                   'queryStrategy': 'UseIPv4' if value['options']['family'] == 4 else 'UseIPv6',
                   'disableFallback': True, 'disableCache': True, 'tag': 'adguard-core-query'}
    guards.append({'type': 'field', 'inboundTag': ['adguard-core-query'], 'outboundTag': 'adguard-node'})
    # Only the filter service can reach this HTTP client proxy, only for HTTPS downloads.
    core['inbounds'].append({'tag': 'adguard-updates', 'listen': links['node']['gateway'], 'port': FILTER_PROXY_PORT,
                             'protocol': 'http', 'settings': {}})
    guards.extend([{'type': 'field', 'inboundTag': ['adguard-updates'], 'network': 'tcp', 'port': '443', 'outboundTag': 'direct'},
                   {'type': 'field', 'inboundTag': ['adguard-updates'], 'outboundTag': 'block'}])
    rules[:0] = guards


def firewall(links, uid):
    ingress, output = [], []
    for mode, link in links.items():
        bridge = BRIDGES[mode]
        service, gateway = link['service'], link['gateway']
        ports = str(UPSTREAM_PORT) if mode == 'warp' else f'{{ {UPSTREAM_PORT}, {FILTER_PROXY_PORT} }}'
        ingress.append(f'  iifname "{bridge}" ip saddr {service} ip daddr {gateway} tcp dport {ports} accept')
        # Local and other host services cannot query the node DNS or borrow its upstream.
        output.extend([f'  oifname "{bridge}" ip daddr {service} meta skuid {uid} meta l4proto {{ tcp, udp }} th dport {DNS_PORT} accept',
                       f'  oifname "{bridge}" ip daddr {service} ct direction reply ct state established accept',
                       f'  oifname "{bridge}" ip daddr {service} drop',
                       f'  ip daddr {gateway} tcp dport {ports} drop'])
    return ingress, output


def prepare(root, links):
    """The panel credential stays outside the directory writable by AdGuard."""
    import ctypes
    import os
    from pathlib import Path
    import secrets
    import node_state

    root = Path(root) / 'adguard'
    node_state.trusted(root)
    root.mkdir(mode=0o700, exist_ok=True)
    credential = root/'credential'
    node_state.trusted(credential)
    if not credential.exists():
        if (root/'conf/AdGuardHome.yaml').exists() or (root/'layout.json').exists():
            raise ValueError('existing DNS filter credential is missing')
        node_state.atomic(credential, secrets.token_hex(32).encode())
    conf, work = root/'conf', root/'work'
    for directory in (conf, work):
        if directory.is_symlink():
            raise ValueError('unsafe DNS filter directory')
        directory.mkdir(mode=0o700, exist_ok=True)
        os.chown(directory, 65532, 65532)
    path = conf/'AdGuardHome.yaml'
    layout = root/'layout.json'
    if layout.exists() and json.loads(layout.read_bytes()) != links:
        raise ValueError('DNS filter network addresses changed')
    if path.is_symlink() or path.exists() and (not path.is_file() or path.stat().st_nlink != 1):
        raise ValueError('unsafe DNS filter configuration')
    if not path.exists():
        crypt = ctypes.CDLL('libcrypt.so.1')
        crypt.crypt_gensalt.restype = crypt.crypt.restype = ctypes.c_char_p
        salt = crypt.crypt_gensalt(b'$2b$', 12, None, 0)
        hashed = crypt.crypt(credential.read_bytes(), salt) if salt else None
        if not hashed or not hashed.startswith(b'$2b$12$'):
            raise RuntimeError('unable to initialize DNS filter authentication')
        # Never follow a service-owned directory entry as root.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(json.dumps(initial_config(links, hashed.decode())).encode())
            os.fchown(stream.fileno(), 65532, 65532)
    node_state.atomic(layout, json.dumps(links).encode())
    return root


def start(command, root, links, image, label):
    root = prepare(root, links)
    args = ['docker', 'create', '--name', CONTAINER, '--label', label+'=1', '--network', links['node']['network'],
            '--ip', links['node']['service'], '--user', '65532:65532', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--pids-limit', '96', '--memory', '192m', '--memory-swap', '192m',
            '--log-driver', 'none', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=8m',
            '--mount', f'type=bind,src={root}/conf,dst=/conf', '--mount', f'type=bind,src={root}/work,dst=/work',
            '--entrypoint', '/opt/adguardhome/AdGuardHome', image, '--no-check-update', '--web-addr', f'127.0.0.1:{PANEL_PORT}',
            '-c', '/conf/AdGuardHome.yaml', '-w', '/work']
    command(args)
    command(['docker', 'network', 'connect', '--ip', links['warp']['service'], links['warp']['network'], CONTAINER])
    command(['docker', 'start', CONTAINER])


def panel(request, root, info, command):
    """The only HTTP target is the panel's loopback inside its own network namespace."""
    import ctypes
    import os
    from pathlib import Path
    import subprocess
    import sys

    if not info or not info.get('State', {}).get('Running'):
        raise ValueError('DNS panel is unavailable')
    with (root/'adguard/credential').open('rb') as f:
        credential = f.read(65)
    if len(credential) != 64:
        raise ValueError('DNS panel authentication is unavailable')
    pid = int(info['State']['Pid'])
    fd = os.open(f'/proc/{pid}/ns/net', os.O_RDONLY | os.O_CLOEXEC)
    try:
        if os.fstat(fd).st_ino == os.stat('/proc/self/ns/net').st_ino:
            raise ValueError('DNS panel network is not isolated')
        libc = ctypes.CDLL(None, use_errno=True)
        def isolate():
            if libc.setns(fd, 0x40000000) != 0:
                os._exit(1)
            os.setgroups([])
            os.setgid(65532)
            os.setuid(65532)
        helper = subprocess.run([sys.executable, '-I', str(Path(__file__).resolve()), 'panel'],
                                input=json.dumps([credential.decode(), request]).encode(), capture_output=True,
                                pass_fds=(fd,), preexec_fn=isolate, timeout=16, check=True)
        return json.loads(helper.stdout)
    finally:
        os.close(fd)


# AdGuard authenticates the bridge as an administrator. Only expose operations
# which preserve its fixed listeners, DNS paths, client identities and log policy.
_PANEL_POST = frozenset({
    'filtering/config', 'filtering/add_url', 'filtering/remove_url', 'filtering/set_url',
    'filtering/refresh', 'filtering/set_rules', 'protection', 'cache_clear', 'querylog_clear',
    'version.json', 'stats_reset', 'clients/search', 'safebrowsing/enable', 'safebrowsing/disable',
    'parental/enable', 'parental/disable', 'rewrite/add', 'rewrite/delete',
})
_PANEL_PUT = frozenset({'profile/update', 'rewrite/update', 'rewrite/settings/update',
                        'safesearch/settings', 'blocked_services/update'})


def panel_operation(method, resource, content):
    if method in ('GET', 'HEAD'):
        return resource not in ('logout', 'install/get_addresses')
    if resource not in {'POST': _PANEL_POST, 'PUT': _PANEL_PUT}.get(method, ()):
        return False
    if resource in ('filtering/add_url', 'filtering/set_url'):
        try:
            payload = json.loads(content)
            if not isinstance(payload, dict) or set(payload) - {'name', 'url', 'data', 'whitelist'}:
                return False
            details = payload if resource == 'filtering/add_url' else payload['data']
            if not isinstance(details, dict) or any(k != k.lower() for k in details):
                return False
            url = urlsplit(details['url'])
            return url.scheme == 'https' and bool(url.hostname) and url.port in (None, 443) and url.username is None
        except (ValueError, KeyError, TypeError, AttributeError):
            return False
    return True


def panel_http(auth, request):
    import base64
    import http.client
    import re
    import urllib.parse

    if set(request) != {'method', 'path', 'body', 'type'} or not all(isinstance(v,str) for v in request.values()):
        raise ValueError('invalid panel request')
    method, target = request['method'], request['path']
    url = urllib.parse.urlsplit(target)
    if method not in ('GET','HEAD','POST','PUT','DELETE','PATCH') or len(target) > 4096 or url.netloc or url.scheme or url.fragment \
            or not re.fullmatch(r'/[a-zA-Z0-9._/-]*', url.path) or '//' in target or any(c in url.path.split('/') for c in ('.','..')) \
            or any(ord(c)<32 or ord(c)>126 for c in target):
        raise ValueError('invalid panel resource')
    static = url.path == '/' or re.fullmatch(r'/(?:[a-zA-Z0-9_-]+/)*[a-zA-Z0-9_.-]+\.(?:html|js|css|svg|png|ico|woff2?|ttf|json|webp)', url.path)
    if not url.path.startswith('/control/') and not (static and method in ('GET', 'HEAD')):
        raise ValueError('unsupported panel resource')
    content = base64.b64decode(request['body'],validate=True)
    if len(content) > 1024*1024 or request['type'] not in ('','application/json','text/plain','application/x-www-form-urlencoded'):
        raise ValueError('invalid panel body')
    if url.path.startswith('/control/') and not panel_operation(method, url.path[len('/control/'):], content):
        # The native UI treats 403 as an expired login and redirects to its login page.
        return {'status': 409, 'type': 'text/plain',
                'body': base64.b64encode(b'This setting is managed by VPNBot.').decode()}
    headers = {'Authorization': 'Basic '+base64.b64encode(('admin:'+auth).encode()).decode()}
    if request['type']:
        headers['Content-Type'] = request['type']
    conn = http.client.HTTPConnection('127.0.0.1', PANEL_PORT, timeout=12)
    try:
        conn.request(method, target, body=content if content else None, headers=headers)
        reply = conn.getresponse()
        body = reply.read(8*1024*1024+1)
        if len(body) > 8*1024*1024:
            raise ValueError('panel response exceeds limit')
        return {'status': reply.status, 'type': reply.getheader('Content-Type','').split(';')[0],
                'body': base64.b64encode(body).decode()}
    finally:
        conn.close()


if __name__ == '__main__':
    import sys
    if sys.argv[1:] != ['panel']:
        sys.exit(2)
    try:
        auth, request = json.loads(sys.stdin.buffer.read(2*1024*1024+1))
        print(json.dumps(panel_http(auth, request), separators=(',',':')))
    except Exception:
        sys.exit(1)
