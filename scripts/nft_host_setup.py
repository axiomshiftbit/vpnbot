#!/usr/bin/env python3
"""Adapt an existing VPNBot nft profile without reloading the host ruleset."""
import argparse
import copy
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nft_node_sets as sets

TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|#[^\n]*|[{}]')
MANAGED = {'node4_sources', 'node4_admins', 'node4_ssh', 'node6_sources',
           'node6_admins', 'node6_ssh', 'node6_public', 'egress6_snat', 'ipv6_routers'}


def run(args, data=None):
    result = subprocess.run(list(map(str, args)), input=data, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise ValueError('Firewall command failed; details suppressed to protect configuration data')
    return result.stdout


def block(text, pattern):
    # Comments/quoted braces must not affect block boundaries.
    masked = re.sub(r'#[^\n]*', lambda m: ' ' * len(m[0]), text)
    matches = list(re.finditer(pattern, masked, re.M))
    if len(matches) != 1:
        raise ValueError('Missing or ambiguous firewall declaration')
    start = matches[0].end()
    depth = 1
    for token in TOKEN.finditer(text, start):
        if token[0] == '{': depth += 1
        if token[0] == '}': depth -= 1
        if depth == 0: return start, token.start()
    raise ValueError('Unclosed firewall declaration')


def elements(text, name, values, kind='set', merge=False):
    a, b = block(text, r'^\s*table\s+ip6\s+filter\s*\{')
    if name.startswith('node4_'):
        a, b = block(text, r'^\s*table\s+ip\s+filter\s*\{')
    table = text[a:b]
    c, d = block(table, r'\b'+kind+r'\s+'+name+r'\s*\{')
    body = table[c:d]
    active = re.sub(r'#[^\n]*', lambda m: ' '*len(m[0]), body)
    matches = list(re.finditer(r'\belements\s*=\s*\{([^{}]*)\}\s*;?', active))
    if len(matches) > 1:
        raise ValueError('Ambiguous set elements')
    values = list(values)
    if matches:
        match = matches[0]
        old = [s.strip() for s in match[1].split(',') if s.strip()]
        if merge: values = list(dict.fromkeys(old + values))
        if kind == 'map':
            # Only our fixed container address is managed; retain other mappings.
            old = [s for s in old if not re.match(r'^fd42:7662:6::9\s+:', s)]
            values = old + values
        body = body[:match.start()] + body[match.end():]
    if name.endswith('_ssh'):
        values = list(map(str, ipaddress.collapse_addresses(ipaddress.ip_network(x) for x in values)))
    value = '\n        elements = { '+', '.join(values)+' };' if values else ''
    body = body.rstrip() + value + '\n    '
    table = table[:c]+body+table[d:]
    return text[:a]+table+text[b:]


def public(value, family):
    addr = ipaddress.ip_address(value)
    if addr.version != family or not addr.is_global or addr.is_multicast or '%' in value \
            or (family == 6 and (addr not in ipaddress.ip_network('2000::/3')
                                or addr in ipaddress.ip_network('2002::/16'))):
        raise ValueError('A public unicast address is required')
    return str(addr)


def node_fields(text):
    """Migrate the known minimal profile: explicit installer ACLs complement MyServer."""
    if 'define NODE_SSH_PORTS' not in text:
        text = text.replace('flush ruleset', 'define NODE_SSH_PORTS = { 22 }\nflush ruleset', 1)
        text = re.sub(r'(?m)^(.*tcp dport )22( .*jump ssh\s*)$', r'\1$NODE_SSH_PORTS\2', text)
    for version in (4, 6):
        family = 'ip' if version == 4 else 'ip6'
        a, b = block(text, r'^\s*table\s+'+family+r'\s+filter\s*\{')
        body = text[a:b]
        added = []
        for suffix in ('sources', 'admins', 'ssh'):
            name = 'node'+str(version)+'_'+suffix
            if not re.search(r'\bset\s+'+name+r'\s*\{', re.sub(r'#[^\n]*', '', body)):
                added.append('    set '+name+' { type ipv'+str(version)+'_addr;'+(' flags interval;' if suffix == 'ssh' else '')+' }\n')
        body = '\n'+''.join(added)+body if added else body
        marker = '# VPNBOT_INSTALLER_ACL'+str(version)
        if marker not in body:
            c, d = block(body, r'\bchain\s+input\s*\{')
            # Insert immediately before the old SSH rule, after anti-spoof/NDP/conntrack.
            match = re.search(r'(?m)^\s*iifname [^\n]+tcp dport \$NODE_SSH_PORTS[^\n]+jump ssh\s*$', body[c:d])
            if not match: raise ValueError('Unsupported minimal firewall SSH rule')
            pos = c+match.start()
            prefix = '        iifname "'+re.search(r'iifname "([^"]+)"', match[0])[1]+'" '+family+' saddr @node'+str(version)
            rules = '\n        '+marker+'\n'
            rules += prefix+'_admins tcp dport $NODE_SSH_PORTS ct state new tcp flags & (fin|syn|rst|ack) == syn jump ssh\n'
            rules += prefix+'_ssh tcp dport $NODE_SSH_PORTS ct state new tcp flags & (fin|syn|rst|ack) == syn jump ssh\n'
            rules += prefix+'_sources ct status dnat ct original proto-dst 443 tcp dport 8443 counter accept\n'
            rules += prefix+'_sources ct status dnat ct original proto-dst { 51820, 51821 } udp dport { 51830, 51831 } counter accept\n'
            body = body[:pos]+rules+body[pos:]
        # The runtime guard authorizes VPN-only sources and remaps only enabled
        # channels. The base chain must also accept those DNAT packets when its
        # installer/MyServer lists predate the node settings.
        c, d = block(body, r'\bchain\s+input\s*\{')
        match = re.search(r'(?m)^\s*(iifname (?:"[^"]+"|\$WAN))[^\n]*tcp dport \$NODE_SSH_PORTS[^\n]*jump ssh(?:_log)?\s*$', body[c:d])
        if not match: raise ValueError('Unsupported minimal firewall SSH rule')
        additions = []
        for ports in ('443 tcp dport 8443', '{ 51820, 51821 } udp dport { 51830, 51831 }'):
            rule = match[1]+' ct status dnat ct original proto-dst '+ports+' counter accept'
            if not re.search(r'(?m)^\s*'+re.escape(rule)+r'\s*$', body[c:d]): additions.append('        '+rule+'\n')
        pos = c+match.start()
        if additions: body = body[:pos]+'\n'+''.join(additions)+body[pos:]
        text = text[:a]+body+text[b:]
    return text


def render(text, host, mode):
    """Only addresses, WAN/SSH bindings and installer-owned sets are changed."""
    node = '# VPNBOT_MANAGED_NODE_HOST' in text.splitlines()
    if mode == 'node' and not node or mode == 'full' and node:
        raise ValueError('Firewall profile does not match installation mode')
    interface = host['interface']
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', interface):
        raise ValueError('Invalid interface')
    text = sets.prepare(text)
    if node: text = node_fields(text)
    addresses = {v: public(host['public'+str(v)], v) if host.get('public'+str(v)) else '' for v in (4, 6)}
    defines = list(re.finditer(r'(?m)^(\s*define PUBLIC_IP\s*=\s*)([^\s;#]+)', text))
    if len(defines) > 1: raise ValueError('Ambiguous public IPv4')
    if defines and addresses[4]:
        match = defines[0]
        text = text[:match.start(2)] + addresses[4] + text[match.end(2):]
    # Replace only a single WAN name. Bridges and service interfaces stay intact.
    wan = re.findall(r'(?m)^\s*define WAN\s*=\s*"([^"]+)"', text)
    if wan:
        if len(wan) != 1: raise ValueError('Ambiguous WAN')
        text = re.sub(r'(?m)^(\s*define WAN\s*=\s*)"[^"]+"', lambda m: m[1]+'"'+interface+'"', text)
    else:
        names = set(re.findall(r'\b[io]ifname\s+"((?:eth|ens|enp|net)[A-Za-z0-9_.:-]*)"', re.sub(r'#[^\n]*', '', text)))
        if len(names) > 1: raise ValueError('Multiple WAN interfaces require explicit configuration')
        if names:
            old = names.pop()
            text = re.sub(r'(\b[io]ifname\s+)"'+re.escape(old)+'"', lambda m: m[1]+'"'+interface+'"', text)
            # Same WAN can occur inside an NDP interface list.
            text = re.sub(r'(\b[io]ifname\s*\{[^}\n]*)"'+re.escape(old)+'"', lambda m: m[1]+'"'+interface+'"', text)
    for value in host.get('routers', []):
        if not ipaddress.IPv6Address(value).is_link_local or '%' in value:
            raise ValueError('Only explicit link-local IPv6 routers are accepted')
    # Absence of usable IPv6 closes local ingress/SNAT, but never clears trust lists.
    text = elements(text, 'node6_public', [addresses[6]] if addresses[6] else [])
    text = elements(text, 'ipv6_routers', host.get('routers', []), merge=True)
    if not node:
        text = elements(text, 'egress6_snat', ['fd42:7662:6::9 : '+addresses[6]] if addresses[6] else [], 'map')
        text = elements(text, 'node6_sources', [public(x, 6) for x in host.get('sources6', [])], merge=True)
    else:
        for v in (4, 6):
            sources = [public(x, v) for x in host['sources'] if ipaddress.ip_address(x).version == v]
            admins = [public(x, v) for x in host['admins']+host['sources'] if ipaddress.ip_address(x).version == v]
            networks = [str(ipaddress.ip_network(x)) for x in host.get('ssh_networks', []) if ipaddress.ip_network(x).version == v]
            for suffix, values in [('sources', sources), ('admins', sorted(set(admins))), ('ssh', networks)]:
                text = elements(text, 'node'+str(v)+'_'+suffix, values, merge=True)
        ports = host['ssh_ports']
        if not ports or any(type(p) != int or not 1 <= p <= 65535 for p in ports):
            raise ValueError('Invalid SSH ports')
        # A bootstrap profile separates explicit management access from its
        # legacy ASN port. Do not move that ASN policy to the management port.
        binding = 'SERVER_SSH_PORTS' if re.search(r'(?m)^\s*define SERVER_SSH_PORTS\s*=', text) else 'NODE_SSH_PORTS'
        text = re.sub(r'(?m)^(\s*define '+binding+r'\s*=)[^\n]+',
                      lambda m: m[1]+' { '+', '.join(map(str, sorted(set(ports))))+' }', text)
        if binding == 'SERVER_SSH_PORTS':
            text = re.sub(r'(@node[46]_(?:admins|ssh) tcp dport )\$NODE_SSH_PORTS',
                          r'\1$SERVER_SSH_PORTS', text)
            # The later source guard must enforce the same explicit installer
            # ACL on the selected management port. Keep the ASN port separate.
            text = re.sub(r'tcp dport \$NODE_SSH_PORTS (ip6? saddr @node[46]_(?:admins|ssh) return)',
                          r'tcp dport $SERVER_SSH_PORTS \1', text)
    return text


def discover():
    host = dict(interface='', public4='', public6='', routers=[], sources6=[])
    # Route lookup does not send network packets. No external "what is my IP" service.
    for v, target in [(4, '1.1.1.1'), (6, '2606:4700:4700::1111')]:
        result = subprocess.run(['ip', '-j', '-'+str(v), 'route', 'get', target], capture_output=True, text=True, timeout=10)
        if result.returncode: continue
        routes = json.loads(result.stdout)
        if len(routes) != 1: raise ValueError('Ambiguous default route')
        route = routes[0]
        interface = route.get('dev', '')
        if host['interface'] and interface != host['interface']:
            raise ValueError('IPv4 and IPv6 use different WAN interfaces')
        host['interface'] = interface
        local = json.loads(run(['ip', '-j', 'address', 'show', 'dev', interface]))
        source = route.get('prefsrc', route.get('src', ''))
        valid = [x['local'] for item in local for x in item.get('addr_info', [])
                 if x.get('scope') == 'global' and x.get('family') == ('inet' if v == 4 else 'inet6')
                 and not any(x.get(flag) or flag in x.get('flags', []) for flag in ('tentative', 'dadfailed', 'deprecated', 'temporary'))]
        if source not in valid: raise ValueError('Default route has no stable assigned source')
        host['public'+str(v)] = public(source, v)
        gateway = route.get('gateway', '')
        if v == 6 and gateway and ipaddress.ip_address(gateway).is_link_local:
            host['routers'] = [str(ipaddress.ip_address(gateway))]
    if not host['interface']: raise ValueError('No usable WAN route')
    host['sources6'] = os.environ.get('VPNBOT_NFT_SOURCES6', '').replace(',', ' ').split()
    return host


def compile_rules(text):
    # Even a supplied profile containing flush ruleset runs ONLY in a new namespace.
    script = ('import subprocess,sys; '
              'p=subprocess.run(["nft","-f","-"],input=sys.stdin.read(),text=True,capture_output=True); '
              'sys.exit(1) if p.returncode else None; '
              'p=subprocess.run(["nft","-j","list","ruleset"],capture_output=True); '
              'sys.stdout.buffer.write(p.stdout);sys.exit(p.returncode)')
    return json.loads(run(['unshare', '--net', sys.executable, '-I', '-c', script], text))


def clean(value):
    if isinstance(value, list): return [clean(x) for x in value]
    if not isinstance(value, dict): return value
    # libnftables may fold an anonymous singleton set on JSON re-import.
    if set(value) == {'set'} and isinstance(value['set'], list) and len(value['set']) == 1:
        return clean(value['set'][0])
    return {k: (None if k == 'counter' else clean(v)) for k, v in value.items()
            if k not in ('handle', 'index', 'packets', 'bytes', 'expires')}


def objects(document, kind):
    return [x[kind] for x in document['nftables'] if kind in x]


def key(value):
    return value['family'], value.get('table', value.get('name')), value.get('name', value.get('chain'))


def equal_elements(a, b):
    return sorted(json.dumps(clean(x), sort_keys=True) for x in a) == sorted(json.dumps(clean(x), sort_keys=True) for x in b)


def delta(before, after, live):
    """Atomic changes to affected chains/sets only; unexpected live drift refuses."""
    commands, rollback = [], []
    tables = {(x['family'], x['name']) for x in objects(live, 'table')}
    missing = {(x['family'], x['name']) for x in objects(after, 'table')} - tables
    # A live table of the profile's name that has none of its chains is not the profile:
    # Docker's first start leaves "ip filter" with only its own DOCKER*/FORWARD chains.
    # The profile's objects are added next to those leftovers, as for a missing table.
    live_chains = {(x['family'], x['table'], x['name']) for x in objects(live, 'chain')}
    wanted_chains = {}
    for x in objects(after, 'chain'):
        wanted_chains.setdefault((x['family'], x['table']), []).append(x['name'])
    stale = {t for t, names in wanted_chains.items()
             if t in tables and not any((t[0], t[1], name) in live_chains for name in names)}
    # Наборы и карты разделяют пространство имён. Откат вправе удалять
    # только те объекты, которые действительно впервые создал этот профиль.
    live_names = {key(obj) for kind in ('set', 'map') for obj in objects(live, kind)}
    if any(key(obj) in live_names and key(obj)[:2] in stale
           for kind in ('set', 'map') for obj in objects(after, kind)):
        raise ValueError('A firewall set or map already exists in the shared table')
    # A supplied, not-yet-loaded base profile can be installed without deleting
    # unrelated tables (including Docker and the test host's LAN guard).
    for item in after['nftables']:
        kind = next(iter(item))
        obj = item[kind]
        if kind == 'metainfo': continue
        identity = obj['family'], obj['name'] if kind == 'table' else obj['table']
        if identity in missing or (identity in stale and kind != 'table'):
            commands.append({'add': {kind: {k:v for k,v in obj.items() if k not in ('handle', 'index')}}})
    rollback += [{'delete': {'table': dict(family=f, name=t)}} for f, t in sorted(missing)]
    for family, table in sorted(stale):
        chains_added = [dict(family=family, table=table, name=x['name']) for x in objects(after, 'chain')
                        if (x['family'], x['table']) == (family, table)]
        rollback += [{'flush': {'chain': name}} for name in chains_added]
        rollback += [{'delete': {'chain': name}} for name in chains_added]
        rollback += [{'delete': {kind: dict(family=family, table=table, name=x['name'])}}
                     for kind in ('set', 'map') for x in objects(after, kind) if (x['family'], x['table']) == (family, table)]
    missing |= stale
    for kind in ('set', 'map'):
        current = {key(x): x for x in objects(live, kind)}
        for obj in objects(after, kind):
            ident = key(obj)
            if obj['name'] not in MANAGED: continue
            if ident[:2] in missing: continue
            value = current.get(ident)
            definition = {k: v for k, v in obj.items() if k not in ('handle', 'elem')}
            if value and clean({k:v for k,v in value.items() if k != 'elem'}) != clean(definition):
                raise ValueError('Managed set type differs from profile')
            name = {k: obj[k] for k in ('family', 'table', 'name')}
            items = copy.deepcopy(obj.get('elem', []))
            if value and obj['name'] != 'node6_public':
                for item in value.get('elem', []):
                    if obj['name'] == 'egress6_snat':
                        if not isinstance(item, list) or len(item) != 2:
                            raise ValueError('Unsupported live SNAT map element')
                        if item[0] == 'fd42:7662:6::9': continue
                        if any(x[0] == item[0] and x != item for x in items):
                            raise ValueError('Unrelated SNAT mapping differs on disk and in memory')
                    if item not in items: items.append(item)
            if value and equal_elements(value.get('elem', []), items): continue
            if value:
                commands.append({'flush': {kind: name}})
                rollback.append({'flush': {kind: name}})
                if value.get('elem'):
                    rollback.append({'add': {'element': name | {'elem': value['elem']}}})
            else:
                commands.append({'add': {kind: definition}})
                rollback.insert(0, {'delete': {kind: name}})
            if items: commands.append({'add': {'element': name | {'elem': items}}})
    def chains(document):
        result = {}
        for rule in objects(document, 'rule'):
            result.setdefault((rule['family'], rule['table'], rule['chain']), []).append(rule)
        return result
    old, new, current = map(chains, (before, after, live))
    for ident in old.keys() | new.keys():
        if ident[:2] in missing: continue
        a, b, c = old.get(ident, []), new.get(ident, []), current.get(ident, [])
        if clean(a) == clean(b) or clean(c) == clean(b): continue
        if clean(c) != clean(a): raise ValueError('Changed live chain differs from supplied profile')
        family, table, chain = ident
        if (family, table) not in tables: raise ValueError('Base firewall is not active')
        name = dict(family=family, table=table, name=chain)
        commands.append({'flush': {'chain': name}})
        # Rollback rules precede deletion of any newly created sets.
        restore = [{'flush': {'chain': name}}]
        for target, rules in [(commands, b), (restore, c)]:
            for rule in rules:
                target.append({'add': {'rule': {k:v for k,v in rule.items() if k not in ('handle', 'index')}}})
        rollback = restore + rollback
    return {'nftables': commands}, {'nftables': rollback}


def verify(change, candidate, live):
    expected = {(x['family'], x['table'], x['chain']): [] for x in objects(candidate, 'rule')}
    actual = {(x['family'], x['table'], x['chain']): [] for x in objects(live, 'rule')}
    for doc, target in [(candidate, expected), (live, actual)]:
        for rule in objects(doc, 'rule'):
            target[(rule['family'], rule['table'], rule['chain'])].append(rule)
    current = {key(x): x for kind in ('set', 'map') for x in objects(live, kind)}
    wanted = {}
    for command in change['nftables']:
        for kind in ('set', 'map'):
            value = command.get('flush', {}).get(kind)
            if value: wanted[key(value)] = []
            value = command.get('add', {}).get(kind)
            if value and value['name'] in MANAGED: wanted[key(value)] = value.get('elem', [])
        value = command.get('flush', {}).get('chain')
        if value:
            ident = (value['family'], value['table'], value['name'])
            if clean(expected.get(ident, [])) != clean(actual.get(ident, [])):
                raise ValueError('Applied chain did not pass readback')
        value = command.get('add', {}).get('element')
        if value: wanted[key(value)] = value.get('elem', [])
    for ident, values in wanted.items():
        if ident not in current or not equal_elements(values, current[ident].get('elem', [])):
            raise ValueError('Applied addresses did not pass readback')


def profile_rules(document, text):
    # Included guards have independent owners/locks and must never be rewritten.
    tables = set(re.findall(r'(?m)^\s*table\s+(ip6?|inet|bridge|netdev|arp)\s+([A-Za-z0-9_]+)\s*\{',
                            re.sub(r'#[^\n]*', '', text)))
    selected = []
    for item in document['nftables']:
        kind = next(iter(item))
        obj = item[kind]
        if kind == 'metainfo': continue
        if (obj['family'], obj['name'] if kind == 'table' else obj['table']) in tables:
            selected.append(item)
    return {'nftables': selected}


def ensure(path, host, mode, check=False):
    path = Path(path).absolute()
    sets.trusted(path)
    if not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError('A regular root-owned /etc/nftables.conf is required')
    before = path.read_text()
    after = render(before, host, mode)
    candidate = profile_rules(compile_rules(after), after)
    live = json.loads(run(['nft', '-j', 'list', 'ruleset']))
    try:
        original = profile_rules(compile_rules(before), before)
    except ValueError:
        # A fresh template can contain an unresolved PUBLIC_IP placeholder.
        # Never guess an old policy when any of its tables is already active.
        existing = {(x['family'], x['name']) for x in objects(live, 'table')}
        if any((x['family'], x['name']) in existing for x in objects(candidate, 'table')): raise
        original = {'nftables': []}
    change, reverse = delta(original, candidate, live)
    if not change['nftables'] and before == after: return False
    run(['nft', '-j', '-c', '-f', '-'], json.dumps(change))
    if check: return True
    permissions = path.stat().st_mode & 0o777
    backup = path.with_name(path.name+'.before-vpnbot-setup')
    sets.trusted(backup)
    sets.atomic(backup, before, 0o600)
    applied, settled = False, False
    watcher, child = watchdog(path, before, after, permissions, reverse)
    try:
        if path.read_text() != before: raise ValueError('Firewall changed during preparation')
        if change['nftables']:
            run(['nft', '-j', '-f', '-'], json.dumps(change))
            applied = True
            verify(change, candidate, json.loads(run(['nft', '-j', 'list', 'ruleset'])))
        sets.atomic(path, after, permissions)
        settled = True
    except BaseException:
        if applied: run(['nft', '-j', '-f', '-'], json.dumps(reverse))
        sets.atomic(path, before, permissions)
        settled = True
        raise
    finally:
        # On abrupt termination the pipe closes without this acknowledgement;
        # the detached child restores the disk file and the narrow nft transaction.
        if settled: os.write(watcher, b'1')
        os.close(watcher)
        os.waitpid(child, 0)
    return True


def watchdog(path, before, after, permissions, reverse):
    reader, writer = os.pipe()
    parent = os.getpid()
    child = os.fork()
    if child:
        os.close(reader)
        return writer, child
    os.close(writer)
    os.setsid()
    null = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2): os.dup2(null, fd)
    try:
        ready, _, _ = select.select([reader], [], [], 600)
        if ready and os.read(reader, 1) == b'1': os._exit(0)
        if not ready:
            # Stop a hung writer before rollback; it must not commit afterwards.
            os.kill(parent, signal.SIGKILL)
        try:
            run(['nft', '-j', '-f', '-'], json.dumps(reverse))
        finally:
            if path.read_text() in (before, after): sets.atomic(path, before, permissions)
    except BaseException:
        os._exit(1)
    os._exit(0)


def configure(path=Path('/etc/nftables.conf'), host=None, mode='full', check=False):
    if not Path(path).exists():
        print('[INFO] /etc/nftables.conf отсутствует: профиль доступа не создаётся автоматически')
        return False
    fd = os.open('/run/lock/nft-docker-watch.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        changed = ensure(path, host if host is not None else discover(), mode, check)
        if not check:
            run(['systemctl', 'enable', 'nftables.service'])
            # Нода на чистом сервере: служба выключена, а итоговая проверка
            # установщика требует её активной. Профиль ноды уже записан с
            # адресами и подключает защиту ноды (guard*.nft), поэтому запуск
            # перезагружает те же правила. Основной бот службу не запускает:
            # при Docker с iptables flush ruleset снял бы его цепочки.
            if mode == 'node' and subprocess.run(['systemctl', 'is-active', '--quiet', 'nftables.service']).returncode:
                run(['systemctl', 'start', 'nftables.service'])
        return changed
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path('/etc/nftables.conf'))
    parser.add_argument('--check', action='store_true', help='Validate without changing files, rules or services')
    args = parser.parse_args()
    if os.geteuid() != 0: raise ValueError('Run as root')
    changed = configure(args.config, check=args.check)
    print('[OK] nftables: '+('требуется согласование адресов' if args.check and changed else 'адреса согласованы')+
          ('; проверка без изменений' if args.check else '; списки доступа и посторонние таблицы сохранены'))


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, subprocess.SubprocessError):
        raise SystemExit('Не удалось согласовать nftables: проверьте профиль, адреса и действующие правила; детали скрыты')
