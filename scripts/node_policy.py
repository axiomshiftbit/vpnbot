"""Compile named destination lists for authenticated managed-node clients."""
from copy import deepcopy
import hashlib
import hmac
import ipaddress
import re
import uuid


def peer_scope(identity):
    return 'peer-' + hashlib.sha256(identity.encode()).hexdigest()[:20]


def relay_login(identity, scope, mode, revision=None):
    message = f'vpnbot/policy/{scope}/{mode}'.encode()
    if revision:
        message += b'/' + revision.encode()
    return str(uuid.UUID(bytes=hmac.digest(identity.encode(), message, 'sha256')[:16], version=4))


def validate(value):
    if not isinstance(value, dict) or set(value) - {'revision', 'controller_ips'} != {'lists', 'bindings'}:
        raise ValueError('invalid routing policy')
    if 'revision' in value and not re.fullmatch(r'[a-f0-9]{32}', value['revision']):
        raise ValueError('invalid policy revision')
    lists, bindings = value['lists'], value['bindings']
    if not isinstance(lists, dict) or len(lists) > 128 or not isinstance(bindings, dict) or len(bindings) > 256:
        raise ValueError('invalid routing policy size')
    for name, parts in lists.items():
        if not re.fullmatch(r'[\w .-]{1,64}', name) or not isinstance(parts, dict) or set(parts) - {'domain', 'ip'}:
            raise ValueError('invalid named list')
        if not any(parts.values()):
            raise ValueError('empty named list')
        for kind, entries in parts.items():
            if not isinstance(entries, list):
                raise ValueError('invalid list entries')
            for item in entries:
                if not isinstance(item, str) or not 1 <= len(item) <= 1024 or any(ord(ch) < 32 for ch in item):
                    raise ValueError('invalid list entry')
                if kind == 'ip':
                    ipaddress.ip_network(item, strict=False)
                elif not re.fullmatch(r'(full|domain|keyword|regexp):.+', item):
                    raise ValueError('invalid domain matcher')
    controller_ips = value.get('controller_ips', [])
    if not isinstance(controller_ips, list) or len(controller_ips) > 200000:
        raise ValueError('invalid controller IP list')
    if controller_ips and 'revision' not in value:
        raise ValueError('controller IP list needs a revision')
    for item in controller_ips:
        if not isinstance(item, str) or len(item) > 64:
            raise ValueError('invalid controller CIDR')
        ipaddress.ip_network(item, strict=False)
    # Bound work before expanding lists across authenticated routes. Multiple
    # users can share the same large list; a wire-size check alone misses it.
    weight = {name: sum(len(item.encode()) + 8 for entries in parts.values() for item in entries)
              for name, parts in lists.items()}
    controller_cost = sum(len(item) + 8 for item in controller_ips)
    total_cost = controller_cost * 5
    for scope, rows in bindings.items():
        if not re.fullmatch(r'all|(?:peer|bot)-[a-f0-9]{20}', scope) or not isinstance(rows, list) or not len(rows) <= 128:
            raise ValueError('invalid policy subject')
        seen = set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != {'list', 'action'} or row['list'] not in lists or row['list'] in seen:
                raise ValueError('invalid list assignment')
            seen.add(row['list'])
            if row['action'] not in (('block',) if scope == 'all' else ('block', 'direct', 'warp')):
                raise ValueError('invalid routing action')
    for scope, rows in bindings.items():
        assigned = rows if scope == 'all' else bindings.get('all', []) + rows
        domain_choices = sum(1 for row in rows if row['action'] != 'block' and lists[row['list']].get('domain'))
        contexts = domain_choices + 2 if scope.startswith('bot-') else 2 if scope == 'all' else 1
        size = sum(weight[row['list']] + 256 for row in assigned)
        ip_size = sum(weight[row['list']] for row in assigned if lists[row['list']].get('ip'))
        if scope.startswith('bot-'):
            ip_size += controller_cost
            size += controller_cost
        total_cost += contexts * (size + ip_size * domain_choices)
    if total_cost > 12 * 1024 * 1024:
        raise ValueError('compiled destination policy too large')
    return value


def accounts(value):
    policy = value['options']['policy']
    scopes = [scope for scope in policy['bindings'] if scope.startswith('bot-')]
    if policy.get('controller_ips'):
        scopes.append('controller')
    for scope in scopes:
        for role, mode in [('direct', 'direct'), ('warp', 'warp'), *[
                (f'row-{i}', row['action']) for i, row in enumerate(policy['bindings'].get(scope, []))
                if row['action'] != 'block' and value['options']['policy']['lists'][row['list']].get('domain')]]:
            yield scope, role, mode, relay_login(value['identity']['uuid'], scope, role, value['options']['policy'].get('revision'))


def compile_policy(main, strict, value):
    policy = value['options'].get('policy')
    if not policy or not (any(policy['bindings'].values()) or policy.get('controller_ips')):
        return
    bindings = policy['bindings']
    lists = policy['lists']
    original = main['inbounds'][0]['settings']['clients'][0]
    incoming = [i['tag'] for i in main['inbounds'] if i['tag'] in ('node', 'node-wg4', 'node-wg6')]
    wg = [tag for tag in incoming if tag != 'node']
    subjects = []
    for scope, role, mode, login in accounts(value):
        email = f'vpnbot/{scope}/{role}'
        client = dict(original, email=email)
        client['password' if 'password' in original else 'id'] = login
        main['inbounds'][0]['settings']['clients'].append(client)
        subjects.append((scope, mode, ['node'], email, role))
    for peer in value['peers']:
        scope = peer_scope(peer['id'])
        if scope not in bindings or not peer['enabled']:
            continue
        if peer.get('channel') == 'wireguard':
            if wg:
                slot = value['identity']['external'][peer['id']]['slot']
                subjects.append((scope, 'direct', wg, f'external-wg-{slot}', None))
        else:
            subjects.append((scope, 'direct', ['node'], peer['name'], None))
    if policy.get('controller_ips'):
        subjects.append(('controller', 'direct', ['node'], 'controller', None))
        if strict:
            subjects.append(('controller', 'warp', ['node'], 'vpnbot/warp', None))
        if wg:
            subjects.append(('controller', 'direct', wg, 'controller-wg', None))
    if bindings.get('all'):
        subjects += [('all', 'warp', ['node'], 'vpnbot/warp', None), ('all', 'direct', incoming, None, None)]

    rules = main.setdefault('routing', {}).setdefault('rules', [])
    # Keep service-specific DNS, diagnostic and torrent guards ahead of every
    # policy. Insert before the existing unconditional WARP controller route.
    position = next((i for i, r in enumerate(rules) if r.get('user') == ['vpnbot/warp'] and 'port' not in r), len(rules))
    if not any(o['tag'] == 'block' for o in main['outbounds']):
        main['outbounds'].append({'tag': 'block', 'protocol': 'blackhole'})
    direct = next(o for o in main['outbounds'] if o['tag'] == 'direct')
    if strict:
        strict['outbounds'].append(deepcopy(direct))
    selection = []
    if policy.get('controller_ips'):
        # Verify the new authenticated channel even when the configured list
        # blocks the connectivity check's IP. This identity has one destination.
        email = 'vpnbot/controller-health'
        login = relay_login(value['identity']['uuid'], 'controller', 'health', policy['revision'])
        main['inbounds'][0]['settings']['clients'].append(original | {
            'email': email, 'password' if 'password' in original else 'id': login})
        field = {'type': 'field', 'inboundTag': ['node'], 'user': [email]}
        selection.extend([field | {'network': 'tcp', 'domain': ['full:www.gstatic.com'], 'port': '443', 'outboundTag': 'direct'},
                          field | {'outboundTag': 'block'}])
    for index, (scope, default, incoming_tags, email, role) in enumerate(subjects):
        personal = bindings.get(scope, []) if scope != 'all' else []
        if role and role.startswith('row-'):
            cutoff = int(role[4:])
            personal = [row for i, row in enumerate(personal) if row['action'] == 'block' or i < cutoff]
        rows = bindings.get('all', []) + personal
        controller_ips = policy.get('controller_ips', []) if scope == 'controller' or scope.startswith('bot-') else []
        # A dedicated relay login always gets its default exit. Without a rule
        # it would fall through to the core's first outbound (direct).
        if not rows and not controller_ips and not role:
            continue
        field = {'type': 'field', 'inboundTag': incoming_tags}
        if email:
            field['user'] = [email]
        rows = sorted(rows, key=lambda row: row['action'] != 'block')
        earlier_ips = [(controller_ips, 'block')] if controller_ips else []
        for order, row in enumerate([*rows, {'action': default}]):
            parts = lists[row['list']] if 'list' in row else {}
            action = row['action']
            domains = [d.removeprefix('keyword:') for d in parts.get('domain', [])]
            ips = parts.get('ip', [])
            if action == 'block':
                if domains:
                    selection.append(field | {'domain': domains, 'outboundTag': 'block'})
                if ips:
                    earlier_ips.append((ips, action))
                continue
            if domains or 'list' not in row:
                target = action
                if earlier_ips:
                    target = resolved_path(main, strict, direct, action, earlier_ips, f'policy-{index}-{order}')
                elif action == 'warp' and not strict:
                    target = 'block'
                selection.append(field | ({'domain': domains} if domains else {}) | {'outboundTag': target})
            if ips:
                earlier_ips.append((ips, action))
    rules[position:position] = selection


def resolved_path(main, strict, direct, mode, earlier, tag):
    """Pin one resolved IP, preserving the provisional exit's DNS context."""
    unavailable = mode == 'warp' and not strict
    core = strict if mode == 'warp' and strict else main
    strategy = 'ForceIPv4' if mode == 'warp' else direct['settings']['domainStrategy']
    core['outbounds'].append({'tag': tag, 'protocol': 'loopback', 'targetStrategy': 'AsIs' if unavailable else strategy, 'settings': {'inboundTag': tag}})
    field = {'type': 'field', 'inboundTag': [tag]}
    # An IP-selected WARP exit must pass the same private-address and family
    # checks as the ordinary WARP handoff even when already inside its core.
    permitted = '0.0.0.0/0' if strategy == 'ForceIPv4' else '2000::/3'
    denied = direct['settings']['finalRules'][0]['ip']
    post = [field | {'ip': denied, 'outboundTag': 'block'}]
    if strategy == 'ForceIPv4':
        post.append(field | {'ip': ['::/0'], 'outboundTag': 'block'})
    else:
        post.append(field | {'ip': ['0.0.0.0/0'], 'outboundTag': 'block'})
    for ips, action in earlier:
        target = 'block' if action == 'warp' and not strict else action
        post.append(field | {'ip': ips, 'outboundTag': target})
    post += [field | {'ip': [permitted], 'outboundTag': 'block' if unavailable else mode}, field | {'outboundTag': 'block'}]
    core['routing']['rules'].extend(post)
    if mode == 'direct' or unavailable:
        return tag
    relay = deepcopy(next(o for o in main['outbounds'] if o['tag'] == 'warp'))
    server = relay['settings']['servers'][0]
    password = hmac.digest(server['password'].encode(), tag.encode(), 'sha256').hex()
    server['password'] = password
    main['outbounds'].append(dict(relay, tag=tag))
    strict['inbounds'][0]['settings']['clients'].append({'password': password, 'email': tag})
    strict['routing']['rules'].insert(0, {'type': 'field', 'inboundTag': ['warp-handoff'], 'user': [tag], 'outboundTag': tag})
    return tag
