"""Shared destination routing of a managed node: Block and WARP lists for all its traffic."""
from copy import deepcopy
import hashlib
import hmac
import ipaddress
import re
import uuid

ROUTE_KINDS = ('block', 'warp')
# Bound the work before routes expand across every authenticated subject.
ROUTE_BYTES = 3 * 1024 * 1024


def peer_scope(identity):
    return 'peer-' + hashlib.sha256(identity.encode()).hexdigest()[:20]


def relay_login(identity, scope, mode, revision=None):
    message = f'vpnbot/policy/{scope}/{mode}'.encode()
    if revision:
        message += b'/' + revision.encode()
    return str(uuid.UUID(bytes=hmac.digest(identity.encode(), message, 'sha256')[:16], version=4))


def migrate(value):
    """Named lists and personal bindings (before shared routes): keep only the shared blocks."""
    lists = value.get('lists') if isinstance(value.get('lists'), dict) else {}
    block = {'domain': [], 'ip': []}
    for row in (value.get('bindings') or {}).get('all', []) if isinstance(value.get('bindings'), dict) else []:
        parts = lists.get(row.get('list')) if isinstance(row, dict) and row.get('action') == 'block' else None
        for kind in ('domain', 'ip'):
            for item in (parts or {}).get(kind, []) if isinstance(parts, dict) else []:
                if item not in block[kind]:
                    block[kind].append(item)
    result = {key: value[key] for key in ('revision', 'controller_ips') if key in value}
    result['routes'] = {'block': {kind: entries for kind, entries in block.items() if entries}} if any(block.values()) else {}
    return result


def validate(value):
    if isinstance(value, dict) and 'bindings' in value:
        value = migrate(value)
    if not isinstance(value, dict) or set(value) - {'revision', 'controller_ips'} != {'routes'}:
        raise ValueError('invalid routing policy')
    if 'revision' in value and not re.fullmatch(r'[a-f0-9]{32}', value['revision']):
        raise ValueError('invalid policy revision')
    routes = value['routes']
    if not isinstance(routes, dict) or set(routes) - set(ROUTE_KINDS):
        raise ValueError('invalid routing lists')
    size = 0
    for name, parts in routes.items():
        if not isinstance(parts, dict) or set(parts) - {'domain', 'ip'} or not any(parts.values()):
            raise ValueError('invalid routing list')
        for kind, entries in parts.items():
            if not isinstance(entries, list) or len(entries) > 200000:
                raise ValueError('invalid list entries')
            for item in entries:
                if not isinstance(item, str) or not 1 <= len(item) <= 1024 or any(ord(ch) < 32 for ch in item):
                    raise ValueError('invalid list entry')
                if kind == 'ip':
                    ipaddress.ip_network(item, strict=False)
                elif not re.fullmatch(r'(full|domain|keyword|regexp):.+', item):
                    raise ValueError('invalid domain matcher')
                size += len(item.encode()) + 8
    controller_ips = value.get('controller_ips', [])
    if not isinstance(controller_ips, list) or len(controller_ips) > 200000:
        raise ValueError('invalid controller IP list')
    if controller_ips and 'revision' not in value:
        raise ValueError('controller IP list needs a revision')
    for item in controller_ips:
        if not isinstance(item, str) or len(item) > 64:
            raise ValueError('invalid controller CIDR')
        ipaddress.ip_network(item, strict=False)
    if size > ROUTE_BYTES:
        raise ValueError('compiled destination policy too large')
    return value


def accounts(value):
    """Revision-bound logins of the controller when it delegates its own IP blocks."""
    policy = value['options']['policy']
    if not policy.get('controller_ips'):
        return
    for role in ('direct', 'warp'):
        yield 'controller', role, role, relay_login(value['identity']['uuid'], 'controller', role, policy.get('revision'))


def shared(policy, strict):
    """Internal named lists: blocks first, then WARP (only with the node's WARP core)."""
    routes = policy.get('routes', {})
    lists, rows = {}, []
    for kind in ROUTE_KINDS:
        parts = routes.get(kind, {})
        if any(parts.values()) and (kind == 'block' or strict):
            lists[kind] = parts
            rows.append({'list': kind, 'action': kind})
    return lists, ({'all': rows} if rows else {})


def compile_policy(main, strict, value):
    policy = value['options'].get('policy')
    if not policy:
        return
    lists, bindings = shared(policy, strict)
    if not bindings and not policy.get('controller_ips'):
        return
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
    if policy.get('controller_ips'):
        subjects.append(('controller', 'direct', ['node'], 'controller', None))
        if strict:
            subjects.append(('controller', 'warp', ['node'], 'vpnbot/warp', None))
        if wg:
            subjects.append(('controller', 'direct', wg, 'controller-wg', None))
    if bindings:
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
        rows = bindings.get('all', [])
        controller_ips = policy.get('controller_ips', []) if scope == 'controller' else []
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
