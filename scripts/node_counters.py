"""Durable per-peer Xray byte totals. Called under the node manager's process lock."""
import hashlib
import re


SOCKET = '/tmp/vpnbot-peer-stats.sock'
FILE = 'peer-counters.json'


def key(peer):
    return hashlib.sha256(('peer-counter:' + peer['id']).encode()).hexdigest()[:32]


def enable(config):
    # /tmp is a private tmpfs in the core container, including with host networking.
    config['stats'] = {}
    config['api'] = {'tag': 'peer-stats', 'services': ['StatsService']}
    config.setdefault('policy', {}).setdefault('levels', {}).setdefault('0', {}).update(
        statsUserUplink=True, statsUserDownlink=True)
    config['inbounds'].append({'tag': 'peer-stats-in', 'listen': SOCKET, 'protocol': 'dokodemo-door',
                               'settings': {'address': '127.0.0.1'}})
    config.setdefault('routing', {}).setdefault('rules', []).insert(
        0, {'type': 'field', 'inboundTag': ['peer-stats-in'], 'outboundTag': 'peer-stats'})


def retired_sequence(store, uid, sequence=None, *, known=False):
    # Keep a small receipt per retired identity. Arbitrary missing IDs never
    # create files. The bounded live ledger still fits the RPC metadata limit.
    from node_state import atomic, encode, sync_directory, trusted
    if not isinstance(uid, str) or not re.fullmatch('[0-9a-f]{32}', uid):
        raise ValueError('invalid stored peer identifier')
    name = 'peer-counter-receipts/' + uid + '.json'
    old = store.read(name)
    if old is not None and (type(old) is not int or not 0 <= old < 2**53):
        raise ValueError('invalid counter receipt')
    if sequence is not None and (known and old is None or old is not None and sequence > old):
        directory = store.root / 'peer-counter-receipts'
        trusted(directory)
        if not directory.exists():
            directory.mkdir(mode=0o700)
            sync_directory(store.root)
        atomic(store.root / name, encode(sequence))
    return old or 0


def persist(store, ledger, previous):
    if ledger != previous:
        from node_state import atomic, encode
        atomic(store.root / FILE, encode(ledger))


def sample(store, peers, read, target=None, sequence=0):
    if target is not None and (not isinstance(target, str) or not re.fullmatch('[0-9a-f]{32}', target)
                               or type(sequence) is not int or not 0 < sequence <= 2**53 - 1):
        raise ValueError('invalid counter reset')
    if store.pending():
        raise ValueError('peer counters await a confirmed generation')
    peers = {key(p): p for p in peers}
    active = {uid: p for uid, p in peers.items() if p.get('channel', 'vless') != 'wireguard'}
    previous = store.read(FILE) or {}
    for uid in previous.keys() - peers.keys():
        row = previous[uid]
        retired_sequence(store, uid, max(row.get('sequence', 0), row.get('floor', 0)), known=True)
    ledger = {uid: row for uid, row in previous.items() if uid in peers}
    if target is not None and target not in active:
        if target in ledger:
            ledger[target] = dict(ledger[target], floor=max(ledger[target].get('floor', 0), sequence))
        else:
            retired_sequence(store, target, sequence)
        persist(store, ledger, previous)
        return {'peer': target, 'sequence': sequence, 'result': 'removed'}
    if active:
        epoch, raw = read()
        if not epoch or not isinstance(raw, dict):
            raise ValueError('peer statistics unavailable')
        by_name = {}
        items = raw.get('stat', [])
        if not isinstance(items, list): raise ValueError('invalid peer statistics')
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get('name'), str): raise ValueError('invalid statistic')
            parts = item['name'].split('>>>')
            if len(parts) != 4 or parts[0] != 'user' or parts[2] != 'traffic' or parts[3] not in ('uplink', 'downlink'):
                continue
            raw_value = item.get('value', 0)
            if type(raw_value) not in (int, str) or not re.fullmatch('[0-9]{1,19}', str(raw_value)):
                raise ValueError('invalid peer counter')
            value = int(raw_value)
            if value < 0 or value > 2**63-1: raise ValueError('invalid peer counter')
            directions = by_name.setdefault(parts[1], {})
            if parts[3] in directions: raise ValueError('duplicate counter')
            directions[parts[3]] = value
        for uid, peer in active.items():
            row = dict(ledger[uid]) if uid in ledger else {'floor': retired_sequence(store, uid)}
            before = row.get('raw', {}) if row.get('epoch') == epoch else {}
            current = by_name.get(peer['name'], {})
            totals = {}
            for direction in ('uplink', 'downlink'):
                count = current.get(direction, 0)
                if count < before.get(direction, 0): raise ValueError('counter went backwards in same core')
                total = row.get(direction, 0) + count - before.get(direction, 0)
                if total > 2**63-1: raise ValueError('counter overflow')
                totals[direction] = total
            if uid == target and sequence > max(row.get('sequence', 0), row.get('floor', 0)):
                totals = dict.fromkeys(totals, 0)
                row['sequence'] = sequence
            ledger[uid] = dict(row, epoch=epoch, raw=current, **totals)
    persist(store, ledger, previous)
    if target is not None:
        row = ledger[target]
        applied = row.get('sequence') == sequence and row.get('floor', 0) < sequence
        return {'peer': target, 'sequence': sequence, 'result': 'applied' if applied else 'superseded'}
    return {uid: {'uplink': ledger[uid]['uplink'], 'downlink': ledger[uid]['downlink'],
                  'sequence': max(ledger[uid].get('sequence', 0), ledger[uid].get('floor', 0))} for uid in active}
