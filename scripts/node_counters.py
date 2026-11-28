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


def sample(store, peers, read, target=None, sequence=0):
    if target is not None and (not isinstance(target, str) or not re.fullmatch('[0-9a-f]{32}', target)
                               or type(sequence) is not int or not 0 < sequence <= 2**53 - 1):
        raise ValueError('invalid counter reset')
    if store.pending():
        raise ValueError('peer counters await a confirmed generation')
    active = {key(p): p for p in peers if p.get('channel', 'vless') != 'wireguard'}
    if target is not None and target not in active:
        return {'peer': target, 'sequence': sequence, 'result': 'removed'}
    previous = store.read(FILE) or {}
    ledger = {uid: row for uid, row in previous.items() if uid in active}
    if active:
        epoch, raw = read()
        if not epoch or not isinstance(raw, dict):
            raise ValueError('peer statistics unavailable')
        by_name = {}
        for item in raw.get('stat') or []:
            parts = item['name'].split('>>>')
            if len(parts) != 4 or parts[0] != 'user' or parts[2] != 'traffic' or parts[3] not in ('uplink', 'downlink'):
                continue
            value = int(item.get('value', 0))
            if value < 0 or value > 2**63-1: raise ValueError('invalid peer counter')
            by_name.setdefault(parts[1], {})[parts[3]] = value
        for uid, peer in active.items():
            row = dict(ledger.get(uid, {}))
            before = row.get('raw', {}) if row.get('epoch') == epoch else {}
            current = by_name.get(peer['name'], {})
            totals = {}
            for direction in ('uplink', 'downlink'):
                count = current.get(direction, 0)
                if count < before.get(direction, 0): raise ValueError('counter went backwards in same core')
                totals[direction] = row.get(direction, 0) + count - before.get(direction, 0)
            if uid == target and sequence > row.get('sequence', 0):
                totals = dict.fromkeys(totals, 0)
                row['sequence'] = sequence
            ledger[uid] = dict(row, epoch=epoch, raw=current, **totals)
    if ledger != previous:
        from node_state import atomic, encode
        atomic(store.root / FILE, encode(ledger))
    if target is not None:
        return {'peer': target, 'sequence': sequence, 'result': 'applied' if ledger[target]['sequence'] == sequence else 'superseded'}
    return {uid: {k: row.get(k, 0) for k in ('uplink', 'downlink', 'sequence')} for uid, row in ledger.items()}
