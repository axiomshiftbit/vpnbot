#!/usr/bin/env python3
"""Durable OpenVPN connect/disconnect counters under the bot's traffic lock."""
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time

TRAFFIC = Path('/etc/openvpn/traffic.json')
LOCK = Path('/logs/.lock.ovpn-traffic')


@contextmanager
def locked(path):
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        deadline = time.monotonic()+10
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline: raise TimeoutError('traffic lock busy')
                time.sleep(.05)
        yield
    finally:
        os.close(descriptor)


def load(path):
    if not path.exists(): return {'users': {}, 'saved': 0}
    data = json.loads(path.read_bytes())
    if isinstance(data, dict):
        for key in ('users', 'sessions'):
            if data.get(key) == []: data[key] = {}
        for row in data.get('users', {}).values() if isinstance(data.get('users'), dict) else ():
            if row.get('live') == []: row['live'] = {}
    if not isinstance(data, dict) or not isinstance(data.get('users'), dict):
        raise ValueError('invalid traffic counters')
    return data


def save(path, data):
    descriptor, temporary = tempfile.mkstemp(prefix='.traffic-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(data, stream, separators=(',', ':'), allow_nan=False)
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def number(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{1,19}', value):
        raise ValueError('invalid traffic metadata')
    result = int(value)
    if result > 2**63-1: raise ValueError('invalid traffic counter')
    return result


def identity(env):
    cn = env.get('common_name', '')
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,64}', cn): raise ValueError('invalid common name')
    address = str(ipaddress.ip_address(env.get('trusted_ip') or env.get('trusted_ip6', '')))
    port = number(env.get('trusted_port', ''))
    if not 1 <= port <= 65535: raise ValueError('invalid remote port')
    epoch = number(env.get('time_unix', ''))
    daemon = str(number(env.get('daemon_start_time', '')))+':'+str(number(env.get('daemon_pid', '')))
    fields = [daemon, cn, epoch, address, port]
    identifier = 'hook:'+hashlib.sha256(json.dumps(fields, separators=(',', ':')).encode()).hexdigest()
    return identifier, dict(cn=cn, epoch=epoch, address=address, port=port, daemon=daemon, closed=False)


def event(path, lock, env, now=None):
    now = int(time.time()) if now is None else now
    kind = env.get('script_type')
    if kind not in ('client-connect', 'client-disconnect'): raise ValueError('invalid traffic event')
    identifier, metadata = identity(env)
    with locked(lock):
        data = load(path)
        sessions = data.setdefault('sessions', {})
        if not isinstance(sessions, dict): raise ValueError('invalid traffic sessions')
        # Tombstones prevent the same seconds/endpoint tuple from being reused.
        # Late duplicate disconnects never create a missing session.
        sessions = {key: value for key, value in sessions.items()
                    if not value.get('closed') or now-int(value.get('closed_at', now)) <= 60}
        data['sessions'] = sessions
        if kind == 'client-connect':
            if identifier in sessions: raise ValueError('duplicate traffic session')
            # A dead daemon cannot deliver final counters. Preserve its last
            # durable sample and retire the stale live record, without reset.
            for key, old in sessions.items():
                if not old.get('closed') and old.get('daemon') != metadata['daemon']:
                    old_row = data['users'].get(old['cn'])
                    if old_row is not None:
                        live = old_row.setdefault('live', {}).pop(key, [0, 0, 0, 0])
                        for index, name in enumerate(('rx', 'tx')):
                            old_row[name] = int(old_row.get(name, 0))+max(0, int(live[index])-int(live[index+2]))
                    old.update(closed=True, closed_at=now)
            row = data['users'].setdefault(metadata['cn'], {'rx': 0, 'tx': 0, 'since': now, 'limit': 0, 'limited': False})
            used = int(row.get('rx', 0))+int(row.get('tx', 0))
            used += sum(max(0, int(v[i])-int(v[i+2])) for v in row.setdefault('live', {}).values() for i in (0, 1))
            if int(row.get('limit', 0)) > 0 and used >= int(row['limit']): raise ValueError('traffic limit reached')
            sessions[identifier] = metadata
            row.setdefault('live', {})[identifier] = [0, 0, 0, 0]
        else:
            session = sessions.get(identifier)
            if session is None or session.get('closed'): return
            row = data['users'].get(metadata['cn'])
            # Explicit deletion by the bot must not resurrect the user's row.
            if row is not None and identifier in row.setdefault('live', {}):
                live = row.setdefault('live', {}).pop(identifier, [0, 0, 0, 0])
                rx, tx = number(env.get('bytes_received', '')), number(env.get('bytes_sent', ''))
                row['rx'] = int(row.get('rx', 0))+max(0, max(rx, int(live[0]))-int(live[2]))
                row['tx'] = int(row.get('tx', 0))+max(0, max(tx, int(live[1]))-int(live[3]))
            session.update(closed=True, closed_at=now)
        data.update(hook_version=1, saved=now)
        save(path, data)


def prepare():
    with locked(LOCK):
        data = load(TRAFFIC)
        data.update(hook_version=1)
        data.setdefault('sessions', {})
        save(TRAFFIC, data)


def main():
    os.umask(0o077)
    if sys.argv[1:] == ['--prepare']:
        prepare()
        return
    # OpenVPN may append its temporary client-connect configuration path.
    # No file passed by the caller is opened or modified.
    if len(sys.argv) > 2: raise ValueError('unsupported hook arguments')
    event(TRAFFIC, LOCK, os.environ)
    # Human-readable connection log remains best effort; accounting above is mandatory.
    try:
        _, data = identity(os.environ)
        disconnected = os.environ['script_type'] == 'client-disconnect'
        detail = (' rx='+str(number(os.environ.get('bytes_received', '')))+' tx='+str(number(os.environ.get('bytes_sent', '')))
                  if disconnected else ' -> '+str(ipaddress.ip_address(os.environ['ifconfig_pool_remote_ip'])))
        with Path('/logs/openvpn-connections.log').open('a') as stream:
            stream.write(time.strftime('%Y-%m-%d %H:%M:%S')+' '+
                         ('DOWN' if disconnected else 'UP')+
                         ' '+data['cn']+' '+data['address']+':'+str(data['port'])+detail+'\n')
    except (OSError, ValueError, KeyError):
        pass


if __name__ == '__main__':
    try: main()
    except Exception:
        print('OpenVPN traffic accounting failed', file=sys.stderr)
        sys.exit(1)
