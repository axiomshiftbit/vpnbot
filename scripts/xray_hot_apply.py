#!/usr/bin/env python3
"""Conservative Xray API updates; private state never contains credentials.

No existing handler is removed: even a packet already routed before an API
update must still find its handler, rather than fall back to the default exit.
Unsupported changes return RESTART, leaving the caller to restart the core.
"""
import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

STATE = Path('/run/vpnbot-xray-hot')
CONFIG = Path('/xray.json')
MAX_INPUT = 32 * 1024 * 1024


def canonical(config):
    config = copy.deepcopy(config)
    # PHP decodes empty JSON objects as arrays; stats is always an object.
    if config.get('stats') == []:
        config['stats'] = {}
    levels = config.get('policy', {}).get('levels')
    if isinstance(levels, list):
        config['policy']['levels'] = {str(k): v for k, v in enumerate(levels)}
    return json.dumps(config, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def digest(config):
    return hashlib.sha256(canonical(config).encode()).hexdigest()


def indexed(items, field='tag'):
    result = {}
    for item in items:
        name = item.get(field)
        if not isinstance(name, str) or not name or name in result:
            raise ValueError('ambiguous identifier')
        result[name] = item
    return result


def plan(previous, target):
    """Allow new users/outbounds and routing; never revoke or replace handlers."""
    old, new = copy.deepcopy(previous), copy.deepcopy(target)
    old_in, new_in = indexed(old.pop('inbounds')), indexed(new.pop('inbounds'))
    old_out, new_out = old.pop('outbounds'), new.pop('outbounds')
    if not old_out or not new_out or old_out[0] != new_out[0]:
        raise ValueError('default outbound changed')
    old_out, new_out = indexed(old_out), indexed(new_out)
    if any(new_out.get(tag) != handler for tag, handler in old_out.items()):
        raise ValueError('existing outbound changed')
    routing = new.pop('routing')
    old_routing = old.pop('routing')
    # ReloadRules does not update domainStrategy or the routing script.
    omit = lambda rules: {k: v for k, v in rules.items() if k not in ('rules', 'balancers')}
    if omit(old_routing) != omit(routing) or routing.get('script'):
        raise ValueError('routing engine changed')
    if canonical(old) != canonical(new) or old_in.keys() != new_in.keys():
        raise ValueError('unsupported core change')
    api = new.get('api', {})
    if api.get('tag') != 'api' or not {'HandlerService', 'RoutingService'} <= set(api.get('services', [])):
        raise ValueError('API not configured')
    inbound = new_in.get('api', {})
    if inbound.get('listen') != '127.0.0.1' or inbound.get('port') != 8080:
        raise ValueError('unexpected API listener')
    api_rule = {'type': 'field', 'inboundTag': ['api'], 'outboundTag': 'api'}
    if api_rule not in routing.get('rules', []):
        raise ValueError('API routing missing')
    users = []
    for tag, before in old_in.items():
        after = new_in[tag]
        if before == after:
            continue
        if before.get('protocol') not in ('vless', 'vmess', 'trojan'):
            raise ValueError('unsupported inbound change')
        prior = indexed(before.get('settings', {}).pop('clients', []), 'email')
        clients = indexed(after.get('settings', {}).pop('clients', []), 'email')
        if before != after or any(clients.get(email) != user for email, user in prior.items()):
            raise ValueError('existing user changed')
        added = [user for email, user in clients.items() if email not in prior]
        if added:
            user_config = copy.deepcopy(after)
            user_config['settings']['clients'] = added
            users.append(user_config)
    return {'outbounds': [o for tag, o in new_out.items() if tag not in old_out],
            'inbounds': users, 'routing': routing if routing != old_routing else None}


def private_dir(path):
    path.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('unsafe state directory')


def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('unsafe state file')
        return json.load(handle)


def save_state(state, config):
    fd, name = tempfile.mkstemp(dir=STATE)
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump({**state, 'digest': digest(config)}, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, STATE / 'state.json')
    finally:
        Path(name).unlink(missing_ok=True)


def process_identity(pid):
    # starttime protects against PID reuse. Check executable as well as name.
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    executable = Path(f'/proc/{pid}/exe').resolve(strict=True)
    binary = Path(shutil.which('xray') or '').resolve(strict=True)
    if fields[0] == 'Z' or executable != binary:
        raise ValueError('core process changed')
    return {'pid': pid, 'start': fields[19], 'binary': str(binary)}


def owns_api(pid):
    sockets = set()
    for path in Path(f'/proc/{pid}/fd').iterdir():
        try:
            sockets.add(os.readlink(path))
        except FileNotFoundError:
            pass
    for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
        fields = line.split()
        if fields[1] == '0100007F:1F90' and fields[3] == '0A' and f'socket:[{fields[9]}]' in sockets:
            return True
    return False


def api(command, argument=None):
    args = ['xray', 'api', command, '--server=127.0.0.1:8080', '--timeout=4']
    if argument is not None:
        args.append(str(argument))
    # Xray CLI may print credentials/config in errors; never forward output.
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)
    if result.returncode:
        raise ValueError('API operation failed')
    if command == 'adu':
        # adu exits 0 even when every AddUser failed. Require its final count.
        expected = sum(len(i['settings']['clients']) for i in json.loads(Path(argument).read_text())['inbounds'])
        match = re.search(rb'\nAdded (\d+) user\(s\) in total\.\s*\Z', result.stdout)
        if not match or int(match[1]) != expected:
            raise ValueError('API user operation incomplete')


def atomic_router():
    result = subprocess.run(['xray', 'version'], capture_output=True, timeout=5, check=True)
    match = re.match(rb'Xray (\S+) ', result.stdout)
    # Explicitly exercised cores. Unknown/future forks use a full restart until
    # their ReloadRules implementation has also been checked for atomicity.
    return bool(match and match[1] in (b'26.9.30', b'26.10.29', b'26.10.28-1202'))


def mark(pid):
    identity = None
    config = json.loads(CONFIG.read_text())
    for attempt in range(10):
        try:
            # The shell's background PID can still be entering exec. Wait for
            # Xray, but never accept a different process once identified.
            current = process_identity(pid)
            if identity is None:
                identity = current
            if current != identity:
                raise ValueError('core process changed')
            api('statssys')
            if process_identity(pid) != identity or not owns_api(pid):
                raise ValueError('core process changed')
            save_state(identity, config)
            return
        except (OSError, ValueError, subprocess.SubprocessError):
            if attempt == 9:
                raise
            time.sleep(0.2)


def apply(previous, target):
    operations = plan(previous, target)
    if not atomic_router():
        raise ValueError('core lacks atomic routing')
    state = read_private(STATE / 'state.json')
    identity = process_identity(state['pid'])
    if any(state.get(k) != v for k, v in identity.items()) or state['digest'] != digest(previous) or not owns_api(state['pid']):
        raise ValueError('runtime does not match previous configuration')
    if digest(json.loads(CONFIG.read_text())) != digest(target):
        raise ValueError('configuration changed concurrently')
    # A failed or killed update must not leave a reusable trusted marker.
    (STATE / 'state.json').unlink()
    with tempfile.TemporaryDirectory(dir=STATE) as directory:
        payload = Path(directory) / 'payload.json'
        def invoke(command, content):
            payload.write_text(json.dumps(content))
            payload.chmod(0o600)
            api(command, payload)
        if operations['outbounds']:
            invoke('ado', {'outbounds': operations['outbounds']})
        # Install access policy BEFORE enabling new accounts. Existing handlers
        # remain registered, including ones selected by an in-flight dispatcher.
        if operations['routing'] is not None:
            invoke('adrules', {'routing': operations['routing']})
        if operations['inbounds']:
            invoke('adu', {'inbounds': operations['inbounds']})
    if process_identity(state['pid']) != identity or digest(json.loads(CONFIG.read_text())) != digest(target):
        raise ValueError('runtime changed during update')
    save_state(identity, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('mark').add_argument('--pid', required=True, type=int)
    sub.add_parser('apply').add_argument('--size', required=True, type=int)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ValueError('root required')
        os.umask(0o077)
        private_dir(STATE)
        fd = os.open(STATE / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.action == 'mark':
                (STATE / 'state.json').unlink(missing_ok=True)
                mark(args.pid)
            else:
                if not 1 <= args.size <= MAX_INPUT:
                    raise ValueError('invalid input size')
                payload = sys.stdin.buffer.read(args.size)
                if len(payload) != args.size:
                    raise ValueError('truncated input')
                data = json.loads(payload)
                apply(data['previous'], data['target'])
        print('APPLIED' if args.action == 'apply' else 'MARKED')
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('RESTART')
        return 1


if __name__ == '__main__':
    sys.exit(main())
