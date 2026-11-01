#!/usr/bin/env python3
"""Pinned, bounded SSH transport for managed nodes; no shell from user input."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time

LIMIT = 65536
ROOT = Path('/ssh/nodes')


class NodeBusy(ValueError):
    """The node rejected this request before executing any operation."""


def encode(value):
    body = json.dumps(value, separators=(',', ':'), allow_nan=False).encode()
    if len(body) > LIMIT:
        raise ValueError('size')
    return body


def decode(body):
    if len(body) > LIMIT:
        raise ValueError('size')
    def pairs(items):
        result = {}
        for name, value in items:
            if name in result:
                raise ValueError('duplicate')
            result[name] = value
        return result
    def invalid(_):
        raise ValueError('number')
    return json.loads(body, object_pairs_hook=pairs, parse_constant=invalid)


def key(value):
    if not isinstance(value, str) or not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]{68}', value):
        raise ValueError('host_key')
    raw = base64.b64decode(value.split()[1], validate=True)
    if len(raw) != 51 or raw[:19] != b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20':
        raise ValueError('host_key')
    return value


def fingerprint(value):
    raw = base64.b64decode(key(value).split()[1])
    return 'SHA256:'+base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')


def endpoint(value):
    if not isinstance(value, dict) or set(value) != {'address', 'port', 'host_key'}:
        raise ValueError('endpoint')
    if not isinstance(value['address'], str) or '%' in value['address']:
        raise ValueError('address')
    address = ipaddress.ip_address(value['address'])
    forbidden = ('64:ff9b::/96', '64:ff9b:1::/48', '2001::/23', '2002::/16', '3fff::/20')
    if not address.is_global or address.is_multicast or address.is_unspecified \
            or address.version == 6 and (address not in ipaddress.ip_network('2000::/3')
            or any(address in ipaddress.ip_network(net) for net in forbidden)):
        raise ValueError('public_address_required')
    if type(value['port']) is not int or not 1 <= value['port'] <= 65535:
        raise ValueError('port')
    return dict(address=str(address), port=value['port'], host_key=key(value['host_key']))


def trusted(path):
    for part in (path, *path.parents):
        if part.is_symlink() or part.exists() and (part.stat().st_uid not in (0, os.geteuid()) or part.stat().st_mode & 0o022):
            if part != Path('/tmp') or part.is_symlink() or not part.stat().st_mode & 0o1000:
                raise ValueError('unsafe_path')
    if path.exists() and path.is_file() and path.stat().st_nlink != 1:
        raise ValueError('unsafe_path')


def atomic(path, body):
    trusted(path)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix='.'+path.name+'-')
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def run(args, data=b'', timeout=15, *, rpc=False):
    # Anonymous regular files avoid pipe deadlocks and unbounded communicate()
    # buffering. RLIMIT_FSIZE bounds a hostile peer's response on disk as well.
    import resource
    with tempfile.TemporaryFile() as incoming, tempfile.TemporaryFile() as outgoing:
        incoming.write(data)
        incoming.seek(0)
        def limits():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT+1, LIMIT+1))
        process = subprocess.Popen(list(map(str, args)), stdin=incoming, stdout=outgoing, stderr=subprocess.DEVNULL,
                                   start_new_session=True, preexec_fn=limits,
                                   env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C.UTF-8'})
        try:
            status = process.wait(timeout=timeout)
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
        outgoing.seek(0)
        body = outgoing.read(LIMIT+1)
        if len(body) > LIMIT:
            raise ValueError('ssh_failed')
        if status:
            if rpc and status == 1:
                try:
                    reply = decode(body)
                except (ValueError, RecursionError, UnicodeError):
                    reply = None
                if isinstance(reply, dict) and set(reply) == {'ok', 'error'} \
                        and reply['ok'] is False and reply['error'] == 'busy':
                    raise NodeBusy('node_busy')
            raise ValueError('ssh_failed')
        return body


def arguments(private, known, address, port, user):
    return ['ssh', '-F', '/dev/null', '-T', '-i', str(private), '-p', str(port),
            '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'BatchMode=yes',
            '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no',
            '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'UserKnownHostsFile='+str(known),
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=5',
            '-o', 'ConnectionAttempts=1', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=1',
            '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes', '-o', 'LogLevel=ERROR',
            '-l', user, address]


class Client:
    def __init__(self, identifier, root=ROOT, hop_root=Path('/ssh')):
        if not isinstance(identifier, str) or not re.fullmatch(r'[a-f0-9]{8}', identifier):
            raise ValueError('id')
        # PHP allows 25 seconds for the complete helper action. Enrollment
        # and rebinding can issue several RPCs; they share one smaller budget.
        self.deadline = time.monotonic()+20
        self.root, self.hop_root = Path(root), Path(hop_root)
        trusted(self.root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory = self.root/identifier
        trusted(self.directory)
        self.directory.mkdir(mode=0o700, exist_ok=True)

    def public(self):
        private = self.directory/'key'
        trusted(private)
        public = self.directory/'key.pub'
        trusted(public)
        if not private.exists():
            run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'vpnbot-node-controller', '-f', private])
        if not public.exists():
            raise ValueError('missing_public_key')
        return key(' '.join(public.read_text().split()[:2]))

    def ssh(self, target):
        target = endpoint(target)
        known = self.directory/'known_hosts'
        name = target['address'] if target['port'] == 22 else f"[{target['address']}]:{target['port']}"
        atomic(known, (name+' '+target['host_key']+'\n').encode())
        args = arguments(self.directory/'key', known, target['address'], target['port'], 'vpnbot-ctl')
        if ':' in target['address']:
            # PHP stays on its private IPv4 network. Only the pinned Xray
            # container opens the external IPv6 socket. Node keys and RPC data
            # remain inside the end-to-end SSH session; no agent forwarding.
            pin = self.hop_root/'hosts/xr/ssh_host_ed25519_key.pub'
            trusted(pin)
            xr_key = key(' '.join(pin.read_text().split()[:2]))
            hop_known = self.directory/'xr_known_hosts'
            atomic(hop_known, ('xr '+xr_key+'\n').encode())
            trusted(self.hop_root/'key')
            proxy = arguments(self.hop_root/'key', hop_known, 'xr', 22, 'root')
            # BusyBox nc has no -6 switch. The validated IPv6 literal itself
            # selects AF_INET6; -n also forbids resolver-based fallback.
            proxy += ['nc -n '+shlex.quote(target['address'])+' '+str(target['port'])]
            args[-1:-1] = ['-o', 'ProxyCommand='+shlex.join(proxy)]
        return args

    def request(self, request, target=None):
        if target is None:
            path = self.directory/'endpoint.json'
            trusted(path)
            target = endpoint(decode(path.read_bytes()))
        if not isinstance(request, dict) or request.get('action') not in ('ping', 'status', 'backup', 'profile', 'confirm', 'submit', 'job'):
            raise ValueError('request')
        args, body = self.ssh(target), encode(request)
        deadline = self.deadline
        attempts = 4 if request['action'] in ('ping', 'status', 'backup', 'profile', 'job') else 1
        for attempt in range(attempts):
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise NodeBusy('node_busy_timeout')
            try:
                result = decode(run(args, body, timeout=min(15, remaining), rpc=True))
                break
            except NodeBusy:
                # Retry only reads with an explicit lock refusal. Mutations
                # and ambiguous SSH failures are never replayed automatically.
                if attempt == attempts-1:
                    raise
                time.sleep(min(.5*(attempt+1), max(0, deadline-time.monotonic())))
        if not isinstance(result, dict) or result.get('ok') is not True or 'result' not in result:
            raise ValueError('rpc_failed')
        return result['result']

    def connect(self, target):
        target = endpoint(target)
        self.public()
        if self.request({'action': 'ping'}, target) != {'schema': 1}:
            raise ValueError('protocol')
        atomic(self.directory/'endpoint.json', encode(target))
        return {'connected': True, 'fingerprint': fingerprint(target['host_key'])}

    def reconnect(self, value):
        if not isinstance(value, dict) or set(value) != {'address', 'port'}:
            raise ValueError('endpoint')
        path = self.directory/'endpoint.json'
        trusted(path)
        current = endpoint(decode(path.read_bytes()))
        target = endpoint(current | value)
        # Address/port changes retain the installed host pin. A different SSH
        # server cannot take over an existing node through this form.
        return self.rebind(target)

    def rebind(self, target):
        target = endpoint(target)
        path = self.directory/'endpoint.json'
        trusted(path)
        endpoint(decode(path.read_bytes()))
        # Explicit recovery supplies a verified replacement pin. Do not fetch
        # a profile or backup from a freshly installed node here.
        if self.request({'action': 'ping'}, target) != {'schema': 1}:
            raise ValueError('protocol')
        status = self.request({'action': 'status'}, target)
        if not isinstance(status, dict) or status.get('pending') or status.get('running') is not True:
            raise ValueError('node_not_ready')
        atomic(path, encode(target))
        return {'status': status}

    def saved(self):
        path = self.directory/'snapshot.json'
        trusted(path)
        with path.open('rb') as stream:
            body = stream.read(LIMIT+1)
        value = decode(body)
        if not isinstance(value, dict):
            raise ValueError('snapshot')
        return {'snapshot': value, 'hash': hashlib.sha256(body).hexdigest()[:16]}

    def forget(self):
        # Only this node's fixed transport files; never recurse or follow links.
        names = {'key', 'key.pub', 'endpoint.json', 'snapshot.json', 'known_hosts', 'xr_known_hosts'}
        files = list(self.directory.iterdir())
        for path in files:
            trusted(path)
            if path.name not in names or not path.is_file():
                raise ValueError('unsafe_path')
        for path in files:
            path.unlink()
        self.directory.rmdir()
        return {'forgotten': True}


def main():
    os.umask(0o077)
    value = decode(sys.stdin.buffer.read(LIMIT+1))
    if not isinstance(value, dict) or set(value) != {'id', 'action', 'value'}:
        raise ValueError('request')
    client = Client(value['id'])
    if value['action'] == 'public' and value['value'] is None:
        result = {'public_key': client.public()}
    elif value['action'] == 'connect':
        result = client.connect(value['value'])
    elif value['action'] == 'reconnect':
        result = client.reconnect(value['value'])
    elif value['action'] == 'rebind':
        result = client.rebind(value['value'])
    elif value['action'] == 'rpc':
        result = client.request(value['value'])
    elif value['action'] == 'saved' and value['value'] is None:
        result = client.saved()
    elif value['action'] == 'forget' and value['value'] is None:
        result = client.forget()
    elif value['action'] == 'snapshot' and value['value'] is None:
        snapshot = client.request({'action': 'backup'})
        atomic(client.directory/'snapshot.json', encode(snapshot))
        result = {'saved': True}
    else:
        raise ValueError('action')
    sys.stdout.buffer.write(encode({'ok': True, 'result': result}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('{"ok":false,"error":"node_connection_failed"}')
        sys.exit(1)
