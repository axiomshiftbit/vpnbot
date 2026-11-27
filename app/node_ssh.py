#!/usr/bin/env python3
"""Pinned, bounded SSH transport for managed nodes; no shell from user input."""
import base64
from contextlib import contextmanager
import ctypes
import errno
import fcntl
from functools import wraps
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time

LIMIT = 65536
POLICY_LIMIT = 4 * 1024 * 1024
POLICY_FRAME = POLICY_LIMIT + 4096
# An uploaded snapshot waits here: the last confirmed copy (snapshot.json) stays until a restore succeeds.
IMPORTED = 'snapshot.import.json'
# The backup format holds at most this many archived controller keys of forgotten nodes.
RETIRED_MAX = 256
ROOT = Path('/ssh/nodes')
# Controller keys of nodes removed from the bot. The node keeps trusting such a
# key, so adding the same server again reuses it instead of a rejected new one.
RETIRED = 'retired'


class NodeBusy(ValueError):
    """The node rejected this request before executing any operation."""


class ListsMissing(ValueError):
    """The node refused lists named by a digest it does not run; nothing was queued."""


def policy_request(request):
    if not isinstance(request, dict) or request.get('action') != 'submit':
        return False
    op = request.get('request', {})
    if not isinstance(op, dict):
        return False
    value = op.get('value')
    if not isinstance(value, dict):
        return False
    options = value if op.get('operation') == 'configure' else value.get('options') if op.get('operation') == 'restore' else None
    return isinstance(options, dict) and isinstance(options.get('policy'), dict)


def snapshot_limit(value):
    if isinstance(value, dict) and isinstance(value.get('options'), dict) and 'policy' in value['options']:
        options = dict(value['options'])
        del options['policy']
        encode(dict(value, options=options))
        return POLICY_LIMIT
    return LIMIT


def encode(value, limit=LIMIT):
    body = json.dumps(value, separators=(',', ':'), allow_nan=False).encode()
    if len(body) > limit:
        raise ValueError('size')
    return body


def decode(body, limit=LIMIT):
    if len(body) > limit:
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


def retired_directory(root, host_key):
    return Path(root)/RETIRED/hashlib.sha256(key(host_key).encode()).hexdigest()[:32]


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
        sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def transport_lock(path, deadline):
    trusted(path)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        trusted(path)
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise NodeBusy('node_busy_timeout')
                time.sleep(.05)
        yield
    finally:
        os.close(descriptor)


def key_locked(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        with self.locked():
            return method(self, *args, **kwargs)
    return call


def exchange_directories(first, second):
    """Linux atomic exchange; unsupported filesystems fail without a fallback."""
    rename = getattr(ctypes.CDLL(None, use_errno=True), 'renameat2', None)
    if rename is None:
        raise OSError(errno.ENOTSUP, 'atomic directory exchange unavailable')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    sync_directory(first.parent)
    if rename(-100, os.fsencode(first), -100, os.fsencode(second), 2) != 0:
        raise OSError(ctypes.get_errno(), 'atomic directory exchange failed')
    sync_directory(first.parent)


def validate_pair(directory):
    # ssh-keygen emits only the derived PUBLIC half; never log its input/output.
    derived = ' '.join(run(['ssh-keygen', '-y', '-P', '', '-f', directory/'key']).decode().split()[:2])
    public = ' '.join((directory/'key.pub').read_text().split()[:2])
    if key(derived) != key(public):
        raise ValueError('controller_key_mismatch')


def run(args, data=b'', timeout=15, *, rpc=False, limit=LIMIT):
    # Anonymous regular files avoid pipe deadlocks and unbounded communicate()
    # buffering. RLIMIT_FSIZE bounds a hostile peer's response on disk as well.
    import resource
    with tempfile.TemporaryFile() as incoming, tempfile.TemporaryFile() as outgoing:
        incoming.write(data)
        incoming.seek(0)
        def limits():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit+1, limit+1))
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
        body = outgoing.read(limit+1)
        if len(body) > limit:
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
                if isinstance(reply, dict) and set(reply) == {'ok', 'error'} \
                        and reply['ok'] is False and reply['error'] == 'lists_missing':
                    raise ListsMissing('lists_missing')
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
        self.lock_path = self.root/('.lock-'+identifier)
        self.lock_depth = 0
        trusted(self.root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory = self.root/identifier
        trusted(self.directory)
        self.directory.mkdir(mode=0o700, exist_ok=True)

    @contextmanager
    def locked(self):
        # The lock inode is outside the directory exchanged during adoption.
        if self.lock_depth:
            yield
            return
        with transport_lock(self.lock_path, self.deadline):
            self.lock_depth += 1
            try:
                yield
            finally:
                self.lock_depth -= 1

    @key_locked
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

    @key_locked
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

    @key_locked
    def request(self, request, target=None):
        if target is None:
            path = self.directory/'endpoint.json'
            trusted(path)
            target = endpoint(decode(path.read_bytes()))
        if not isinstance(request, dict) or request.get('action') not in ('ping', 'status', 'tls_probe', 'backup', 'profile', 'confirm', 'submit', 'job', 'warp_info', 'routes'):
            raise ValueError('request')
        args = self.ssh(target)
        if policy_request(request):
            body = encode(request,POLICY_FRAME)
            if len(body) > LIMIT:
                body = b'#' + body
        else:
            body = encode(request)
        deadline = self.deadline
        # submit too: "busy" means the node refused before queueing anything, and
        # its one-second status/watch passes would otherwise fail a user's Apply.
        attempts = 4 if request['action'] in ('ping', 'status', 'tls_probe', 'backup', 'profile', 'job', 'submit', 'warp_info', 'routes') else 1
        for attempt in range(attempts):
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise NodeBusy('node_busy_timeout')
            try:
                if request['action'] in ('status','backup'):
                    reply = run(args,body,timeout=min(15,remaining),rpc=True,limit=POLICY_FRAME)
                    result = decode(reply,POLICY_FRAME)
                    if len(reply) > LIMIT and snapshot_limit(result.get('result')) != POLICY_LIMIT:
                        raise ValueError('oversized metadata')
                elif request['action'] == 'routes':
                    # Only lists: the running generation's Block and WARP entries.
                    result = decode(run(args,body,timeout=min(15,remaining),rpc=True,limit=POLICY_FRAME),POLICY_FRAME)
                else:
                    result = decode(run(args, body, timeout=min(15, remaining), rpc=True))
                break
            except NodeBusy:
                # Retry only an explicit lock refusal: nothing ran. Ambiguous SSH
                # failures and confirmations are never replayed automatically.
                if attempt == attempts-1:
                    raise
                time.sleep(min(.5*(attempt+1), max(0, deadline-time.monotonic())))
        if not isinstance(result, dict) or result.get('ok') is not True or 'result' not in result:
            raise ValueError('rpc_failed')
        return result['result']

    @key_locked
    def connect(self, target):
        target = endpoint(target)
        self.public()
        try:
            if self.request({'action': 'ping'}, target) != {'schema': 1}:
                raise ValueError('protocol')
        except NodeBusy:
            raise
        except ValueError:
            if not self.adopt_retired(target):
                raise
            # The archived copy is the only key the node trusts until the card
            # is connected: drop it only after endpoint.json is written.
            atomic(self.directory/'endpoint.json', encode(target))
            self.discard_retired(target)
        else:
            atomic(self.directory/'endpoint.json', encode(target))
        return {'connected': True, 'fingerprint': fingerprint(target['host_key'])}

    @key_locked
    def adopt_retired(self, target):
        """First enrollment only: the server still trusts the key of an earlier removal."""
        with transport_lock(self.root/'.retired.lock', self.deadline):
            return self._adopt_retired_locked(target)

    def _adopt_retired_locked(self, target):
        directory = retired_directory(self.root, target['host_key'])
        private, public, current = directory/'key', directory/'key.pub', self.directory/'endpoint.json'
        for path in (directory, private, public, current):
            trusted(path)
        if current.exists() or not private.is_file() or not public.is_file():
            return False
        active = self.directory
        names = {'key', 'key.pub', 'known_hosts', 'xr_known_hosts', 'snapshot.json'}
        with tempfile.TemporaryDirectory(prefix='.adopt-', dir=self.root) as temporary:
            candidate = Path(temporary)
            for path in active.iterdir():
                trusted(path)
                if path.name not in names or not path.is_file():
                    raise ValueError('unsafe_path')
                if path.name not in ('key', 'key.pub'):
                    atomic(candidate/path.name, path.read_bytes())
            for path in (private, public):
                body = path.read_bytes()
                if not body or len(body) > 16384:
                    raise ValueError('incomplete_controller')
                atomic(candidate/path.name, body)
            validate_pair(candidate)
            # SSH opens the candidate private key; active files remain intact.
            self.directory = candidate
            try:
                if self.request({'action': 'ping'}, target) != {'schema': 1}:
                    raise ValueError('protocol')
            finally:
                self.directory = active
            sync_directory(candidate)
            exchange_directories(active, candidate)
            # TemporaryDirectory now contains only the previous complete set.
        return True

    @key_locked
    def discard_retired(self, target):
        """The adopted pair is now recorded as this card's key: remove its archive."""
        with transport_lock(self.root/'.retired.lock', self.deadline):
            directory = retired_directory(self.root, target['host_key'])
            private, public = directory/'key', directory/'key.pub'
            for path in (directory, private, public):
                trusted(path)
            if not (private.is_file() and public.is_file()):
                return
            # Never remove an archive that is not the active key (e.g. replaced).
            if private.read_bytes() != (self.directory/'key').read_bytes():
                return
            private.unlink()
            public.unlink()
            try:
                directory.rmdir()
            except OSError:
                pass  # A foreign leftover must not fail an enrollment that already succeeded.

    @key_locked
    def retire(self):
        """Keep the controller key of a node being forgotten for a later re-enrollment."""
        with transport_lock(self.root/'.retired.lock', self.deadline):
            return self._retire_locked()

    def _retire_locked(self):
        private, public, current = self.directory/'key', self.directory/'key.pub', self.directory/'endpoint.json'
        for path in (private, public, current):
            trusted(path)
        if not current.exists():
            return
        if not (private.is_file() and public.is_file() and current.is_file()):
            raise ValueError('incomplete_controller')
        directory = retired_directory(self.root, endpoint(decode(current.read_bytes()))['host_key'])
        trusted(directory.parent)
        directory.parent.mkdir(mode=0o700, exist_ok=True)
        trusted(directory)
        sync_directory(self.root)
        # The archive lock also owns staging. A retry cleans up a previously
        # interrupted write or eviction before creating another private copy.
        with self._retire_staging(directory.parent) as staging:
            pair = staging/'pair'
            pair.mkdir(mode=0o700)
            for path in (private, public):
                with path.open('rb') as stream:
                    body = stream.read(16385)
                if not body or len(body) > 16384:
                    raise ValueError('incomplete_controller')
                atomic(pair/path.name, body)
            ages = self._retired_ages(directory.parent, staging)
            # The PHP backup format sees whole seconds. A freshly stored or
            # replaced pair must sort after every prior successful retirement.
            if ages:
                stamp = pair.stat()
                latest = ages[-1][0]
                if stamp.st_mtime_ns // 1_000_000_000 <= latest:
                    next_ns = (latest + 1) * 1_000_000_000
                    os.utime(pair, ns=(stamp.st_atime_ns, next_ns))
                    if pair.stat().st_mtime_ns != next_ns:
                        raise OSError('retired age out of range')
                    sync_directory(pair)
            if directory.exists():
                self._check_retired_files(directory)
                exchange_directories(directory, pair)
            else:
                pair.rename(directory)
            sync_directory(directory.parent)
            sync_directory(staging)
            self._trim_retired(directory, staging, ages)

    @staticmethod
    @contextmanager
    def _retire_staging(root):
        staging = root/'.staging'
        trusted(staging)
        if staging.exists():
            for entry in staging.iterdir():
                trusted(entry)
                if entry.name != 'pair' and not re.fullmatch('[a-f0-9]{32}', entry.name):
                    raise ValueError('unsafe_path')
            # A previous exchange may have moved the old pair here before
            # the directory entries reached disk. Finish the sync before removal.
            sync_directory(root)
            sync_directory(staging)
            shutil.rmtree(staging)
        staging.mkdir(mode=0o700)
        try:
            yield staging
        finally:
            # Keep the previous pair in staging if syncing the exchange fails.
            sync_directory(root)
            sync_directory(staging)
            shutil.rmtree(staging)
            sync_directory(root)

    @staticmethod
    def _check_retired_files(directory):
        if not directory.is_dir():
            raise ValueError('unsafe_path')
        for path in directory.iterdir():
            trusted(path)
            if path.name not in ('key', 'key.pub') or not path.is_file():
                raise ValueError('unsafe_path')

    @staticmethod
    def _retired_ages(root, staging):
        entries = []
        for entry in root.iterdir():
            if entry == staging:
                continue
            if entry.is_symlink() or not entry.is_dir() or not re.fullmatch('[a-f0-9]{32}', entry.name):
                raise ValueError('unsafe_path')
            # PHP ranks existing pairs by whole seconds and breaks ties by ID.
            entries.append((entry.stat().st_mtime_ns // 1_000_000_000, entry))
        return sorted(entries)

    @staticmethod
    def _trim_retired(current, staging, ages):
        """Evict the oldest pairs only after the current pair is durable."""
        previous = [entry for _, entry in ages if entry != current]
        for entry in previous[:max(0, len(previous)-RETIRED_MAX+1)]:
            Client._check_retired_files(entry)
            entry.rename(staging/entry.name)
            sync_directory(current.parent)

    @key_locked
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

    @key_locked
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

    @key_locked
    def snapshot(self, generation):
        if generation is not None and (not isinstance(generation, str) or not re.fullmatch(r'[a-f0-9]{32}', generation)):
            raise ValueError('invalid_generation')

        def check_generation():
            status = self.request({'action': 'status'})
            if status.get('generation') != generation or status.get('pending'):
                raise ValueError('unconfirmed_snapshot_generation')

        if generation is not None:
            check_generation()
        snapshot = self.request({'action': 'backup'})
        if generation is not None:
            check_generation()
        body = encode(snapshot, snapshot_limit(snapshot))
        atomic(self.directory/'snapshot.json', body)
        return {'saved': True, 'sha256': hashlib.sha256(body).hexdigest()}

    @key_locked
    def saved(self, candidate=False):
        """The confirmed copy; for a restore (candidate) an uploaded copy waiting to be restored comes first."""
        path = self.directory/'snapshot.json'
        if candidate:
            imported = self.directory/IMPORTED
            trusted(imported)
            if imported.exists():
                path = imported
        trusted(path)
        with path.open('rb') as stream:
            body = stream.read(POLICY_LIMIT+1)
        value = decode(body, POLICY_LIMIT)
        if len(body) > snapshot_limit(value):
            raise ValueError('oversized snapshot')
        if not isinstance(value, dict):
            raise ValueError('snapshot')
        result = {'snapshot': value, 'hash': hashlib.sha256(body).hexdigest()[:16]}
        if path.name == IMPORTED:
            result['imported'] = True
        return result

    @key_locked
    def store(self, snapshot):
        """Keep a snapshot uploaded by the administrator as the restore candidate.

        Only the fixed snapshot fields are accepted here; the node validates
        the full contents when the snapshot is restored. Until then the last
        confirmed copy stays in snapshot.json for backups and another restore."""
        if not isinstance(snapshot, dict) or set(snapshot) != {'schema', 'options', 'identity', 'peers', 'images', 'tls'} \
                or type(snapshot['schema']) is not int or snapshot['schema'] != 1:
            raise ValueError('snapshot')
        atomic(self.directory/IMPORTED, encode(snapshot,snapshot_limit(snapshot)))
        return self.saved(True)

    @key_locked
    def clear_import(self, expected=None):
        path = self.directory/IMPORTED
        trusted(path)
        if expected is not None:
            if not isinstance(expected, str) or not re.fullmatch('[a-f0-9]{16}', expected):
                raise ValueError('invalid import hash')
            if not path.exists() or self.saved(True)['hash'] != expected:
                return False
        path.unlink(missing_ok=True)
        return True

    @key_locked
    def forget(self):
        # Only this node's fixed transport files; never recurse or follow links.
        names = {'key', 'key.pub', 'endpoint.json', 'snapshot.json', IMPORTED, 'known_hosts', 'xr_known_hosts'}
        files = list(self.directory.iterdir())
        for path in files:
            trusted(path)
            if path.name not in names or not path.is_file():
                raise ValueError('unsafe_path')
        # Never destroy the only usable key when archiving fails (including a
        # partial pair write). The original pair remains available for retry.
        self.retire()
        for path in files:
            path.unlink()
        self.directory.rmdir()
        return {'forgotten': True}


def main():
    os.umask(0o077)
    first = sys.stdin.buffer.read(1)
    policy_frame = first == b'#'
    limit = POLICY_FRAME if policy_frame else LIMIT
    value = decode((b'' if policy_frame else first)+sys.stdin.buffer.read(limit+1),limit)
    if policy_frame:
        if not isinstance(value,dict) or not isinstance(value.get('value'),dict):
            raise ValueError('invalid policy frame')
        payload = value['value']
        if not ((value.get('action') == 'rpc' and policy_request(payload)) or
                (value.get('action') == 'import' and snapshot_limit(payload.get('snapshot')) == POLICY_LIMIT)):
            raise ValueError('invalid policy frame')
    if not isinstance(value, dict) or set(value) != {'id', 'action', 'value'}:
        raise ValueError('request')
    client = Client(value['id'])
    with client.locked():
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
        elif value['action'] == 'restore-source' and value['value'] is None:
            result = client.saved(True)
        elif value['action'] == 'import-clear':
            result = {'cleared': client.clear_import(value['value'])}
        elif value['action'] == 'saved-routes' and value['value'] is None:
            policy = client.saved()['snapshot']['options'].get('policy', {})
            result = {'routes': policy.get('routes', {})}
        elif value['action'] == 'retire' and value['value'] is None:
            client.retire()
            result = {'retired': True}
        elif value['action'] == 'forget' and value['value'] is None:
            result = client.forget()
        elif value['action'] == 'import' and isinstance(value['value'], dict) and set(value['value']) == {'snapshot'}:
            saved = client.store(value['value']['snapshot'])
            result = {'hash': saved['hash']}
        elif value['action'] == 'snapshot':
            result = client.snapshot(value['value'])
        else:
            raise ValueError('action')
        sys.stdout.buffer.write(encode({'ok': True, 'result': result}, POLICY_FRAME if value['action'] in ('rpc','saved','restore-source','saved-routes','rebind','reconnect') else LIMIT))


if __name__ == '__main__':
    try:
        main()
    except ListsMissing:
        print('{"ok":false,"error":"lists_missing"}')
        sys.exit(1)
    except Exception:
        print('{"ok":false,"error":"node_connection_failed"}')
        sys.exit(1)
