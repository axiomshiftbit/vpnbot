#!/usr/bin/env python3
"""Bounded snapshots and durable apply/confirm/rollback for managed nodes."""
import base64
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import tempfile
import time

from node_config import settings, identity, peers, needs_certificate

MAX_BYTES = 65536
# Named destination lists travel only in configure/restore requests and snapshots.
POLICY_BYTES = 4 * 1024 * 1024
CORE_CONFIG_BYTES = 16 * 1024 * 1024
# Local root-owned deployment/enrollment files may contain complete ASN lists.
# This limit never applies to SSH requests, snapshots or responses.
MAX_DEPLOYMENT_BYTES = 8 * 1024 * 1024
GENERATION = re.compile(r'[a-f0-9]{32}\Z')


def decode(data, limit=MAX_BYTES):
    if not isinstance(data, (str, bytes)) or len(data) > limit:
        raise ValueError('invalid request size')

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON field')
            result[key] = value
        return result

    def invalid(value):
        raise ValueError('invalid JSON number')

    try:
        return json.loads(data, object_pairs_hook=unique, parse_constant=invalid)
    except (RecursionError, UnicodeError) as error:
        raise ValueError('invalid JSON') from error


def encode(value, limit=MAX_BYTES):
    result = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if len(result) > limit:
        raise ValueError('snapshot exceeds size limit')
    return result


def policy_size(value):
    """Keep the original metadata limit when transferring a larger policy."""
    container = value
    path = []
    if 'operation' in container:
        if container['operation'] not in ('configure', 'restore'):
            return MAX_BYTES
        path.append('value')
        if container['operation'] == 'restore':
            path.append('options')
    else:
        path.append('options')
    for key in path:
        if not isinstance(container, dict) or not isinstance(container.get(key), dict):
            return MAX_BYTES
        container = container[key]
    if 'policy' not in container:
        return MAX_BYTES
    stripped = dict(container)
    del stripped['policy']
    for i in reversed(range(len(path))):
        parent = value
        for key in path[:i]:
            parent = parent[key]
        stripped = dict(parent, **{path[i]: stripped})
    encode(stripped)
    return POLICY_BYTES


def snapshot(value):
    if not isinstance(value, dict) or set(value) != {'schema', 'options', 'identity', 'peers', 'images', 'tls'} \
            or type(value['schema']) is not int or value['schema'] != 1:
        raise ValueError('unsupported snapshot')
    result = {'schema': 1, 'options': settings(value['options']), 'identity': identity(value['identity']),
              'peers': peers(value['peers']), 'images': {}, 'tls': {}}
    if any(peer['id'] in (result['identity']['uuid'], result['identity'].get('warp_uuid')) for peer in result['peers']):
        raise ValueError('peer conflicts with controller')
    channels = {peer['id']: peer['channel'] for peer in result['peers'] if peer.get('channel', 'vless') != 'vless'}
    external = result['identity'].get('external', {})
    if set(external) != set(channels) or any(external[key]['channel'] != channel for key, channel in channels.items()):
        raise ValueError('external channel identities do not match peers')
    if not isinstance(value['images'], dict) or 'xr' not in value['images'] or set(value['images'])-{'xr', 'ng', 'wg', 'ad'}:
        raise ValueError('invalid node images')
    for name, image in value['images'].items():
        if not isinstance(image, str) or not re.fullmatch(r'ghcr\.io/axiomshiftbit/vpnbot-'+name+r'@sha256:[a-f0-9]{64}', image):
            raise ValueError('only immutable VPNBot images are accepted')
        # The AdGuard Home image of older snapshots is no longer run on nodes.
        if name != 'ad':
            result['images'][name] = image
    if result['options'].get('warp_mode', 'off') != 'off' and ('warp_uuid' not in result['identity'] or 'wg' not in result['images']):
        raise ValueError('WARP identity and helper image are required')
    if not isinstance(value['tls'], dict) or set(value['tls']) not in (set(), {'fullchain.pem', 'privkey.pem'}):
        raise ValueError('invalid certificate snapshot')
    for name, encoded in value['tls'].items():
        if not isinstance(encoded, str) or len(encoded) > 24576:
            raise ValueError('invalid certificate size')
        try:
            body = base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise ValueError('invalid certificate encoding') from error
        if not body.startswith(b'-----BEGIN ') or b'\x00' in body:
            raise ValueError('invalid certificate encoding')
        result['tls'][name] = encoded
    if needs_certificate(result['options']) and not result['tls']:
        raise ValueError('a TLS certificate is required')
    if result['options'].get('cover') and ('ng' not in result['images'] or 'cover_auth' not in result['identity']):
        raise ValueError('cover image and authentication are required')
    for channel in ('wireguard', 'amnezia'):
        if result['options'].get(channel, {}).get('enabled') and channel not in result['identity']:
            raise ValueError('backup channel identity is required')
    encode(result, policy_size(result))
    return result


def trusted(path):
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError('symlink in state path')
        if part.exists() and (part.stat().st_uid not in (0, os.geteuid()) or part.stat().st_mode & 0o022):
            # Sticky /tmp is permitted only as an ancestor for isolated tests.
            if part != Path('/tmp') or not part.stat().st_mode & 0o1000:
                raise ValueError('untrusted state path')


def atomic(path, data, mode=0o600):
    trusted(path)
    if path.exists() and (not path.is_file() or path.stat().st_nlink != 1):
        raise ValueError('unsafe state file')
    descriptor, temporary = tempfile.mkstemp(prefix='.'+path.name+'-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def sync_directory(path):
    descriptor = os.open(path, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class Store:
    def __init__(self, root):
        self.root = Path(root).absolute()
        trusted(self.root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        (self.root/'generations').mkdir(mode=0o700, exist_ok=True)
        trusted(self.root/'generations')

    def path(self, generation):
        if not isinstance(generation, str) or not GENERATION.fullmatch(generation):
            raise ValueError('invalid generation')
        path = self.root/'generations'/generation
        trusted(path)
        return path

    def read(self, name):
        path = self.root/name
        trusted(path)
        if not path.exists():
            return None
        large = name == 'request.json' or bool(re.fullmatch(r'generations/[a-f0-9]{32}/snapshot\.json', name))
        limit = POLICY_BYTES if large else MAX_BYTES
        if not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > limit:
            raise ValueError('invalid state file')
        value = decode(path.read_bytes(), limit)
        if path.stat().st_size > MAX_BYTES and (not isinstance(value, dict) or policy_size(value) == MAX_BYTES):
            raise ValueError('oversized state metadata')
        return value

    def current(self):
        value = self.read('current.json')
        if value is None:
            return None
        self.path(value)
        return value

    def load(self, generation=None):
        generation = generation or self.current()
        self.path(generation)
        return snapshot(self.read('generations/'+generation+'/snapshot.json'))

    def create(self, value, bundle=None):
        value = snapshot(value)
        data = encode(value, policy_size(value))
        self.prune()
        generation = secrets.token_hex(16)
        path = self.path(generation)
        path.mkdir(mode=0o700)
        atomic(path/'snapshot.json', data)
        if bundle is not None:
            atomic(path/'image-bundle.json', encode(bundle))
        return generation

    def prune(self):
        # Leave room for the new generation; never remove recovery targets.
        protected = {self.current(), self.read('previous.json')}
        pending = self.pending()
        if pending:
            protected.update((pending['before'], pending['after']))
        for generation in protected - {None}:
            self.path(generation)
        generations = []
        for path in (self.root/'generations').iterdir():
            if GENERATION.fullmatch(path.name):
                trusted(path)
                if not path.is_dir():
                    raise ValueError('invalid generation directory')
                generations.append(path)
        generations.sort(key=lambda path: path.stat().st_mtime_ns, reverse=True)
        available = max(0, 15 - sum(path.name in protected for path in generations))
        disposable = [path for path in generations if path.name not in protected]
        for path in disposable[available:]:
            shutil.rmtree(path)
        sync_directory(self.root/'generations')

    def pending(self):
        value = self.read('pending.json')
        if value is None:
            return None
        if not isinstance(value, dict) or set(value) != {'before', 'after', 'nonce', 'deadline'} \
                or type(value['deadline']) is not int or not isinstance(value['nonce'], str) \
                or not re.fullmatch(r'[a-f0-9]{64}', value['nonce']):
            raise ValueError('invalid pending transaction')
        for field in ('before', 'after'):
            self.path(value[field])
        return value

    def begin(self, generation):
        if self.pending():
            raise ValueError('another change awaits confirmation')
        self.load(generation)
        before = self.current()
        if before is None:
            raise ValueError('node is not initialized')
        value = dict(before=before, after=generation, nonce=secrets.token_hex(32), deadline=int(time.time())+120)
        atomic(self.root/'pending.json', encode(value))
        return value

    def activate(self, generation):
        self.load(generation)
        atomic(self.root/'current.json', encode(generation))

    def confirm(self, nonce):
        pending = self.pending()
        if not pending or not isinstance(nonce, str) or not secrets.compare_digest(nonce, pending['nonce']) \
                or self.current() != pending['after'] or time.time() >= pending['deadline']:
            raise ValueError('invalid or expired confirmation')
        atomic(self.root/'previous.json', encode(pending['before']))
        self.clear_pending()

    def clear_pending(self):
        (self.root/'pending.json').unlink(missing_ok=True)
        sync_directory(self.root)

    def rollback(self):
        pending = self.pending()
        if not pending:
            return None
        self.activate(pending['before'])
        self.clear_pending()
        return pending['before']
