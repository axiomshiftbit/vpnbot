#!/usr/bin/env python3
"""Pinned node code generations and recovery of an interrupted unit installation.

The installed copy of this stdlib-only file is the stable node_manager.py
launcher. It never imports modules through the mutable installation root.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid

ACTIVE = 'code-active.json'
JOURNAL = 'code-transaction.json'
UNIT_ROOT = Path('/etc/systemd/system')


def trusted(path):
    for part in (path, *path.parents):
        if part.is_symlink() or part.exists() and (part.stat().st_uid not in (0, os.geteuid()) or part.stat().st_mode & 0o022):
            if part != Path('/tmp') or part.is_symlink() or not part.stat().st_mode & 0o1000:
                raise ValueError('untrusted code path')
    if path.is_file() and path.stat().st_nlink != 1:
        raise ValueError('untrusted code file')


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, body, mode=0o644):
    trusted(path)
    fd, temporary = tempfile.mkstemp(prefix='.'+path.name+'-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(body); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


@contextmanager
def locked(lib):
    path = lib/'.code.lock'; trusted(path)
    # Normal systemd workers see LIB read-only through ProtectSystem=strict.
    # flock needs no write access to an existing inode.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        trusted(path)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def active_id(lib):
    path = lib/ACTIVE; trusted(path)
    if not path.exists(): return None
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict) or set(value) != {'schema', 'release'} or value['schema'] != 1 \
            or not isinstance(value['release'], str) or not re.fullmatch('[a-f0-9]{32}', value['release']):
        raise ValueError('invalid code generation')
    return value['release']


def active_path(lib):
    identifier = active_id(lib)
    path = lib/'releases'/identifier if identifier else lib
    trusted(path)
    return path


def publish(lib, identifier):
    atomic(lib/ACTIVE, json.dumps({'schema': 1, 'release': identifier}).encode())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def recover(lib, units, command):
    """Caller holds .code.lock. Backups are on the same filesystem as units."""
    journal = lib/JOURNAL; trusted(journal)
    if not journal.exists(): return
    record = json.loads(journal.read_bytes())
    candidate = record.get('candidate')
    previous = record.get('previous')
    if record.get('schema') != 1 or not isinstance(candidate, str) or not re.fullmatch('[a-f0-9]{32}', candidate) \
            or previous is not None and (not isinstance(previous, str) or not re.fullmatch('[a-f0-9]{32}', previous)) \
            or not isinstance(record.get('units'), dict):
        raise ValueError('invalid code transaction')
    staging = units/('.vpnbot-code-'+candidate); trusted(staging)
    for name, old_hash in record['units'].items():
        if not re.fullmatch(r'vpnbot-node(?:-[a-z]+)?\.(service|timer)', name) \
                or old_hash is not None and (not isinstance(old_hash, str) or not re.fullmatch('[a-f0-9]{64}', old_hash)):
            raise ValueError('invalid code transaction unit')
        for path in (units/name, staging/('old-'+name), staging/('new-'+name)): trusted(path)
    current = active_id(lib)
    if current not in (previous, candidate): raise ValueError('unexpected active code generation')
    if current != candidate:
        for name, old_hash in record['units'].items():
            target, backup = units/name, staging/('old-'+name)
            if old_hash is None:
                target.unlink(missing_ok=True)
            elif not target.exists() or digest(target) != old_hash:
                if not backup.is_file() or digest(backup) != old_hash:
                    raise ValueError('code rollback backup missing')
                os.replace(backup, target)
            sync_directory(units)
        command(['systemctl', 'daemon-reload'])
    journal.unlink(); sync_directory(lib)
    # Do not recursively remove unknown files, including after a crash.
    for name in record['units']:
        for prefix in ('old-', 'new-'): (staging/(prefix+name)).unlink(missing_ok=True)
    staging.rmdir(); sync_directory(units)


def validate_release(path):
    # An import checks cross-module contracts, not just Python syntax.
    probe = 'import sys;sys.path.insert(0,sys.argv[1]);import node_manager'
    result = subprocess.run([sys.executable, '-I', '-B', '-c', probe, str(path)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=30, env={'PATH': '/usr/bin:/bin'})
    if result.returncode: raise ValueError('node code import validation failed')


def stage_release(lib, modules):
    releases = lib/'releases'; trusted(releases); releases.mkdir(mode=0o755, exist_ok=True)
    identifier = uuid.uuid4().hex
    path = releases/identifier; path.mkdir(mode=0o755)
    for name, data in modules.items():
        if not re.fullmatch(r'[a-z_]+\.py', name): raise ValueError('invalid code module')
        compile(data, name, 'exec')
        atomic(path/name, data)
    validate_release(path)
    sync_directory(path); sync_directory(releases)
    return identifier


def install(lib, units, modules, services, launcher, command):
    """Stage everything, publish units, then commit a single code pointer."""
    with locked(lib):
        recover(lib, units, command)
        candidate = stage_release(lib, modules)
        previous = active_id(lib)
        if previous is None and (lib/'node_manager.py').is_file():
            # First migration: preserve the complete legacy set before replacing
            # its entrypoint. It remains usable even if installing units fails.
            legacy = {}
            for name in modules:
                path = lib/name; trusted(path)
                if path.is_file(): legacy[name] = path.read_bytes()
            previous = stage_release(lib, legacy)
            publish(lib, previous)
        atomic(lib/'node_manager.py', launcher)
        staging = units/('.vpnbot-code-'+candidate); trusted(staging); staging.mkdir(mode=0o700)
        record = {'schema': 1, 'candidate': candidate, 'previous': previous, 'units': {}}
        for name, text in services.items():
            target = units/name; trusted(target)
            if target.exists():
                atomic(staging/('old-'+name), target.read_bytes(), target.stat().st_mode & 0o777)
                record['units'][name] = digest(staging/('old-'+name))
            else:
                record['units'][name] = None
            atomic(staging/('new-'+name), text.encode())
        sync_directory(staging); sync_directory(units)
        atomic(lib/JOURNAL, json.dumps(record, sort_keys=True).encode(), 0o600)
        try:
            for name in services:
                os.replace(staging/('new-'+name), units/name)
                sync_directory(units)
            command(['systemctl', 'daemon-reload'])
            publish(lib, candidate)
        except BaseException:
            recover(lib, units, command)
            raise
        recover(lib, units, command)


def main():
    if os.geteuid() != 0: raise ValueError('node launcher requires root')
    lib = Path(__file__).absolute().parent; trusted(lib)
    def command(args):
        subprocess.run(args, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=30)
    with locked(lib):
        recover(lib, UNIT_ROOT, command)
        if active_id(lib) is None: raise ValueError('node code is not installed')
        entry = active_path(lib)/'node_manager.py'; trusted(entry)
        if not entry.is_file(): raise ValueError('node entrypoint missing')
    # Absolute immutable path pins every later import in this process.
    os.execv(sys.executable, [sys.executable, '-I', '-B', str(entry), *sys.argv[1:]])


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('node code recovery failed', file=sys.stderr)
        sys.exit(1)
