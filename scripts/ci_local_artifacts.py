#!/usr/bin/env python3
"""Small CI JSON artifacts shared by runners on one HomeBuild host.

Images stay in GHCR. This is deliberately not a general archive/file service.
The root-only store contains no credentials, logs or test configurations.
"""
import argparse
from contextlib import contextmanager
import fcntl
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import time

from image_bundle import IMAGES
from ci_release_policy import stages

ROOT = Path('/var/lib/vpnbot-ci-artifacts')
FILES = {'descriptor-' + image: image + '.json' for image in IMAGES}
FILES.update({'image-bundle': 'bundle.json', 'native-admission': 'native.json'})
FILES.update({'admission-'+stage: stage+'.json' for stage in stages()})
MAX_BYTES = 16 * 1024 * 1024
RETENTION = 7 * 24 * 3600


def regular_bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_BYTES:
            raise ValueError('not a bounded regular file')
        data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError('artifact too large')
        return data


def atomic(path, data, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix='.artifact-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Store:
    def __init__(self, root, run, attempt, source, temporary):
        if not re.fullmatch(r'[1-9][0-9]{0,19}', run) or not re.fullmatch(r'[1-9][0-9]{0,5}', attempt):
            raise ValueError('invalid run identity')
        if not re.fullmatch(r'[0-9a-f]{40}', source):
            raise ValueError('invalid source')
        self.root = Path(root)
        self.directory = self.root / (run + '-' + source)
        self.identity = {'run': run, 'source': source}
        self.attempt = int(attempt)
        self.temporary = Path(temporary)
        if not self.temporary.is_absolute() or self.temporary.resolve() != self.temporary:
            raise ValueError('invalid runner temporary directory')

    @contextmanager
    def locked(self):
        self.root.mkdir(mode=0o700, exist_ok=True)
        if self.root.resolve() != self.root or self.root.stat().st_mode & 0o077:
            raise ValueError('store must be private and not a symlink')
        fd = os.open(self.root / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if self.directory.is_symlink():
                raise ValueError('invalid run directory')
            yield

    def local_path(self, value):
        path = Path(value)
        if not path.is_absolute() or '..' in path.parts or path.resolve() != path:
            raise ValueError('invalid artifact path')
        if not path.is_relative_to(self.temporary):
            raise ValueError('artifact must stay inside runner temporary directory')
        return path

    def read(self, name):
        value = json.loads(regular_bytes(self.directory / (name + '.json')))
        if (not isinstance(value, dict) or value.get('identity') != self.identity or value.get('name') != name
                or type(value.get('attempt')) is not int or not 1 <= value['attempt'] <= self.attempt):
            raise ValueError('artifact belongs to another build')
        data = value['content'].encode('utf-8')
        if hashlib.sha256(data).hexdigest() != value['sha256']:
            raise ValueError('artifact checksum mismatch')
        if not isinstance(json.loads(data), dict):
            raise ValueError('expected JSON object')
        return data

    def upload(self, name, pattern):
        if name not in FILES or '\n' in pattern:
            raise ValueError('unsupported artifact')
        # One explicit JSON per job, including descriptor/*.json. Never recurse
        # into a checkout or copy an archive, hidden file or directory.
        paths = glob.glob(pattern)
        if len(paths) != 1:
            raise ValueError('expected exactly one artifact file')
        path = self.local_path(paths[0])
        if path.name != FILES[name]:
            raise ValueError('unexpected artifact filename')
        data = regular_bytes(path)
        if not isinstance(json.loads(data), dict):
            raise ValueError('expected JSON object')
        value = dict(identity=self.identity, attempt=self.attempt, name=name,
                     sha256=hashlib.sha256(data).hexdigest(), content=data.decode('utf-8'))
        encoded = json.dumps(value, ensure_ascii=False).encode('utf-8')
        if len(encoded) > MAX_BYTES:
            raise ValueError('artifact too large')
        with self.locked():
            self.directory.mkdir(mode=0o700, exist_ok=True)
            target = self.directory / (name + '.json')
            if target.exists() or target.is_symlink():
                self.read(name)  # An earlier attempt cannot overwrite a newer one.
            atomic(target, encoded)
            os.utime(self.directory, None)
            self.prune()

    def download(self, name, pattern, merge, destination):
        if name in FILES and not pattern:
            names = [name]
        elif not name and pattern in ('descriptor-*', 'admission-*') and merge:
            names = sorted(n for n in FILES if n.startswith(pattern[:-1]))
        else:
            raise ValueError('unsupported artifact selection')
        directory = self.local_path(destination)
        with self.locked():
            # Validate the entire selection before writing any output. A missing
            # or damaged descriptor is fatal; never silently use a partial set.
            data = {n: self.read(n) for n in names}
            directory.mkdir(parents=True, exist_ok=True)
            for n, content in data.items():
                target = self.local_path(str(directory / FILES[n]))
                atomic(target, content, 0o644)

    def prune(self):
        # Failed/cancelled runs survive for seven days to support Re-run failed
        # jobs, just like named GitHub artifacts from earlier run attempts.
        for path in self.root.iterdir():
            if (path != self.directory and re.fullmatch(r'[1-9][0-9]{0,19}-[0-9a-f]{40}', path.name)
                    and not path.is_symlink() and path.is_dir()
                    and time.time() - path.stat().st_mtime > RETENTION):
                shutil.rmtree(path)

    def cleanup(self):
        with self.locked():
            if self.directory.exists():
                shutil.rmtree(self.directory)
            self.prune()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['upload', 'download', 'cleanup'])
    parser.add_argument('--name', default='')
    parser.add_argument('--pattern', default='')
    parser.add_argument('--merge-multiple', choices=['true', 'false'], default='false')
    parser.add_argument('--path', default='')
    args = parser.parse_args()
    if (os.geteuid() != 0 or os.environ.get('GITHUB_REPOSITORY') != 'axiomshiftbit/vpnbot'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'self-hosted'
            or Path('/etc/vpnbot-ci-test-host').read_text().strip() != 'home-build'):
        raise ValueError('local artifacts require the dedicated HomeBuild host')
    store = Store(ROOT, os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT'],
                  os.environ['GITHUB_SHA'], os.environ['RUNNER_TEMP'])
    if args.operation == 'upload':
        store.upload(args.name, args.path)
    elif args.operation == 'download':
        store.download(args.name, args.pattern, args.merge_multiple == 'true', args.path)
    else:
        store.cleanup()
    print('HomeBuild JSON artifact: ' + args.operation + ' OK')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as error:
        # No file contents, paths, environment or credentials in the job log.
        print('Local artifact operation rejected: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
