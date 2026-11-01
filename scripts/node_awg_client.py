#!/usr/bin/env python3
"""Maintain at most eight fixed Amnezia carriers inside the Xray container.

The bot writes validated metadata in its read-only Xray configuration. Helpers
have separate UIDs, no capabilities, bounded descriptors and no writable state.
No shell, arbitrary target, SOCKS server or kernel TUN is exposed.
"""
import ctypes
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import node_awg

ROOT = Path('/run/vpnbot-amnezia')
CONFIG = Path('/xray.json')
BINARY = '/usr/bin/wireproxy-node'


def metadata(value):
    if isinstance(value, list):
        value = {str(index): row for index, row in enumerate(value)}
    if not isinstance(value, dict) or len(value) > 8:
        raise ValueError('invalid Amnezia slot list')
    result = {}
    for slot, row in value.items():
        if not isinstance(slot, str) or not re.fullmatch('[0-7]', slot) or not isinstance(row, dict) \
                or set(row) != {'client', 'session'} or not isinstance(row['session'], str) \
                or not re.fullmatch('[a-f0-9]{16}', row['session']):
            raise ValueError('invalid Amnezia slot')
        result[int(slot)] = {'client': node_awg.validate_client(row['client']), 'session': row['session']}
    return result


def read_config():
    descriptor = os.open(CONFIG, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 8*1024*1024:
            raise ValueError('invalid Xray configuration file')
        value = json.loads(source.read(8*1024*1024+1))
    return metadata(value.get('_vpnbot_amnezia', {}))


def restrict(uid):
    resource.setrlimit(resource.RLIMIT_NOFILE, (512, 512))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    # NoNewPrivileges remains set after exec. setuid clears permitted and
    # effective capabilities; no supplementary group can read another slot.
    if ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0) != 0:
        raise OSError('cannot restrict Amnezia helper')
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)


class Carriers:
    def __init__(self):
        self.active, self.retry = {}, {}
        if ROOT.is_symlink():
            raise ValueError('unsafe carrier directory')
        ROOT.mkdir(mode=0o711, exist_ok=True)
        info = ROOT.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unsafe carrier directory')
        ROOT.chmod(0o711)

    def stop(self, slot):
        entry = self.active.get(slot)
        if entry:
            process = entry[1]
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        # A task blocked in kernel I/O may outlive SIGKILL.
                        # Keep its slot occupied and reap it on the next pass.
                        return
        self.active.pop(slot, None)
        (ROOT/(str(slot)+'.conf')).unlink(missing_ok=True)

    def sync(self, desired):
        for slot, (value, process) in list(self.active.items()):
            if value != desired.get(slot) or process.poll() is not None:
                self.stop(slot)
        for slot, value in desired.items():
            if slot in self.active or self.retry.get(slot, 0) > time.monotonic():
                continue
            self.retry[slot] = time.monotonic()+5
            path = ROOT/(str(slot)+'.conf')
            descriptor, temporary = tempfile.mkstemp(dir=ROOT, prefix='.carrier-')
            try:
                with os.fdopen(descriptor, 'w') as stream:
                    os.fchmod(stream.fileno(), 0o640)
                    os.fchown(stream.fileno(), 0, 61000+slot)
                    stream.write(node_awg.client(value['client'], slot))
                os.replace(temporary, path)
                process = subprocess.Popen([BINARY, '-s', '-c', str(path)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    env={'PATH':'/usr/bin:/bin', 'GODEBUG':'multipathtcp=0', 'GOMAXPROCS':'2', 'GOMEMLIMIT':'48MiB'},
                    preexec_fn=lambda: restrict(61000+slot))
                self.active[slot] = (value, process)
            except (OSError, ValueError, subprocess.SubprocessError):
                path.unlink(missing_ok=True)
            finally:
                Path(temporary).unlink(missing_ok=True)
        self.retry = {slot: value for slot, value in self.retry.items() if slot in desired}


def main():
    if os.geteuid() != 0:
        raise SystemExit('Carrier supervisor must start as root')
    os.umask(0o077)
    carriers = Carriers()
    running = True
    def finish(*_):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, finish)
    signal.signal(signal.SIGINT, finish)
    try:
        while running:
            try:
                desired = read_config()
            except (OSError, ValueError, TypeError, AttributeError, RecursionError):
                desired = {}
            carriers.sync(desired)
            time.sleep(.5)
    finally:
        for slot in list(carriers.active):
            carriers.stop(slot)


if __name__ == '__main__':
    main()
