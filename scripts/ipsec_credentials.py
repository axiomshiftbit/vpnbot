#!/usr/bin/env python3
"""Rebuild derived credentials from durable user intent before charon starts."""
import fcntl
import json
import os
from pathlib import Path
import re
import sys
import tempfile


def render(users, psk):
    if users == []: users = {}
    if not isinstance(users, dict) or not isinstance(psk, str) or not psk or re.search(r'[\x00-\x1f]', psk):
        raise ValueError('invalid IPsec credentials')
    lines = ['# Managed by vpnbot — regenerated from users_ikev2.json, do not edit.',
             'secrets {', '    ike-l2tp {', '        secret = "'+psk.replace('\\', '\\\\').replace('"', '\\"')+'"', '    }']
    index = 0
    for name, row in users.items():
        if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,64}', name) or not isinstance(row, dict) \
                or not isinstance(row.get('pass'), str) or re.search(r'[\x00-\x1f"\\]', row['pass']) \
                or type(row.get('disabled')) is not bool \
                or row.get('pending', 'reload') not in ('reload', 'disable', 'delete'):
            raise ValueError('invalid IPsec user')
        if row['disabled'] or row.get('pending') in ('disable', 'delete'): continue
        index += 1
        lines += [f'    eap-{index} {{', '        id = "'+name+'"', '        secret = "'+row['pass']+'"', '    }']
    return '\n'.join(lines+['}', ''])


def rebuild(root, lock):
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        users = root/'users_ikev2.json'
        # Preserve unmanaged legacy credentials only when no managed DB exists.
        if not users.exists() and (root/'secrets.conf').exists(): return
        body = render(json.loads(users.read_bytes()) if users.exists() else {}, (root/'psk').read_text().strip())
        fd, temporary = tempfile.mkstemp(prefix='.secrets-', dir=root)
        try:
            with os.fdopen(fd, 'w') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(body); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, root/'secrets.conf')
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory)
            finally: os.close(directory)
        finally:
            Path(temporary).unlink(missing_ok=True)
    finally:
        os.close(descriptor)


if __name__ == '__main__':
    try:
        os.umask(0o077)
        rebuild(Path('/config/ipsec'), Path('/logs/.lock.ipsec-users'))
    except Exception:
        print('IPsec credential preparation failed', file=sys.stderr)
        sys.exit(1)
