#!/usr/bin/env python3
"""Validate fresh, one-run fixtures. No existing server data may be imported."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path('/opt/vpnbot-hosted-ci')


def main():
    if (ROOT / 'owner').read_text() != 'vpnbot-hosted-ci\n':
        raise RuntimeError('not a disposable fixture')
    for item in json.loads((ROOT / 'suite/client-artifacts.json').read_text()):
        p = Path(item['path'])
        if not p.is_relative_to(ROOT) or not os.access(p, os.X_OK):
            raise RuntimeError('invalid client artifact')
        if hashlib.sha256(p.read_bytes()).hexdigest() != item['sha256']:
            raise RuntimeError('changed native client')
    for name in ('wgclient', 'ovpnclient', 'ipsecclient', 'ssclient', 'warppeer'):
        subprocess.run(['docker', 'start', 'vpnbot-audit-' + name], check=True, capture_output=True)
    subprocess.run(['docker', 'start', 'vpnbot-protocol-target'], check=True, capture_output=True)
    print('Fresh clients verified')


if __name__ == '__main__':
    main()
