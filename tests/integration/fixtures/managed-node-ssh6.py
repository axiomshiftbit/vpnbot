#!/usr/bin/env python3
"""Pinned SSH RPC using native IPv6 and exact source authorization."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil

if subprocess.run(['systemd-detect-virt', '--container'], capture_output=True).stdout.strip() != b'docker':
    raise SystemExit('Run only in the disposable Docker test host')
os.umask(0o077)
sys.path.insert(0, '/lab/scripts')
import node_install as install
import node_state as state


def run(args, **kwargs):
    return subprocess.run(list(map(str, args)), capture_output=True, timeout=20, **kwargs)


root = Path(tempfile.mkdtemp(prefix='node-ssh6-', dir='/run'))
authorized = install.ETC/'controller.pub'
before = authorized.read_bytes()  # Public authorized key, never a private key.
addresses = ['2606:4700:4700::1111', '2620:fe::fe', '2620:fe::9']
results = []


def check(label, ok):
    results.append({'case': label, 'ok': bool(ok)})
    print(('PASS ' if ok else 'FAIL ') + label, flush=True)
    if not ok:
        raise AssertionError(label)


try:
    for address in addresses:
        run(['ip', '-6', 'address', 'add', address+'/128', 'dev', 'lo', 'nodad'], check=True)
    key = root/'identity'
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key], check=True)
    install.install_ssh(key.with_suffix('.pub').read_text(), [addresses[1]])
    public = Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()[:2]
    known = root/'known_hosts'
    known.write_text('['+addresses[0]+']:2222 '+' '.join(public)+'\n')
    args = ['ssh', '-6', '-F', '/dev/null', '-T', '-p', '2222', '-i', key, '-b', addresses[1],
            '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile='+str(known), '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'ConnectTimeout=3', install.CONTROL+'@'+addresses[0]]
    result = run(args, input=b'{"action":"ping"}')
    check('ipv6-to-ipv6-pinned-rpc', result.returncode == 0 and json.loads(result.stdout)['ok'])
    args[args.index('-b')+1] = addresses[2]
    result = run(args, input=b'{"action":"ping"}')
    check('ipv6-unlisted-controller-denied', result.returncode != 0 and not result.stdout)
    args[args.index('-b')+1] = addresses[1]
    result = run(args[:-1]+['-W', '[::1]:2222', args[-1]])
    check('ipv6-forwarding-denied', result.returncode != 0)
finally:
    state.atomic(authorized, before, 0o644)
    for address in addresses:
        run(['ip', '-6', 'address', 'del', address+'/128', 'dev', 'lo'])
    shutil.rmtree(root)
    Path('/run/node-ssh6-results.json').write_text(json.dumps(results, indent=2))
