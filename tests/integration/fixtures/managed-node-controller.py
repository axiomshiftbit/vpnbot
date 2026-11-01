#!/usr/bin/env python3
"""Actual SSH controller handover on the disconnected systemd test host."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

if subprocess.run(['systemd-detect-virt', '--container'], capture_output=True).stdout.strip() != b'docker':
    raise SystemExit('Disposable Docker host required')
os.umask(0o077)
sys.path.insert(0, '/lab/scripts')
import node_install as install
import node_setup as setup
import node_state as state

def run(args, **kwargs):
    return subprocess.run(list(map(str, args)), capture_output=True, timeout=20, **kwargs)

def check(label, ok):
    print(('PASS ' if ok else 'FAIL ')+label, flush=True)
    if not ok:
        raise RuntimeError(label)

root = Path(tempfile.mkdtemp(prefix='node-handover-', dir='/run'))
store = state.Store(setup.ROOT)
before = store.load()
authorized = install.ETC/'controller.pub'
saved_authorized = authorized.read_bytes()  # Public keys only.
job = store.read('job.json')
try:
    for name in ('first', 'next'):
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', root/name], check=True)
    host = state.decode((install.ETC/'deployment.json').read_bytes(), state.MAX_DEPLOYMENT_BYTES)
    install.install_ssh((root/'first.pub').read_text(), host['sources'])
    pin = ' '.join(Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()[:2])
    (root/'known').write_text('[11.77.0.4]:2222 '+pin+'\n')

    def ping(name):
        result = run(['ssh', '-F', '/dev/null', '-T', '-i', root/name, '-p', '2222', '-b', '11.77.0.2',
                      '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                      '-o', 'UserKnownHostsFile='+str(root/'known'), '-o', 'GlobalKnownHostsFile=/dev/null',
                      '-o', 'ConnectTimeout=3', 'vpnbot-ctl@11.77.0.4'], input=b'{"action":"ping"}')
        return result.returncode == 0 and json.loads(result.stdout).get('ok') is True

    check('initial controller connects', ping('first'))
    check('next controller initially refused', not ping('next'))
    state.atomic(store.root/'job.json', state.encode({'state': 'running'}))
    try:
        setup.replace_controller((root/'next.pub').read_text())
        blocked = False
    except ValueError:
        blocked = True
    check('handover during running job refused without replacing authorization', blocked and (root/'first.pub').read_text().split()[1].encode() in authorized.read_bytes())
    if job is None:
        (store.root/'job.json').unlink()
    else:
        state.atomic(store.root/'job.json', state.encode(job))
    setup.replace_controller((root/'next.pub').read_text())
    check('new controller connects after handover', ping('next'))
    check('old controller is revoked', not ping('first'))
    check('handover preserves node settings identities peers certificates', store.load() == before)
    check('handover leaves core running', run(['systemctl', 'is-active', '--quiet', 'vpnbot-node.service']).returncode == 0)
finally:
    state.atomic(authorized, saved_authorized, 0o644)
    if job is None:
        (store.root/'job.json').unlink(missing_ok=True)
    else:
        state.atomic(store.root/'job.json', state.encode(job))
    shutil.rmtree(root)
