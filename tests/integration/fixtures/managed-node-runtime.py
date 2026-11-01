#!/usr/bin/env python3
"""Real Docker + systemd rollback/backup tests inside the disposable node host."""
import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time

if subprocess.run(['systemd-detect-virt', '--container'], capture_output=True).stdout.strip() != b'docker':
    raise SystemExit('Run only in the disposable Docker test host')
os.umask(0o077)
sys.path.insert(0, '/lab/scripts')
import node_install as install
import node_manager as manager
import node_runtime as runtime
import node_state as state

IMAGE = 'ghcr.io/axiomshiftbit/vpnbot-xr@sha256:ae2180af6a5540e9a9cb510764b2bb9e4acf216d4bbccada713cd64d73989f38'
results = []


def run(args, **kwargs):
    return subprocess.run(list(map(str, args)), capture_output=True, timeout=45, **kwargs)


def check(label, ok):
    results.append({'case': label, 'ok': bool(ok)})
    print(('PASS ' if ok else 'FAIL ') + label, flush=True)
    if not ok:
        raise AssertionError(label)


def active():
    return backend.container()['State']['Running']


try:
    install.install_code('/lab/scripts')
    host = state.decode((install.ETC/'deployment.json').read_bytes())
    store = state.Store('/var/lib/vpnbot-node')
    backend = runtime.Runtime(store, host)
    control = manager.Manager(store, backend)
    # The namespace has no external interface/route: cached configurations must work offline.
    check('isolated-test-host', not run(['ip', 'route', 'show', 'default'], check=True).stdout.strip())
    backend.stop()
    store.clear_pending()
    work = Path('/run/node-runtime-fixture')
    work.mkdir(mode=0o700, exist_ok=True)
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=node.example.test',
         '-addext', 'subjectAltName=DNS:node.example.test', '-keyout', work/'privkey.pem', '-out', work/'fullchain.pem'], check=True)
    value = dict(schema=1, options=dict(transport='ws', family=4, core='origin', domain='node.example.test', mask='mask.example.test'),
                 identity=backend.identity(IMAGE), peers=[], images={'xr': IMAGE},
                 tls={name: base64.b64encode((work/name).read_bytes()).decode() for name in ('privkey.pem', 'fullchain.pem')})
    initial = store.create(value)
    backend.validate(initial)
    store.activate(initial)
    boot = run(['systemctl', 'restart', 'vpnbot-node.service'])
    check('systemd-boot-real-core', boot.returncode == 0 and active())
    info = backend.container()
    check('core-unprivileged', info['Config']['User'] == str(host['uid'])+':'+str(host['gid'])
          and info['HostConfig']['ReadonlyRootfs'] and info['HostConfig']['CapDrop'] == ['ALL'])
    check('no-host-control-secrets-mounted', len(info['Mounts']) == 1
          and info['Mounts'][0]['Destination'] == '/node' and not info['Mounts'][0]['RW']
          and set(info['HostConfig']['Tmpfs']) == {'/tmp'})
    original_pid = info['State']['Pid']
    broken = copy.deepcopy(value)
    broken['tls']['privkey.pem'] = base64.b64encode(b'-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n').decode()
    try:
        control.apply(broken)
        rejected = False
    except Exception:
        rejected = True
    check('invalid-certificate-preserves-core', rejected and backend.container()['State']['Pid'] == original_pid
          and store.current() == initial and store.pending() is None)
    # A normal setting change must not require registry access when its digest is cached.
    try:
        change = control.execute({'operation': 'configure', 'value': value['options'] | {'transport': 'grpc'}})
        changed = True
    except Exception:
        changed = False
    check('offline-change-uses-cached-digest', changed)
    check('new-transport-running', active() and store.load()['options']['transport'] == 'grpc')
    check('unconfirmed-change-is-durable', store.pending() is not None)
    # Boot is a separate process reading persisted state, not a mocked rollback.
    reboot = run(['systemctl', 'restart', 'vpnbot-node.service'])
    check('restart-rolls-back-unconfirmed-change', reboot.returncode == 0 and active()
          and store.current() == initial and store.pending() is None)
    change = control.execute({'operation': 'configure', 'value': value['options'] | {'transport': 'xhttp'}})
    store.confirm(change['pending']['nonce'])
    confirmed = store.current()
    reboot = run(['systemctl', 'restart', 'vpnbot-node.service'])
    check('restart-preserves-confirmed-change', reboot.returncode == 0 and store.current() == confirmed and active())
    snapshot = control.rpc({'action': 'backup'})
    peer = dict(id='22222222-2222-4222-8222-222222222222', name='panel', enabled=True)
    change = control.execute({'operation': 'peers', 'value': [peer]})
    store.confirm(change['pending']['nonce'])
    check('external-panel-profile-exported', control.rpc({'action': 'profile', 'peer': peer['id']})['outbound']['settings']['id'] == peer['id'])
    change = control.execute({'operation': 'restore', 'value': snapshot})
    store.confirm(change['pending']['nonce'])
    check('backup-restores-identities-certificate-and-options', store.load() == snapshot and active())
    check('restore-revokes-added-panel', not store.load()['peers'])
    change = control.execute({'operation': 'configure', 'value': snapshot['options'] | {'transport': 'ws'}})
    pending = store.pending()
    pending['deadline'] = int(time.time())-1
    state.atomic(store.root/'pending.json', state.encode(pending))
    run(['systemctl', 'start', 'vpnbot-node-watch.service'], check=True)
    check('watchdog-rolls-back-expired-change', store.pending() is None and store.load() == snapshot and active())
    run(['docker', 'kill', runtime.CONTAINER], check=True)
    run(['systemctl', 'start', 'vpnbot-node-watch.service'], check=True)
    check('watchdog-recovers-crashed-core', active())
    advanced = snapshot['options'] | {'core': 'fork', 'xray': {'encryption': {'auth': 'mlkem768', 'mode': 'xorpub'},
                'reality': {'mldsa': True}, 'smux': {'enabled': True, 'half_close': 'require'}}}
    change = control.execute({'operation': 'configure', 'value': advanced})
    store.confirm(change['pending']['nonce'])
    encrypted = control.rpc({'action': 'backup'})
    check('real-core-generates-postquantum-keys', encrypted['identity']['encryption']['auth'] == 'mlkem768'
          and bool(encrypted['identity']['mldsa']) and active())
    exported = control.rpc({'action': 'profile', 'peer': None})
    check('profile-keeps-encryption-and-smux', '.xorpub.' in exported['outbound']['settings']['encryption']
          and exported['outbound']['smux']['logicalHalfClose'] == 'require')
    change = control.execute({'operation': 'rotate', 'value': 'encryption'})
    store.confirm(change['pending']['nonce'])
    check('rotate-encryption-preserves-client-identity', store.load()['identity']['encryption'] != encrypted['identity']['encryption']
          and store.load()['identity']['uuid'] == encrypted['identity']['uuid'])
    change = control.execute({'operation': 'restore', 'value': encrypted})
    store.confirm(change['pending']['nonce'])
    run(['systemctl', 'restart', 'vpnbot-node.service'], check=True)
    check('backup-and-restart-preserve-postquantum-smux-settings', store.load() == encrypted
          and control.rpc({'action': 'profile', 'peer': None}) == exported and active())
finally:
    Path('/run/node-runtime-results.json').write_text(json.dumps(results, indent=2))
