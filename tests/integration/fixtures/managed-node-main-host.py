#!/usr/bin/env python3
"""Prepare/restore only the disposable node host for the native main bot test."""
import copy
import fcntl
import os
from pathlib import Path
import subprocess
import sys

if subprocess.run(['systemd-detect-virt', '--container'], capture_output=True).stdout.strip() != b'docker':
    raise SystemExit('Disposable Docker host required')
os.umask(0o077)
sys.path.insert(0, '/lab/scripts')
import node_install as install
import node_manager as manager
import node_runtime as runtime
import node_state as state
import node_config as config

work = Path('/run/managed-main-fixture')
store = state.Store('/var/lib/vpnbot-node')
lock = os.open(store.root/'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
fcntl.flock(lock, fcntl.LOCK_EX)
mode = sys.argv[1]
if mode in ('prepare', 'prepare-amnezia', 'prepare-amnezia-ipv6', 'prepare-ssh6'):
    original_core = config.core_config
    def diagnostic_core(*args, **kwargs):
        value = original_core(*args, **kwargs)
        value['log'] = {'loglevel': 'debug'}
        return value
    config.core_config = diagnostic_core
    work.mkdir(mode=0o700)
    original = store.load()
    host = state.decode((install.ETC/'deployment.json').read_bytes())
    state.atomic(work/'snapshot.json', state.encode(original))
    state.atomic(work/'deployment.json', state.encode(host))
    state.atomic(work/'controller.pub', (install.ETC/'controller.pub').read_bytes())
    host.update(interface='mn-node', public4='11.77.0.4', sources=['11.77.0.3'], admins=['11.77.0.3'], ssh_ports=[2222])
    if mode.startswith('prepare-amnezia'):
        import pwd
        install.accounts()
        host['awg_uid'] = pwd.getpwnam(install.AWG).pw_uid
    if mode.endswith(('-ipv6', '-ssh6')):
        host['public6'] = '2606:4700:4700::1111'
        host['sources'].append('2620:fe::fe')
    state.atomic(install.ETC/'deployment.json', state.encode(host))
    install.install_code('/lab/scripts')
    install.install_ssh(sys.stdin.read().strip(), host['sources'])
    value = copy.deepcopy(original)
    if mode.startswith('prepare-amnezia'):
        value['images']['xr'] = Path('/lab/amnezia-image-ref').read_text().strip()
    value['options'].update(transport='reality', family=4, connect_family=4, core='origin', cover=True)
    if mode.endswith('-ipv6'):
        value['options']['connect_family'] = 6
    value['options']['xray'] = {}
    control = manager.Manager(store, runtime.Runtime(store, host))
    result = control.apply(value)
    store.confirm(result['pending']['nonce'])
    Path(work/'probe').write_text('managed-main-pass\n')
elif mode == 'reinstall':
    host = state.decode((install.ETC/'deployment.json').read_bytes())
    backend = runtime.Runtime(store, host)
    value = copy.deepcopy(store.load())
    value['options']['xray'] = {}
    value['options']['wireguard'] = {'enabled': False, 'active': False}
    value['options']['amnezia'] = {'enabled': False, 'active': False}
    value['identity'] = backend.identity(value['images']['xr'])
    value['peers'] = []
    backend.ensure_keys(value)
    result = manager.Manager(store, backend).apply(value)
    store.confirm(result['pending']['nonce'])
    dropin = Path('/etc/ssh/sshd_config.d/01-vpnbot-native-reinstall.conf')
    if dropin.exists():
        raise RuntimeError('unexpected reinstall fixture file')
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(work/'new-host-key')],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    state.atomic(dropin, ('HostKey '+str(work/'new-host-key')+'\n').encode(), 0o644)
    subprocess.run(['sshd', '-t'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    subprocess.run(['systemctl', 'reload', 'ssh'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
elif mode == 'restore':
    # Recover a failed test transaction with its current deployment identity;
    # the saved pre-test deployment may not yet have an Amnezia service UID.
    if store.pending():
        current_host = state.decode((install.ETC/'deployment.json').read_bytes())
        manager.Manager(store, runtime.Runtime(store, current_host)).recover()
    host = state.decode((work/'deployment.json').read_bytes())
    state.atomic(install.ETC/'deployment.json', state.encode(host))
    state.atomic(install.ETC/'controller.pub', (work/'controller.pub').read_bytes(), 0o644)
    control = manager.Manager(store, runtime.Runtime(store, host))
    result = control.apply(state.decode((work/'snapshot.json').read_bytes()))
    store.confirm(result['pending']['nonce'])
    if (work/'new-host-key.pub').exists():
        Path('/etc/ssh/sshd_config.d/01-vpnbot-native-reinstall.conf').unlink(missing_ok=True)
        subprocess.run(['sshd', '-t'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        subprocess.run(['systemctl', 'reload', 'ssh'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    import shutil
    shutil.rmtree(work)
else:
    raise SystemExit('invalid fixture action')
