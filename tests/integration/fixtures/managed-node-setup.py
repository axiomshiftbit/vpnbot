#!/usr/bin/env python3
"""Fresh bootstrap on the disposable host, then restore its previous fixture."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import traceback
import zipfile

if subprocess.run(['systemd-detect-virt', '--container'], capture_output=True).stdout.strip() != b'docker':
    raise SystemExit('Run only in the disposable Docker test host')
os.umask(0o077)
sys.path.insert(0, '/lab/scripts')
import node_install as install
import node_setup as setup
import node_state as state
from node_runtime import Runtime, CONTAINER, COVER_CONTAINER, LABEL
import image_bundle

work = Path(tempfile.mkdtemp(prefix='node-setup-', dir='/var/tmp'))
failures = 0
entry_created = False


def run(args, **kwargs):
    return subprocess.run(list(map(str, args)), capture_output=True, timeout=120, **kwargs)


def check(label, ok):
    global failures
    failures += not ok
    print(('PASS ' if ok else 'FAIL ')+label, flush=True)


try:
    if run(['ip', 'route', 'show', 'default'], check=True).stdout.strip():
        raise RuntimeError('external network must be detached')
    host = state.decode((install.ETC/'deployment.json').read_bytes())
    before = state.Store(setup.ROOT).load()
    protected = [install.ETC/'deployment.json', install.ETC/'controller.pub', install.ETC/'guard.nft',
                 Path('/etc/ssh/sshd_config.d/00-vpnbot-node.conf'), Path('/etc/sudoers.d/vpnbot-node')]
    original = {path: path.read_bytes() if path.exists() else None for path in protected}
    run(['systemctl', 'stop', 'vpnbot-node-watch.timer', 'vpnbot-node-renew.timer', 'vpnbot-node.service'], check=True)
    run(['nft', 'delete', 'table', 'inet', 'vpnbot_node'])
    (install.ETC/'guard.nft').unlink(missing_ok=True)
    shutil.move(setup.ROOT, work/'previous-state')
    key = work/'controller'
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key], check=True)
    manifest = dict(schema=1, source='a'*40, run=1, attempt=1, state_epoch=1,
                    images={name: image_bundle.REGISTRY+name+'@sha256:'+'a'*64 for name in image_bundle.IMAGES})
    manifest['images'].update(before['images'])
    bundle = work/'bundle.json'
    bundle.write_bytes(state.encode(manifest))
    value = dict(schema=1, controller_key=key.with_suffix('.pub').read_text(),
                 deployment={k: v for k, v in host.items() if k not in ('uid', 'gid', 'cover_uid', 'awg_uid')},
                 options=dict(transport='reality', core='origin', family=4, connect_family=4,
                              domain='', mask='mask.example.test', cover=False))
    value['deployment'].update(interface='lo', ssh_ports=[2222])
    if '--fail-after-start' in sys.argv:
        original_command = setup.command
        def fail_after_start(args, **kwargs):
            result = original_command(args, **kwargs)
            if args[:2] == ['systemctl', 'start'] and 'vpnbot-node.service' in args:
                raise RuntimeError('synthetic setup interruption')
            return result
        setup.command = fail_after_start
        try:
            setup.setup(value, '/lab/scripts', bundle=bundle)
            interrupted = False
        except RuntimeError:
            interrupted = True
        finally:
            setup.command = original_command
        check('partial-install-reproduces-post-start-failure', interrupted)
        check('partial-install-does-not-claim-installed-state', not (setup.ROOT/'current.json').exists())
        check('partial-install-leaves-no-running-node', not run(['docker', 'ps', '-q', '--filter', 'label='+LABEL+'=1']).stdout.strip())
        units = ('vpnbot-node.service', 'vpnbot-node-watch.timer', 'vpnbot-node-renew.timer')
        check('partial-install-disables-automatic-services', all(run(['systemctl', 'is-enabled', '--quiet', name]).returncode != 0 for name in units))
        check('partial-install-stops-automatic-services', all(run(['systemctl', 'is-active', '--quiet', name]).returncode != 0 for name in units))
        check('partial-install-removes-persistent-guard', not (install.ETC/'guard.nft').exists())
        check('partial-install-restores-previous-controller-authorization',
              (install.ETC/'controller.pub').read_bytes() == original[install.ETC/'controller.pub'])
        # Remove only fixture leftovers before testing a clean retry. All
        # original state is restored by the outer finally block below.
        run(['systemctl', 'disable', '--now', *units])
        run(['nft', 'delete', 'table', 'inet', 'vpnbot_node'])
        (install.ETC/'guard.nft').unlink(missing_ok=True)
        shutil.rmtree(setup.ROOT, ignore_errors=True)
    try:
        if '--entrypoint' in sys.argv:
            target = Path('/root/vpnbot')
            if target.exists():
                raise RuntimeError('entrypoint fixture requires an unused installation path')
            for binary in ('rsync', 'unzip', 'docker', 'sshd', 'nft', 'sudo'):
                if not shutil.which(binary):
                    raise RuntimeError('fixture dependency missing: '+binary)
            # This disconnected stand already has OS dependencies installed.
            # Exercise the original archive/bootstrap flow, while preventing
            # apt from contacting external repositories during the test.
            shim = work/'bin'
            shim.mkdir()
            (shim/'apt').write_text('#!/bin/sh\nprintf "called\\n" >> "'+str(work/'apt-calls')+'"\n')
            (shim/'apt').chmod(0o755)
            archive = work/'vpnbot.zip'
            with zipfile.ZipFile(archive, 'w') as package:
                package.writestr('app/', '')
                for file in Path('/lab/scripts').glob('*'):
                    if file.is_file() and file.suffix in ('.py', '.sh'):
                        package.write(file, 'scripts/'+file.name)
                package.write(bundle, 'update/image-bundle.pending.json')
            public = work/'enrollment.json'
            public.write_bytes(state.encode(value, state.MAX_DEPLOYMENT_BYTES))
            environment = {'PATH': str(shim)+':'+os.environ['PATH'], 'HOME': '/root', 'LANG': 'C.UTF-8',
                           'VPNBOT_ARCHIVE': str(archive), 'VPNBOT_NODE_CONFIG': str(public)}
            entry_created = True
            response = run(['bash', '/lab/scripts/init.sh', '--mode', 'node', 'dev'], env=environment)
            installed = response.returncode == 0
            result = {'host_fingerprint': 'SHA256:' if b'SHA256:' in response.stdout else ''}
            check('entrypoint-reaches-dependency-installation', (work/'apt-calls').is_file())
            check('entrypoint-does-not-create-telegram-config', not (target/'app/config.php').exists())
            check('entrypoint-has-public-installation-result', b'vpnbot-ctl' in response.stdout and b'ssh-ed25519' in response.stdout)
            if not installed:
                print('ENTRYPOINT_EXIT '+str(response.returncode), flush=True)
        else:
            result = setup.setup(value, '/lab/scripts', bundle=bundle)
            installed = result.get('installed') is True
    except Exception as error:
        print('SETUP_ERROR '+type(error).__name__+' at '+'>'.join(frame.name+':'+str(frame.lineno)
              for frame in traceback.extract_tb(error.__traceback__)), flush=True)
        installed = False
    check('fresh-install-completes-with-real-systemd', installed)
    if installed:
        store = state.Store(setup.ROOT)
        backend = Runtime(store, state.decode((install.ETC/'deployment.json').read_bytes()))
        check('fresh-install-one-required-container', backend.status()['running'] and backend.container(COVER_CONTAINER) is None)
        check('fresh-install-pinned-host-fingerprint', result['host_fingerprint'].startswith('SHA256:'))
        check('fresh-install-timers-enabled', all(run(['systemctl', 'is-enabled', '--quiet', name]).returncode == 0
              for name in ('vpnbot-node.service', 'vpnbot-node-watch.timer', 'vpnbot-node-renew.timer')))
        check('fresh-install-ssh-source-restricted', b'from="' in (install.ETC/'controller.pub').read_bytes())
        snapshot = store.load()
        run(['systemctl', 'restart', 'vpnbot-node.service'], check=True)
        check('fresh-install-reboot-keeps-state', store.load() == snapshot and backend.status()['running'])
        try:
            setup.setup(value, '/lab/scripts', bundle=bundle)
            refused = False
        except Exception:
            refused = True
        check('repeat-install-keeps-existing-identities', refused and store.load() == snapshot and backend.status()['running'])
finally:
    run(['systemctl', 'stop', 'vpnbot-node-watch.timer', 'vpnbot-node-renew.timer', 'vpnbot-node.service'])
    for name in (CONTAINER, COVER_CONTAINER):
        run(['docker', 'rm', '-f', name])
    if (work/'previous-state').exists():
        shutil.rmtree(setup.ROOT, ignore_errors=True)
        shutil.move(work/'previous-state', setup.ROOT)
        for path, contents in original.items():
            if contents is None:
                path.unlink(missing_ok=True)
            else:
                state.atomic(path, contents, 0o440 if path.name == 'vpnbot-node' else 0o644 if path.name.endswith('.conf') or path.suffix == '.pub' else 0o600)
        run(['systemctl', 'reload', 'ssh'], check=True)
        run(['systemctl', 'start', 'vpnbot-node.service'], check=True)
    shutil.rmtree(work)
    if entry_created:
        shutil.rmtree('/root/vpnbot')
raise SystemExit(bool(failures))
