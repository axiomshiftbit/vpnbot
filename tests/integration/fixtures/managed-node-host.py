#!/usr/bin/env python3
"""Real sshd/sudo/systemd integration in the disposable systemd container."""
import json
import os
from pathlib import Path
import subprocess
import sys

if subprocess.run(['systemd-detect-virt', '--container'], capture_output=True).stdout.strip() != b'docker':
    raise SystemExit('Run only inside the disposable Docker test host')
if Path('/run/host-node-test.done').exists():
    raise SystemExit('Use a fresh test container')
os.umask(0o077)
sys.path.insert(0, '/lab/scripts')
sys.path.insert(0, '/lab/tests')
import node_install as install
import node_state as state
from node_state_test import VALUE
from node_config_test import HOST

results = []


def run(args, **kwargs):
    return subprocess.run(list(map(str, args)), capture_output=True, timeout=30, **kwargs)


def check(label, ok):
    results.append({'case': label, 'ok': bool(ok)})
    print(('PASS ' if ok else 'FAIL ') + label, flush=True)
    if not ok:
        raise AssertionError(label)


try:
    install.install_code('/lab/scripts')
    account = install.accounts()
    host = HOST | {'uid': account.pw_uid, 'gid': account.pw_gid}
    state.atomic(install.ETC/'deployment.json', state.encode(host))
    store = state.Store('/var/lib/vpnbot-node')
    store.activate(store.create(VALUE))
    for address in ('11.77.0.2/32', '11.77.0.4/32'):
        run(['ip', 'address', 'replace', address, 'dev', 'lo'], check=True)
    state.atomic(Path('/etc/ssh/sshd_config'), b'''Include /etc/ssh/sshd_config.d/*.conf
Port 2222
PermitRootLogin prohibit-password
AllowUsers root
PasswordAuthentication no
UsePAM yes
Subsystem sftp internal-sftp
''', 0o644)
    run(['ssh-keygen', '-A'], check=True)
    run(['systemctl', 'restart', 'ssh'], check=True)
    key = Path('/run/node-control-test')
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key], check=True)
    install.install_ssh(key.with_suffix('.pub').read_text(), ['11.77.0.2'])
    # Pins are copied from the test host's public key, never learned over an untrusted connection.
    hostkey = Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()[:2]
    known = Path('/run/node-test-known-hosts')
    known.write_text('[11.77.0.4]:2222 '+' '.join(hostkey)+'\n')
    ssh = ['ssh', '-F', '/dev/null', '-p', '2222', '-b', '11.77.0.2', '-i', key,
           '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
           '-o', 'UserKnownHostsFile='+str(known), '-o', 'GlobalKnownHostsFile=/dev/null',
           '-o', 'ConnectTimeout=3']
    target = install.CONTROL+'@11.77.0.4'
    reply = run(ssh+[target], input=b'{"action":"ping"}')
    check('pinned-key-rpc', reply.returncode == 0 and json.loads(reply.stdout).get('result', {}).get('schema') == 1)
    reply = run(ssh+[target, 'id'], input=b'{"action":"ping"}')
    check('remote-command-is-forced-rpc', reply.returncode == 0 and json.loads(reply.stdout).get('result', {}).get('schema') == 1)
    reply = run(ssh+[target, 'id'], input=b'id\n')
    check('shell-input-rejected', reply.returncode != 0 and b'uid=' not in reply.stdout)
    reply = run(ssh+['-W', '127.0.0.1:2222', target])
    check('tcp-forwarding-denied', reply.returncode != 0)
    reply = run(ssh+['-tt', target], input=b'{"action":"ping"}')
    check('pty-denied', b'PTY allocation request failed' in reply.stderr)
    reply = run(['runuser', '-u', install.CONTROL, '--', 'sudo', '-n', '/bin/sh', '-c', 'id'])
    check('sudo-shell-denied', reply.returncode != 0 and b'uid=' not in reply.stdout)
    reply = run(['runuser', '-u', install.CONTROL, '--', 'sudo', '-n', '/usr/bin/python3', '-I',
                 '/usr/local/lib/vpnbot-node/node_manager.py', 'rpc', 'extra'], input=b'{}')
    check('sudo-extra-argument-denied', reply.returncode != 0)
    reply = run(['runuser', '-u', install.CONTROL, '--', 'test', '-w', install.ETC/'controller.pub'])
    check('control-key-not-writable', reply.returncode != 0)
    reply = run(['runuser', '-u', install.CONTROL, '--', 'test', '-r', '/var/lib/vpnbot-node/current.json'])
    check('state-not-readable-by-control-user', reply.returncode != 0)
    before = run(['sshd', '-T', '-C', 'user=root,host=node,addr=11.77.0.2'], check=True).stdout
    check('root-access-policy-preserved', b'allowusers root' in before and b'forcecommand none' in before)
    # A second installation must remain usable and must not create duplicate global restrictions.
    install.install_ssh(key.with_suffix('.pub').read_text(), ['11.77.0.2'])
    reply = run(ssh+[target], input=b'{"action":"ping"}')
    check('ssh-setup-idempotent', reply.returncode == 0)
    wrong = Path('/run/node-wrong-key')
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', wrong], check=True)
    wrong_known = Path('/run/node-test-wrong-hosts')
    wrong_known.write_text('[11.77.0.4]:2222 '+' '.join(wrong.with_suffix('.pub').read_text().split()[:2])+'\n')
    bad_ssh = [str(x).replace(str(known), str(wrong_known)) for x in ssh]
    reply = run(bad_ssh+[target], input=b'{"action":"ping"}')
    check('changed-host-key-rejected', reply.returncode != 0 and not reply.stdout)
    reply = run(ssh+[target], input=b'{"action":"backup","path":"/etc/shadow"}')
    check('arbitrary-backup-path-rejected', reply.returncode != 0 and b'root:' not in reply.stdout)
    for name in install.units():
        check('unit-valid-'+name, run(['systemd-analyze', 'verify', '/etc/systemd/system/'+name]).returncode == 0)
    Path('/run/host-node-test.done').touch()
finally:
    Path('/run/host-node-results.json').write_text(json.dumps(results, indent=2))
    for path in Path('/run').glob('node-*test*'):
        if path.is_file():
            path.unlink()
