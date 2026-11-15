#!/usr/bin/env python3
"""Disposable container only: install a managed node like node_setup does, synthetic data."""
import base64, json, os, pwd, subprocess, sys
from pathlib import Path
if subprocess.run(['systemd-detect-virt', '--container'], capture_output=True).stdout.strip() != b'docker':
    raise SystemExit('disposable container required')
os.umask(0o077)
sys.path.insert(0, '/lab/scripts'); sys.path.insert(0, '/lab/tests')
import node_install as install, node_runtime as runtime, node_state as state, node_upgrade
from node_config_test import HOST
def run(args, **kw):
    r = subprocess.run(list(map(str, args)), capture_output=True, timeout=900, **kw)
    if r.returncode: raise RuntimeError('failed: '+' '.join(map(str, args[:3]))+'')
    return r
bundle = json.loads(Path('/lab/bundle.json').read_text())
XR, NG = bundle['images']['xr'], bundle['images']['ng']
Path('/etc/nftables.conf').unlink(missing_ok=True)
run(['ssh-keygen', '-A'])
Path('/etc/ssh/sshd_config.d/10-lab-port.conf').write_text('Port 2222\n')
run(['systemctl', 'enable', '--now', 'ssh.service'])
for image in (XR, NG): run(['docker', 'image', 'inspect', image])
install.install_code('/lab/scripts')
node_upgrade.record(Path('/var/lib/vpnbot-node'), Path('/lab/scripts'), True)
account = install.accounts()
host = HOST | {'uid': account.pw_uid, 'gid': account.pw_gid, 'cover_uid': pwd.getpwnam(install.COVER).pw_uid,
               'awg_uid': pwd.getpwnam(install.AWG).pw_uid, 'ssh_ports': [2222], 'sources': ['11.77.0.3'], 'admins': ['11.77.0.3']}
state.atomic(install.ETC/'deployment.json', state.encode(host))
work = Path('/run/lab-bootstrap'); work.mkdir(mode=0o700, exist_ok=True)
run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', work/'controller'])
install.install_ssh((work/'controller.pub').read_text().strip(), host['sources'])
store = state.Store('/var/lib/vpnbot-node')
state.atomic(store.root/'release.json', json.dumps(bundle).encode())
backend = runtime.Runtime(store, host)
run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=node.example.test',
     '-addext', 'subjectAltName=DNS:node.example.test', '-keyout', work/'privkey.pem', '-out', work/'fullchain.pem'])
value = dict(schema=1, options=dict(transport='ws', family=4, core='origin', domain='node.example.test', mask='mask.example.test', cover=True),
             identity=backend.identity(XR), peers=[], images={'xr': XR, 'ng': NG},
             tls={name: base64.b64encode((work/name).read_bytes()).decode() for name in ('privkey.pem', 'fullchain.pem')})
backend.ensure_keys(value)
initial = store.create(value); backend.validate(initial); store.activate(initial)
run(['systemctl', 'enable', '--now', 'vpnbot-node.service', 'vpnbot-node-watch.timer'])
run(['ip', 'address', 'replace', '11.77.0.128/32', 'dev', 'lo'])
print('BOOTSTRAP OK', backend.container()['State']['Running'])
