#!/usr/bin/env python3
"""Real password cover + VPN transports in the isolated Docker/systemd host."""
import base64
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import threading
import time
import shutil
import socket

if subprocess.run(['systemd-detect-virt', '--container'], capture_output=True).stdout.strip() != b'docker':
    raise SystemExit('Run only in the disposable Docker test host')
os.umask(0o077)
sys.path.insert(0, '/lab/scripts')
import node_config as config
import node_install as install
import node_manager as manager
import node_runtime as runtime
import node_state as state

NG = 'ghcr.io/axiomshiftbit/vpnbot-ng@sha256:d766744fec520b177c476e5b8731ca592de75ea6aee03575fd68a551f8f03197'
FAMILY = int(os.environ.get('NODE_COVER_FAMILY', '4'))
if FAMILY not in (4, 6):
    raise SystemExit('invalid fixture family')
results = []
work = Path(tempfile.mkdtemp(prefix='node-cover-', dir='/run'))
process = None
server = None


def run(args, **kwargs):
    return subprocess.run(list(map(str, args)), capture_output=True, timeout=45, **kwargs)


def check(label, ok):
    results.append({'case': label, 'ok': bool(ok)})
    print(('PASS ' if ok else 'FAIL ')+label, flush=True)
    if not ok:
        raise AssertionError(label)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', '15')
        self.end_headers()
        self.wfile.write(b'cover-vpn-pass!')

    def log_message(self, *_):
        pass


class Http6(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def web(path='/', password=None):
    # Authentication is fixture-only and never appears in argv or output.
    command = ['curl', '--noproxy', '*', '-sS', '--max-time', '5', '--cacert', work/'fullchain.pem',
               '--resolve', 'node.example.test:8443:'+('127.0.0.1' if FAMILY == 4 else '[::1]'), '-o', '/dev/null', '-w', '%{http_code}',
               '--config', '-', 'https://node.example.test:8443'+path]
    data = ('user = "admin:'+password+'"\n').encode() if password else b''
    result = run(command, input=data)
    return result.returncode, result.stdout.strip()


try:
    install.install_code('/lab/scripts')
    install.accounts()
    host = state.decode((install.ETC/'deployment.json').read_bytes())
    host.update(cover_uid=pwd.getpwnam(install.COVER).pw_uid, interface='lo')
    state.atomic(install.ETC/'deployment.json', state.encode(host))
    run(['ip', 'address', 'replace', '11.77.0.128/32', 'dev', 'lo'], check=True)
    if FAMILY == 6:
        for address in ('2606:4700:4700::1111', '2620:fe::fe'):
            run(['ip', '-6', 'address', 'replace', address+'/128', 'dev', 'lo', 'nodad'], check=True)
    store = state.Store('/var/lib/vpnbot-node')
    backend = runtime.Runtime(store, host)
    control = manager.Manager(store, backend)
    before = store.load()
    check('no-external-network', not run(['ip', 'route', 'show', 'default'], check=True).stdout.strip())
    names = 'DNS:node.example.test,'+','.join(f'DNS:padding-{i:03d}-abcdefghijklmnopqrstuvwxyz.example.test' for i in range(100))
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=node.example.test',
         '-addext', 'subjectAltName='+names, '-keyout', work/'privkey.pem', '-out', work/'fullchain.pem'], check=True)
    password = base64.urlsafe_b64encode(os.urandom(24)).decode()
    password_hash = run(['openssl', 'passwd', '-6', '-stdin'], input=(password+'\n').encode(), check=True).stdout.decode().strip()
    target = '11.77.0.128' if FAMILY == 4 else '2620:fe::fe'
    server = (ThreadingHTTPServer if FAMILY == 4 else Http6)((target, 18080), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    for transport in config.TRANSPORTS:
        if os.environ.get('NODE_COVER_TRANSPORT') and transport != os.environ['NODE_COVER_TRANSPORT']:
            continue
        value = copy.deepcopy(before)
        value['options'] = dict(transport=transport, family=FAMILY, connect_family=FAMILY, core='origin', cover=True,
                                domain='node.example.test', mask='node.example.test')
        if transport == 'reality' and os.environ.get('NODE_COVER_XVER'):
            value['options']['xray'] = {'reality': {'xver': int(os.environ['NODE_COVER_XVER'])}}
        value['images']['ng'] = NG
        value['identity']['cover_auth'] = password_hash
        value['tls'] = {name: base64.b64encode((work/name).read_bytes()).decode() for name in ('privkey.pem', 'fullchain.pem')}
        change = control.apply(value)
        check(transport+'-both-containers-running', backend.status()['running'])
        check(transport+'-unauthenticated-401', web() == (0, b'401'))
        check(transport+'-wrong-password-401', web(password='incorrect-fixture') == (0, b'401'))
        check(transport+'-correct-password-200', web(password=password) == (0, b'200'))
        for path in ('/.htpasswd', '/privkey.pem', '/xray.json'):
            check(transport+'-private-path-'+path.rsplit('/', 1)[-1], web(path, password)[1] == b'404')
        info = backend.container(runtime.COVER_CONTAINER)
        check(transport+'-cover-unprivileged', info['Config']['User'].startswith(str(host['cover_uid'])+':')
              and info['HostConfig']['ReadonlyRootfs'] and info['HostConfig']['CapDrop'] == ['ALL'])
        check(transport+'-cover-cannot-read-xray-key', run(['docker', 'exec', runtime.COVER_CONTAINER,
                'test', '-e', '/node/xray.json']).returncode != 0)
        check(transport+'-xray-has-no-cover-certificate-key', run(['docker', 'exec', runtime.CONTAINER,
                'test', '-e', '/node/privkey.pem']).returncode != 0)
        outbound = control.rpc({'action': 'profile', 'peer': None})['outbound']
        outbound['settings'].update(address='127.0.0.1' if FAMILY == 4 else '::1', port=8443)
        if transport != 'reality':
            outbound['streamSettings']['tlsSettings']['certificates'] = [{'usage': 'verify', 'certificateFile': str(work/'fullchain.pem')}]
        client = {'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1', 'port': 10871, 'protocol': 'socks'}], 'outbounds': [outbound]}
        client_file = work/'client.json'
        client_file.write_bytes(state.encode(client))
        process = subprocess.Popen(['/lab/x31', 'run', '-c', str(client_file)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   env={'PATH': '/usr/bin:/bin', 'GODEBUG': 'multipathtcp=0'})
        time.sleep(.5)
        result = run(['curl', '-sS', '--socks5-hostname', '127.0.0.1:10871', '--max-time', '5',
                      'http://'+(target if FAMILY == 4 else '['+target+']')+':18080/'])
        check(transport+'-vpn-through-own-cover', result.returncode == 0 and result.stdout == b'cover-vpn-pass!')
        process.terminate()
        process.wait(timeout=5)
        process = None
        store.confirm(change['pending']['nonce'])
        check(transport+'-confirmed-after-real-traffic', store.pending() is None)
    snapshot = control.rpc({'action': 'backup'})
    run(['systemctl', 'restart', 'vpnbot-node.service'], check=True)
    check('cover-restart-preserves-certificate-and-auth', control.rpc({'action': 'backup'}) == snapshot and web() == (0, b'401'))
    # Restore into an empty state directory: no old runtime mounts or generated
    # files may be required to recover authentication, TLS and transports.
    restored = state.Store(work/'restored')
    generation = restored.create(state.decode(state.encode(snapshot)))
    recovered = runtime.Runtime(restored, host, work/'restore-guard.nft')
    recovered.validate(generation)
    recovered.apply(generation)
    restored.activate(generation)
    check('clean-cover-backup-restore', restored.load() == snapshot and recovered.status()['running']
          and web() == (0, b'401') and web(password=password) == (0, b'200'))
    backend.apply(store.current())
    run(['docker', 'kill', runtime.COVER_CONTAINER], check=True)
    run(['systemctl', 'start', 'vpnbot-node-watch.service'], check=True)
    check('watchdog-recovers-cover-container', backend.status()['running'] and web() == (0, b'401'))
    broken = copy.deepcopy(snapshot)
    broken['tls']['privkey.pem'] = base64.b64encode(b'-----BEGIN PRIVATE KEY-----\nbroken\n').decode()
    pid = backend.container()['State']['Pid']
    try:
        control.apply(broken)
        rejected = False
    except Exception:
        rejected = True
    check('invalid-cover-restore-keeps-running-site', rejected and backend.container()['State']['Pid'] == pid
          and control.rpc({'action': 'backup'}) == snapshot and web() == (0, b'401'))
finally:
    if 'control' in locals() and store.pending():
        control.recover()
    if process:
        process.terminate()
        process.wait(timeout=5)
    if server:
        server.shutdown()
        server.server_close()
    Path('/run/node-cover-results.json').write_text(json.dumps(results, indent=2))
    shutil.rmtree(work)
