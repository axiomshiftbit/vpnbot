#!/usr/bin/env python3
"""Real Certbot/Pebble HTTP-01, renewal and closed firewall windows.

Run only in a disposable container with NET_ADMIN/SYS_ADMIN and no network.
Pebble is a test CA; its certificates and account never leave the container.
"""
import base64
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

if not Path('/.dockerenv').exists() or os.geteuid() != 0:
    raise SystemExit('Disposable root container required')
os.umask(0o077)
sys.path.insert(0, '/lab/scripts')
import node_config as config
import node_runtime as runtime
import node_state as state

root = Path(tempfile.mkdtemp(prefix='node-acme-', dir='/run'))
processes = []
original_hosts = Path('/etc/hosts').read_bytes()
real_command = runtime.command
checks, issues = 0, 0

def run(args, **kwargs):
    return subprocess.run(list(map(str,args)), capture_output=True, timeout=120, **kwargs)

def check(name, ok):
    global checks
    print(('PASS ' if ok else 'FAIL ')+name, flush=True)
    if not ok: raise RuntimeError(name)
    checks += 1

def window_closed():
    sets = json.loads(run(['nft','-j','list','set','inet','vpnbot_node','acme_http'],check=True).stdout)
    return not any(item.get('set',{}).get('elem') for item in sets['nftables'])

def command(args, **kwargs):
    global issues
    if args[0] != 'certbot': return real_command(args, **kwargs)
    if args[1] == 'delete':
        return real_command(args, **kwargs)
    issues += 1
    check('ACME window open only inside certificate operation', not window_closed())
    # Only the CA URL/trust root differ from production. The actual Certbot
    # command, standalone challenge listener and nft transaction are retained.
    result = run([*args, '--server', 'https://11.77.0.200:14000/dir'],
                 env=os.environ | {'REQUESTS_CA_BUNDLE': str(root/'ca.pem')})
    if result.returncode:
        text=(result.stdout+result.stderr).decode(errors='replace').lower()
        private_logs = root/'state/acme/logs'
        for logfile in private_logs.glob('letsencrypt.log*'):
            text += logfile.read_text(errors='replace').lower()
        text += (root/'pebble.log').read_text(errors='replace').lower()
        for category in ('connection refused', 'network is unreachable', 'no route to host', 'timeout',
                         'address family not supported', 'cannot assign requested', 'address already in use',
                         'could not bind', 'no valid ip', 'nxdomain', 'unauthorized', 'certificate', 'failed', 'renew'):
            if category in text: print('Certbot failure category '+category, flush=True)
        print('ACME input IPv6 packets',run(['nft','list','chain','inet','acme_observe','input'],check=True).stdout.decode().split('packets ')[-1].split(' bytes')[0],flush=True)
        raise RuntimeError('Certbot failed; private diagnostics suppressed')
    return result

def verify(tls, domain):
    folder=root/'export';folder.mkdir(exist_ok=True,mode=0o700)
    for name,value in tls.items(): state.atomic(folder/name,base64.b64decode(value))
    backend.check_certificate(folder,domain)
    return run(['openssl','x509','-in',folder/'fullchain.pem','-serial','-noout'],check=True).stdout

try:
    # Go caches /etc/hosts. Install every fixture name before the CA starts,
    # so a later case cannot accidentally fall back to the isolated DNS path.
    Path('/etc/hosts').write_bytes(original_hosts+b'\n11.77.0.4 node-a.example.test node-b.example.test blocked.example.test\n2606:4700:4700::4 node6.example.test\n11.77.0.201 wrong.example.test\n')
    run(['ip','link','set','lo','up'],check=True)
    peer=subprocess.Popen(['unshare','-n','sleep','600']);processes.append(peer);time.sleep(.2)
    run(['ip','link','add','eth0','type','veth','peer','name','acme-peer'],check=True)
    run(['ip','link','set','acme-peer','netns',peer.pid],check=True)
    peer_args=['nsenter','-t',str(peer.pid),'-n']
    for prefix,interface,addresses in [([], 'eth0', ['11.77.0.4/24','2606:4700:4700::4/64']),
                                      (peer_args,'acme-peer',['11.77.0.200/24','2606:4700:4700::200/64'])]:
        run(prefix+['ip','link','set','lo','up'],check=True)
        run(prefix+['ip','link','set',interface,'up'],check=True)
        for address in addresses:
            run(prefix+['ip','address','add',address,'dev',interface]+(['nodad'] if ':' in address else []),check=True)
    run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','7','-subj','/CN=ACME Fixture',
         '-addext','subjectAltName=IP:11.77.0.200','-keyout',root/'ca.key','-out',root/'ca.pem'],check=True)
    settings={'pebble': {'listenAddress':'11.77.0.200:14000','managementListenAddress':'11.77.0.200:15000',
              'certificate':str(root/'ca.pem'),'privateKey':str(root/'ca.key'),'httpPort':80,'tlsPort':443,
              'profiles':{'default':{'validityPeriod':7776000}}}}
    (root/'pebble.json').write_text(json.dumps(settings))
    log=(root/'pebble.log').open('wb')
    ca=subprocess.Popen(peer_args+['pebble','-config',str(root/'pebble.json')], stdout=log,stderr=log,
                        env=os.environ | {'PEBBLE_VA_NOSLEEP':'1','PEBBLE_WFE_NONCEREJECT':'0','PEBBLE_AUTHZREUSE':'0'})
    processes.append(ca)
    for _ in range(100):
        try:
            with socket.create_connection(('11.77.0.200',14000),timeout=.1): break
        except OSError: time.sleep(.1)
    else: raise RuntimeError('Test CA did not start')
    host=dict(public4='11.77.0.4',public6='2606:4700:4700::4',sources=['11.77.0.2'],admins=['11.77.0.2'],
              routers=[],ssh_ports=[2222],interface='eth0',uid=995,gid=995)
    options=dict(transport='ws',core='origin',family=4,domain='node-a.example.test',mask='mask.example.test')
    run(['nft','-f','-'],input=config.firewall(options,host).encode(),check=True)
    run(['nft','-f','-'],input=b'table inet acme_observe {\n chain input {\n type filter hook input priority -25; policy accept;\n meta nfproto ipv6 tcp dport 8080 counter\n }\n}\n',check=True)
    backend=runtime.Runtime(state.Store(root/'state'),host)
    runtime.command=command
    check('ACME window initially closed',window_closed())
    tls=backend.certificate('node-a.example.test')
    first=verify(tls,'node-a.example.test')
    check('actual HTTP-01 issuance over IPv4',bool(first))
    check('ACME window closed after issuance',window_closed())
    same=backend.certificate('node-a.example.test')
    check('unexpired certificate reused',verify(same,'node-a.example.test')==first)
    check('ACME window closed after reuse',window_closed())
    forced=backend.certificate('node-a.example.test',force=True)
    check('forced issuance replaces unexpired certificate',verify(forced,'node-a.example.test')!=first)
    check('ACME window closed after forced issuance',window_closed())
    renewal=root/'state/acme/config/renewal/vpnbot-node.conf'
    renewal.write_text('renew_before_expiry = 100 days\n'+renewal.read_text())
    renewed=backend.certificate('node-a.example.test')
    check('due certificate renewed through actual ACME',verify(renewed,'node-a.example.test')!=first)
    check('ACME window closed after renewal',window_closed())
    # Both names are deliberately resolved to the same real local address.
    changed=backend.certificate('node-b.example.test')
    check('domain change accepted noninteractively',bool(verify(changed,'node-b.example.test')))
    check('ACME window closed after domain change',window_closed())
    check('test CA has IPv6 route to node',run(peer_args+['ip','-6','route','get','2606:4700:4700::4']).returncode==0)
    ipv6=backend.certificate('node6.example.test')
    check('actual HTTP-01 issuance over IPv6',bool(verify(ipv6,'node6.example.test')))
    check('ACME window closed after IPv6 issuance',window_closed())
    run(peer_args+['nft','-f','-'],input=b'table inet acme_fail {\n chain output {\n type filter hook output priority -50; policy accept;\n tcp dport 80 drop\n }\n}\n',check=True)
    try:
        backend.certificate('blocked.example.test')
    except RuntimeError:
        check('unreachable HTTP challenge rejected',True)
    else: check('unreachable HTTP challenge rejected',False)
    check('ACME window closed after failed validation',window_closed())
    live=root/'state/acme/config/live/vpnbot-node/fullchain.pem'
    check('failed issuance preserves previous certificate',run(['openssl','x509','-in',live,'-checkhost','node6.example.test','-noout'],check=True).stdout.endswith(b'does match certificate\n'))
    before=issues
    try: backend.certificate('wrong.example.test')
    except ValueError: check('foreign DNS rejected before ACME',issues==before and window_closed())
    else: check('foreign DNS rejected before ACME',False)
    backend.delete_certificate()
    check('Certbot registration deleted',not renewal.exists() and not live.exists())
    check('delete never opens ACME window',window_closed())
    print(f'PASS {checks} real ACME checks',flush=True)
finally:
    runtime.command=real_command
    Path('/etc/hosts').write_bytes(original_hosts)
    for process in reversed(processes):
        process.terminate();process.wait(timeout=10)
    shutil.rmtree(root)
