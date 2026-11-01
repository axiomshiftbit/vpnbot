#!/usr/bin/env python3
"""Real PHP -> pinned SSH -> systemd job -> Xray traffic -> confirmed backup.

Run on the test machine with an existing vpnbot-managed-node-lab container.
All links live in two disposable container namespaces; host firewall is untouched.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

os.umask(0o077)
lab = Path('/root/vpnbot-managed-node-lab')
outer, main = 'vpnbot-managed-node-lab', 'vpnbot-managed-main-fixture'
work = Path(tempfile.mkdtemp(prefix='main-fixture-', dir=lab))
prepared = False
server = None
server_log = None
watch_was_active = None
wg_block = False
removed_lo6 = []
hop = None

def run(args, **kwargs):
    return subprocess.run(list(map(str, args)), capture_output=True, timeout=60, **kwargs)

def inner(mode, **kwargs):
    return run(['docker', 'exec', '-i', outer, 'python3', '/lab/tests/integration/fixtures/managed-node-main-host.py', mode], **kwargs)

def step(action):
    result = run(['docker', 'exec', main, 'php', '/lab/tests/integration/fixtures/managed-node-main.php', action])
    # PHP fixture intentionally emits only named assertions.
    for line in result.stdout.decode().splitlines():
        if line.startswith(('PASS ', 'FAIL ', 'RETRY ')):
            print(line, flush=True)
    if result.returncode:
        raise RuntimeError('stage '+action)

def poll(action='poll', attempts=60):
    seen = set()
    for _ in range(attempts):
        result = run(['docker', 'exec', main, 'php', '/lab/tests/integration/fixtures/managed-node-main.php', action])
        if result.returncode == 2:
            for line in result.stdout.decode().splitlines():
                if line.startswith(('FAIL ', 'RETRY ')) and line not in seen:
                    print(line, flush=True)
                    seen.add(line)
            time.sleep(.5)
            continue
        for line in result.stdout.decode().splitlines():
            if line.startswith(('PASS ', 'FAIL ')):
                print(line, flush=True)
        if result.returncode:
            raise RuntimeError('poll')
        return
    state = run(['docker', 'exec', main, 'php', '-r', '$p=json_decode(file_get_contents("/work/pac.json"),true);$n=$p["managed_nodes"]["aabbccdd"];echo json_encode(["phase"=>$n["job"]["phase"]??null,"error"=>$n["error"]??null]);'])
    print('Controller test state '+state.stdout.decode(), flush=True)
    raise RuntimeError('poll timeout')

try:
    for part in ('ssh', 'work'):
        (work/part).mkdir(mode=0o700)
    run(['docker', 'run', '-d', '--name', main, '--network', 'none', '--memory', '256m', '--pids-limit', '128',
         '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--tmpfs', '/logs:mode=700',
         *(['--cap-add','CHOWN','--cap-add','SETUID','--cap-add','SETGID','--cap-add','KILL',
            '-v',f'{lab}/wireproxy-node:/usr/bin/wireproxy-node:ro'] if '--amnezia' in sys.argv else []),
         '-v', f'{lab}:/lab:ro', '-v', f'{work}/ssh:/ssh', '-v', f'{work}/work:/work',
         '--entrypoint', 'sleep', 'vpnbot-audit1031-php:final', '1800'], check=True)
    step('init')
    if '--amnezia' in sys.argv:
        run(['docker','exec','-d',main,'python3','-c',
             'import sys;from pathlib import Path;sys.path.insert(0,"/lab/scripts");import node_awg_client as m;m.CONFIG=Path("/work/core.json");m.main()'],check=True)
    node_pid = int(run(['docker', 'inspect', '-f', '{{.State.Pid}}', outer], check=True).stdout)
    main_pid = int(run(['docker', 'inspect', '-f', '{{.State.Pid}}', main], check=True).stdout)
    # Create and move the peer directly inside the disposable namespaces.
    if '--ssh6' in sys.argv:
        import managed_node_ssh_hop as hop
        hop.connect(main, node_pid)
    else:
        run(['nsenter', '-t', node_pid, '-n', 'ip', 'link', 'add', 'mn-node', 'type', 'veth', 'peer', 'name', 'mn-main'], check=True)
        run(['nsenter', '-t', node_pid, '-n', 'ip', 'link', 'set', 'mn-main', 'netns', main_pid], check=True)
    for pid, link, address, remote in ((node_pid, 'mn-node', '11.77.0.4', '11.77.0.3'),
                                      (main_pid, 'mn-main', '11.77.0.3', '11.77.0.4')):
        for args in (['link', 'set', link, 'up'], ['address', 'replace', address+'/32', 'dev', link],
                     ['route', 'replace', remote+'/32', 'dev', link]):
            run(['nsenter', '-t', pid, '-n', 'ip', *args], check=True)
    run(['nsenter', '-t', main_pid, '-n', 'ip', 'address', 'replace', '11.77.0.128/32', 'dev', 'mn-main'], check=True)
    if '--carrier6' in sys.argv or '--ssh6' in sys.argv:
        # Earlier isolated suites assigned these synthetic addresses to lo.
        # A leftover local route would swallow replies intended for the peer.
        for address in ('2606:4700:4700::1111', '2620:fe::fe'):
            if run(['nsenter', '-t', node_pid, '-n', 'ip', '-6', 'address', 'del', address+'/128', 'dev', 'lo']).returncode == 0:
                removed_lo6.append(address)
        for pid, link, address, remote in ((node_pid, 'mn-node', '2606:4700:4700::1111', '2620:fe::fe'),
                                          (main_pid, 'mn-main', '2620:fe::fe', '2606:4700:4700::1111')):
            if '--ssh6' in sys.argv and pid == main_pid:
                continue
            run(['nsenter', '-t', pid, '-n', 'ip', '-6', 'address', 'replace', address+'/128', 'dev', link, 'nodad'], check=True)
            run(['nsenter', '-t', pid, '-n', 'ip', '-6', 'route', 'replace', remote+'/128', 'dev', link], check=True)
    if '--ssh-edit' in sys.argv:
        run(['nsenter', '-t', main_pid, '-n', 'ip', 'route', 'replace', '11.77.0.2/32', 'dev', 'mn-main'], check=True)
    # The target is outside the node namespace, so the real WAN egress guard
    # remains in force. Previous fixture suites used this address on loopback.
    run(['nsenter', '-t', node_pid, '-n', 'ip', 'address', 'del', '11.77.0.128/32', 'dev', 'lo'], check=True)
    run(['nsenter', '-t', node_pid, '-n', 'ip', 'route', 'replace', '11.77.0.128/32', 'dev', 'mn-node'], check=True)
    pin = run(['docker', 'exec', outer, 'cat', '/etc/ssh/ssh_host_ed25519_key.pub'], check=True).stdout
    (work/'work/host.pub').write_bytes(b' '.join(pin.split()[:2]))
    prepared = True
    mode = 'prepare-amnezia' if '--amnezia' in sys.argv else 'prepare'
    if '--carrier6' in sys.argv:
        mode += '-ipv6'
    if '--ssh6' in sys.argv:
        mode = 'prepare-ssh6'
    inner(mode, input=(work/'work/controller.pub').read_bytes(), check=True)
    if hop:
        hop.start(work, main, node_pid)
    watch_was_active = run(['docker', 'exec', outer, 'systemctl', 'is-active', '--quiet', 'vpnbot-node-watch.timer']).returncode == 0
    run(['docker', 'exec', outer, 'systemctl', 'start', 'vpnbot-node-watch.timer'], check=True)
    server_log = (work/'http.log').open('wb')
    http_code = '''from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import TCPServer
from pathlib import Path
class FixtureServer(HTTPServer):
 def server_bind(self):
  TCPServer.server_bind(self)
  self.server_name='fixture';self.server_port=self.server_address[1]
class Probe(BaseHTTPRequestHandler):
 def do_GET(self):
  body=b'managed-main-pass\\n'
  self.send_response(200 if self.path=='/probe' else 404)
  self.send_header('Content-Length',str(len(body)))
  self.end_headers();self.wfile.write(body)
 def log_message(self,*args): pass
server=FixtureServer(('11.77.0.128',18089),Probe)
Path('/work/probe.ready').touch()
server.serve_forever()
'''
    def start_target():
        (work/'work/probe.ready').unlink(missing_ok=True)
        process = subprocess.Popen(['docker', 'exec', main, 'python3', '-c', http_code],
                                   stdout=subprocess.DEVNULL, stderr=server_log)
        # No reverse DNS in this isolated network. Wait for the actual listener.
        for _ in range(100):
            if (work/'work/probe.ready').exists():
                return process
            if process.poll() is not None:
                raise RuntimeError('HTTP fixture exited before listening')
            time.sleep(.1)
        raise RuntimeError('HTTP fixture did not start')
    server = start_target()
    if '--carrier6' in sys.argv:
        direct = run(['docker', 'exec', main, 'python3', '-c',
                      'import socket;socket.create_connection(("2606:4700:4700::1111",443),timeout=3).close()'])
        print(('PASS ' if direct.returncode == 0 else 'FAIL ')+'native IPv6 TCP listener reachable', flush=True)
    step('connect')
    if '--cold-restore' in sys.argv:
        if '--amnezia' in sys.argv:
            step('awg-enable')
            poll()
            step('awg-traffic')
        step('peer-add')
        poll()
        step('peer-export')
        step('backup')
        inner('reinstall', check=True)
        new_pin = run(['docker', 'exec', outer, 'cat', '/run/managed-main-fixture/new-host-key.pub'], check=True).stdout
        (work/'work/new-host.pub').write_bytes(b' '.join(new_pin.split()[:2]))
        step('cold-rebind')
        step('node-restore')
        poll()
        step('cold-restored')
    elif '--ssh6' in sys.argv:
        step('ssh6-edit')
        step('backup')
        step('restore')
        step('submit-restart')
        poll()
    elif '--ssh-edit' in sys.argv:
        step('ssh-edit')
        step('backup')
        step('restore')
    elif '--delete' in sys.argv:
        step('backup')
        step('delete')
        run(['docker', 'exec', outer, 'systemctl', 'is-active', '--quiet', 'vpnbot-node.service'], check=True)
        print('PASS removing controller leaves remote node running', flush=True)
        step('restore')
        step('vless-traffic')
    elif '--wireguard' in sys.argv or '--amnezia' in sys.argv:
        channel = 'awg' if '--amnezia' in sys.argv else 'wg'
        step(channel+'-enable')
        poll()
        # Independent DROP survives node guard replacements. SSH and HTTP
        # target remain reachable, while the old VLESS transport cannot pass.
        run(['docker', 'exec', '-i', outer, 'nft', '-f', '-'], input=b'table inet node_fixture_vless_block {\n chain input {\n type filter hook input priority -30; policy accept;\n tcp dport 8443 ct original proto-dst 443 drop\n }\n}\n', check=True)
        wg_block = True
        denied = run(['docker', 'exec', main, 'python3', '-c', 'import socket;socket.create_connection(("11.77.0.4",443),timeout=.5)'])
        if denied.returncode == 0: raise RuntimeError('VLESS block fixture failed')
        print('PASS VLESS port actually blocked', flush=True)
        step(channel+'-traffic')
        step('backup')
        step('restore')
        step('node-restore')
        poll()
        step(channel+'-traffic')
        step(channel+'-rotate')
        poll()
        step(channel+'-traffic')
        step('submit-restart')
        poll()
        step(channel+'-traffic')
        run(['docker', 'exec', outer, 'nft', 'delete', 'table', 'inet', 'node_fixture_vless_block'], check=True)
        wg_block = False
        step(channel+'-disable')
        poll()
        step('vless-traffic')
    elif '--peers' in sys.argv:
        step('peer-add')
        poll()
        step('peer-export')
        step('backup')
        step('peer-off')
        poll()
        step('peer-revoked')
        step('restore')
        step('node-restore')
        poll()
        step('peer-export')
        step('peer-rotate')
        poll()
        step('peer-revoked')
        step('peer-export')
        step('peer-delete')
        poll()
        step('peer-revoked')
    else:
        step('configure')
        poll()
        step('backup')
        step('restore')
        step('node-restore')
        poll()
        run(['docker', 'exec', outer, 'systemctl', 'restart', 'vpnbot-node.service'], check=True)
        step('restart')
        # Restore a main backup whose saved job has since been replaced remotely.
        step('rotate')
        step('backup')
        poll()
        step('submit-restart')
        poll()
        step('restore')
        poll()
        # The target really goes down: no mocked probe result and no forced clock.
        step('rotate')
        run(['docker', 'exec', main, 'pkill', '-f', '^python3 -c from http.server import'], check=True)
        server.wait(timeout=10)
        poll('await-rollback')
        server = start_target()
        poll('rolled-back', attempts=240)
except Exception:
    import traceback
    frames = traceback.extract_tb(sys.exc_info()[2])
    location = next((frame.lineno for frame in reversed(frames) if frame.filename == __file__), 0)
    print('FAIL native main orchestration at fixture line '+str(location)+' (private diagnostics suppressed)', flush=True)
    if (work/'work/last-request.json').exists() and run(['docker', 'cp', work/'work/last-request.json', outer+':/run/managed-main-fixture/replay.json']).returncode == 0:
        replay = run(['docker', 'exec', '-i', outer, 'python3', '-'], input=b'''
import fcntl,os,sys,traceback
from pathlib import Path
sys.path.insert(0,'/lab/scripts')
import node_state as state,node_manager as manager,node_runtime as runtime
store=state.Store('/var/lib/vpnbot-node')
fd=os.open(store.root/'lock',os.O_RDWR)
fcntl.flock(fd,fcntl.LOCK_EX)
job=store.read('job.json') or {}
print('Diagnostic worker state',job.get('state','absent'))
print('Diagnostic node pending',bool(store.pending()))
request=state.decode(Path('/run/managed-main-fixture/replay.json').read_bytes())
print('Diagnostic request generation current',request.get('generation')==store.current())
if job.get('state')=='failed' and not store.pending():
 host=state.decode(Path('/etc/vpnbot-node/deployment.json').read_bytes())
 try:
  manager.Manager(store,runtime.Runtime(store,host)).execute(request)
  print('Diagnostic replay succeeded')
 except Exception as error:
  print('Diagnostic replay exception',type(error).__name__)
  for frame in traceback.extract_tb(error.__traceback__):
   if '/lab/' in frame.filename:print('Diagnostic frame',Path(frame.filename).name,frame.lineno)
''')
        print(replay.stdout.decode(), flush=True)
    diagnostic = run(['docker', 'exec', '-i', main, 'python3', '-'], input=b'''
import sys,subprocess
from pathlib import Path
sys.path.insert(0,'/lab/app')
import node_ssh
client=node_ssh.Client('aabbccdd')
target=dict(address='11.77.0.4',port=2222,host_key=Path('/work/host.pub').read_text().strip())
try:
 r=subprocess.run(client.ssh(target),input=b'{"action":"ping"}',capture_output=True,timeout=15)
 print('SSH diagnostic status',r.returncode)
 for category in (b'setgroups',b'Connection refused',b'Permission denied',b'Host key verification',b'Connection timed out',b'No route to host',b'setresgid',b'Operation not permitted',b'reset',b'closed',b'no matching',b'Bad',b'not found',b'unknown',b'libcrypto',b'missing',b'unprotected',b'hostname',b'timed',b'authentication'):
  if category.lower() in r.stderr.lower(): print('SSH category',category.decode())
 print('RPC envelope accepted',b'"ok":true' in r.stdout.replace(b' ',b''))
 r=subprocess.run(client.ssh(target),input=b'{"action":"backup"}',capture_output=True,timeout=15)
 print('Backup SSH status and bytes',r.returncode,len(r.stdout))
 response=node_ssh.decode(r.stdout)
 print('Backup RPC accepted',response.get('ok') is True)
 try:
  snapshot=client.request({'action':'backup'},target)
  node_ssh.atomic(client.directory/'snapshot.json',node_ssh.encode(snapshot))
  print('Snapshot retry saved',True)
 except Exception as error:
  import traceback
  print('Snapshot retry class',type(error).__name__)
  for frame in traceback.extract_tb(error.__traceback__):
   if '/lab/' in frame.filename: print('Snapshot location',Path(frame.filename).name,frame.lineno)
except Exception as error: print('SSH diagnostic class',type(error).__name__)
''')
    print(diagnostic.stdout.decode(), flush=True)
    network = run(['docker', 'exec', '-i', outer, 'python3', '-'], input=b'''
import subprocess,os,socket
from pathlib import Path
def fetch():
 try:
  with socket.create_connection(('11.77.0.128',18089),timeout=3) as s:
   s.sendall(b'GET /probe HTTP/1.0\\r\\nHost: fixture\\r\\n\\r\\n')
   data=b''
   while True:
    part=s.recv(4096)
    if not part:break
    data+=part
   return b'managed-main-pass' in data
 except Exception as error:
  print('HTTP fetch failure',type(error).__name__)
  return False
print('HTTP target reachable from node root',fetch())
import pwd
uid=pwd.getpwnam('vpnbot-core').pw_uid
os.setgroups([]);os.setgid(uid);os.setuid(uid)
print('HTTP target reachable from node core UID',fetch())
''')
    print(network.stdout.decode(), flush=True)
    for container in (outer, main):
        addresses = run(['docker', 'exec', container, 'ip', '-4', '-brief', 'address'])
        print(container+' fixture addresses:',addresses.stdout.decode(),flush=True)
    node_log = run(['docker', 'exec', outer, 'docker', 'logs', 'vpnbot-node-xray'])
    import re
    for line in (node_log.stdout+node_log.stderr).decode(errors='replace').splitlines():
        if any(term in line for term in ('proxy/freedom', 'failed', 'rejected')) and not re.search('key|password|uuid|private',line,re.I):
            line=re.sub(r'[A-Za-z0-9_+/=-]{30,}', '[redacted]', line)
            print('Node diagnostic:',line[:300],flush=True)
    if server_log:
        server_log.flush()
        log = (work/'http.log').read_text(errors='replace')
        for category in ('RuntimeError', 'PermissionError', 'FileNotFoundError', 'OSError', 'BrokenPipeError',
                         "can't start new thread", 'Resource temporarily unavailable', 'NotImplementedError'):
            if category in log:
                print('HTTP server diagnostic category', category, flush=True)
        import re
        print('HTTP server exception classes', sorted(set(re.findall(r'\b[A-Z][A-Za-z]{1,40}(?:Error|Exception)\b', log))), flush=True)
        print('HTTP fixture running', server.poll() is None, flush=True)
        # This process serves a fixed public test string and has no credential
        # input; its startup diagnostics cannot contain node identities.
        print('HTTP fixture startup diagnostic:', log[:2000], flush=True)
        processes = run(['docker', 'exec', main, 'ps', '-o', 'pid,comm'])
        print(processes.stdout.decode(), flush=True)
    logfile = work/'work/client.log'
    if logfile.is_file():
        log = logfile.read_text(errors='replace').lower()
        for category in ('failed to connect', 'connection refused', 'failed to process', 'reality verification',
                         'certificate', 'network is unreachable', 'connection reset', 'eof', 'timeout',
                         'proxy/vless/outbound', 'app/dispatcher', 'invalid user', 'invalid connection',
                         'permission denied', 'cannot assign', 'too many', 'out of memory',
                         'address already', 'resource temporarily unavailable', 'wireguard', 'panic', 'failed to start'):
            if category in log:
                print('Client diagnostic category', category, flush=True)
    sys.exit(1)
finally:
    if wg_block:
        run(['docker', 'exec', outer, 'nft', 'delete', 'table', 'inet', 'node_fixture_vless_block'])
    if server:
        run(['docker', 'exec', main, 'pkill', '-f', '^python3 -c from http.server import'])
        server.wait(timeout=10)
    if server_log:
        server_log.close()
    if hop:
        hop.stop()
    run(['docker', 'rm', '-f', main])
    if watch_was_active is False:
        run(['docker', 'exec', outer, 'systemctl', 'stop', 'vpnbot-node-watch.timer'])
    for address in removed_lo6:
        run(['docker', 'exec', outer, 'ip', '-6', 'address', 'replace', address+'/128', 'dev', 'lo', 'nodad'])
    if prepared:
        restored = inner('restore')
        print(('PASS' if restored.returncode == 0 else 'FAIL')+' original disposable node restored', flush=True)
    run(['docker', 'exec', outer, 'ip', 'link', 'del', 'mn-node'])
    run(['docker', 'exec', outer, 'ip', 'address', 'replace', '11.77.0.128/32', 'dev', 'lo'])
    shutil.rmtree(work)
