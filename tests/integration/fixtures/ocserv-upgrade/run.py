"""Новый ocserv: TLS/DTLS, rekey, строгие конфиги и завершение процесса.

run.py IMAGE CLIENT_IMAGE RESULTS_DIRECTORY
Только собственные контейнеры, сеть и одноразовые данные.
"""
from pathlib import Path
import json, os, secrets, subprocess, sys, time
IMAGE, CLIENT_IMAGE, OUTPUT = sys.argv[1:]
OUT = Path(OUTPUT).resolve(); OUT.mkdir(parents=True, exist_ok=True, mode=0o700)
os.umask(0o077)
NET = 'vpnbot-ocserv-upgrade'; SERVER = NET + '-server'; CLIENT = NET + '-client'
SERVER_IP, CLIENT_IP = '198.51.100.3', '198.51.100.2'
TARGET_IP = '198.51.100.4'  # Separate destination: vpnc excludes the VPN endpoint from tunnel routes.
rows = []; owned = []; network = False
password = secrets.token_urlsafe(24)

def run(*args, timeout=45, **kw):
    return subprocess.run(list(map(str, args)), capture_output=True, timeout=timeout, **kw)

def need(*args, **kw):
    result = run(*args, **kw)
    if result.returncode:
        (OUT / 'command-error.log').write_bytes(result.stdout + result.stderr)
        raise RuntimeError('probe command failed: ' + str(args[0]))
    return result.stdout

def check(name, ok):
    rows.append({'name': name, 'passed': bool(ok)})
    (OUT / 'results.json').write_text(json.dumps(rows, indent=2))
    print(('PASS ' if ok else 'FAIL ') + name, flush=True)
    if not ok: raise RuntimeError(name)

def stop_client():
    run('docker', 'exec', CLIENT, 'pkill', 'openconnect'); time.sleep(.3)

def connect(label, *, dtls=False, valid_password=True):
    stop_client()
    args = ['openconnect', 'https://upgrade.example.test', '--resolve=upgrade.example.test:'+SERVER_IP,
            '--user=upgrade', '--passwd-on-stdin', '--non-inter', '--cafile=/probe/cert.pem',
            '--background', '--interface=upgradetun', '--script=/etc/vpnc/vpnc-script', '--verbose']
    if not dtls: args.append('--no-dtls')
    import shlex
    command = shlex.join(args) + ' >/tmp/upgrade-client.log 2>&1'
    r = run('docker', 'exec', '-i', CLIENT, 'sh', '-c', command,
            input=((password if valid_password else 'wrong')+'\n').encode(), timeout=25)
    (OUT / (label+'.log')).write_bytes(need('docker', 'exec', CLIENT, 'cat', '/tmp/upgrade-client.log'))
    return r.returncode == 0

def traffic():
    r = run('docker', 'exec', CLIENT, 'curl', '--noproxy', '*', '--interface', 'upgradetun',
            '--max-time', '4', '-fsS', 'http://'+TARGET_IP+':8080/')
    if r.returncode:
        (OUT/'traffic-error.log').write_bytes(r.stdout+r.stderr)
        (OUT/'client-routes.log').write_bytes(need('docker','exec',CLIENT,'ip','route'))
        (OUT/'server-sockets.log').write_bytes(need('nsenter','-t',pid,'-n','ss','-ltn'))
    return r.returncode == 0 and r.stdout == b'ocserv-upgrade-traffic\n'

def start_server():
    need('docker', 'start', SERVER)
    for _ in range(100):
        r = run('docker', 'exec', SERVER, 'occtl', 'show', 'status')
        if r.returncode == 0: return
        time.sleep(.1)
    raise RuntimeError('ocserv not ready')

def stop_server(label):
    need('docker', 'stop', '--time', '15', SERVER)
    state = json.loads(need('docker', 'inspect', '--format', '{{json .State}}', SERVER))
    check(label+'-no-segfault-or-forced-kill', state['ExitCode'] == 0 and not state['OOMKilled'])

try:
    if run('docker', 'network', 'inspect', NET).returncode == 0: raise RuntimeError('network already exists')
    need('docker', 'network', 'create', '--internal', '--subnet', '198.51.100.0/24', NET); network = True
    need('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
         '-keyout', OUT/'key.pem', '-out', OUT/'cert.pem', '-subj', '/CN=upgrade.example.test',
         '-addext', 'subjectAltName=DNS:upgrade.example.test')
    (OUT/'users').mkdir(exist_ok=True); (OUT/'users/upgrade').write_text('route = 198.51.100.4/32\n')
    conf = '''auth = "plain[passwd=/probe/passwd]"
tcp-port = 443
udp-port = 443
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket
use-occtl = true
server-cert = /probe/cert.pem
server-key = /probe/key.pem
isolate-workers = true
max-clients = 16
max-same-clients = 4
keepalive = 10
dpd = 10
mobile-dpd = 10
rekey-time = 10
rekey-method = ssl
cookie-timeout = 300
device = vpnupgrade
ipv4-network = 10.73.0.0
ipv4-netmask = 255.255.255.0
dns = 198.51.100.4
route = 198.51.100.4/32
config-per-user = /probe/users
'''
    (OUT/'ocserv.conf').write_text(conf)
    need('docker', 'run', '--rm', '--network', 'none', '-i', '--entrypoint', 'ocpasswd',
         '-v', f'{OUT}:/probe', IMAGE, '-c', '/probe/passwd', 'upgrade', input=(password+'\n'+password+'\n').encode())
    need('docker', 'create', '--name', SERVER, '--network', NET, '--ip', SERVER_IP,
         '--cap-add=NET_ADMIN', '--device=/dev/net/tun', '--entrypoint', 'ocserv',
         '-v', f'{OUT}:/probe:ro', IMAGE, '-f', '-d', '3', '-c', '/probe/ocserv.conf'); owned.append(SERVER)
    need('docker', 'run', '-d', '--name', CLIENT, '--network', NET, '--ip', CLIENT_IP,
         '--cap-add=NET_ADMIN', '--device=/dev/net/tun', '-v', f'{OUT}:/probe:ro', CLIENT_IMAGE); owned.append(CLIENT)
    start_server()
    pid = need('docker','inspect','--format','{{.State.Pid}}',SERVER).decode().strip()
    need('nsenter','-t',pid,'-n','ip','addr','add',TARGET_IP+'/32','dev','lo')
    # HTTP echo shares the server network: client traffic must cross its TUN.
    (OUT/'echo_server.py').write_text('''from http.server import BaseHTTPRequestHandler,HTTPServer
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(b'ocserv-upgrade-traffic\\n')
 def log_message(self,*a): pass
HTTPServer(('0.0.0.0',8080),H).serve_forever()
''')
    echo = NET+'-echo'
    need('docker', 'run', '-d', '--name', echo, '--network', 'container:'+SERVER,
         '-v', f'{OUT}:/probe:ro', '--entrypoint', 'python3', CLIENT_IMAGE, '/probe/echo_server.py'); owned.append(echo)
    check('wrong-password-rejected', not connect('wrong', valid_password=False))
    check('TLS-profile-accepted', connect('tls'))
    check('TLS-traffic', traffic())
    deadline = time.monotonic()+50  # ocserv's periodic check runs every 30 s.
    updated = False
    while time.monotonic() < deadline:
        time.sleep(3)
        logs = run('docker', 'logs', SERVER)
        if b'TLS 1.3 session keys refreshed (rekey)' in logs.stdout + logs.stderr:
            updated = True; break
    check('TLS13-KeyUpdate-observed', updated)
    check('TLS-traffic-after-rekey', traffic())
    stop_client()
    check('DTLS-profile-accepted', connect('dtls', dtls=True)); time.sleep(1)
    log = need('docker','exec',CLIENT,'cat','/tmp/upgrade-client.log')
    check('DTLS-channel-established', b'Established DTLS connection' in log)
    check('DTLS-traffic', traffic()); stop_client()
    (OUT/'users/upgrade').write_text('[unterminated-section\n')
    check('malformed-user-config-rejected', not connect('malformed-user'))
    (OUT/'users/upgrade').write_text('route = 198.51.100.4/32\n')
    check('fixed-user-config-recovers', connect('fixed-user')); stop_client()
    stop_server('first-stop')
    (OUT/'users/upgrade').unlink()
    (OUT/'ocserv.conf').write_text(conf+'default-user-config = /probe/missing-default.conf\n')
    start_server(); check('missing-default-config-rejected', not connect('missing-default'))
    stop_server('second-stop')
    (OUT/'users/upgrade').write_text('route = 198.51.100.4/32\n')
    (OUT/'ocserv.conf').write_text(conf)
    start_server(); check('restart-keeps-profile-working', connect('restart')); stop_client()
    stop_server('final-stop')
finally:
    if NET+'-echo' in owned:
        logs = run('docker','logs',NET+'-echo'); (OUT/'echo.log').write_bytes(logs.stdout+logs.stderr)
    if SERVER in owned:
        logs = run('docker','logs',SERVER); (OUT/'server.log').write_bytes(logs.stdout+logs.stderr)
    for name in reversed(owned): need('docker', 'rm', '-f', name)
    if network: need('docker','network','rm',NET)
    for name in ('key.pem','passwd'): (OUT/name).unlink(missing_ok=True)
print(json.dumps({'passed': sum(row['passed'] for row in rows), 'total':len(rows)}))
