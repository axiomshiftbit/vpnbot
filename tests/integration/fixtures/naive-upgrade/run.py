"""Изолированный Naive: HTTP/2, HTTP/3, idle CONNECT и отказ без авторизации.

run.py IMAGE PHP_IMAGE NAIVE_CLIENT RESULTS_DIRECTORY
Только синтетический сертификат и своя сеть, без конфигурации установки.
"""
from pathlib import Path
import json, os, socket, ssl, struct, subprocess, sys, time

IMAGE, PHP, CLIENT, OUTPUT = sys.argv[1:]
OUT = Path(OUTPUT).resolve(); OUT.mkdir(parents=True, exist_ok=True, mode=0o700)
os.umask(0o077)
NET = 'vpnbot-naive-upgrade'
SERVER, TARGET = NET + '-server', NET + '-target'
ADDRESS, DEST = '198.51.100.3', '198.51.100.2'
rows = []; owned = []; network = False

def run(*args, timeout=60, **kw):
    return subprocess.run(list(map(str, args)), capture_output=True, timeout=timeout, **kw)

def need(*args):
    result = run(*args)
    if result.returncode:
        (OUT / 'command-error.log').write_bytes(result.stdout + result.stderr)
        raise RuntimeError('probe command failed: ' + str(args[0]))
    return result.stdout

def check(name, ok):
    rows.append({'name': name, 'passed': bool(ok)})
    (OUT / 'results.json').write_text(json.dumps(rows, indent=2))
    print(('PASS ' if ok else 'FAIL ') + name, flush=True)
    if not ok: raise RuntimeError(name)

def exact(sock, size):
    result = b''
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk: raise EOFError('closed tunnel')
        result += chunk
    return result

def socks(port, destination=DEST):
    sock = socket.create_connection(('127.0.0.1', port), timeout=5)
    try:
        sock.sendall(b'\x05\x01\x00')
        if exact(sock, 2) != b'\x05\x00': raise RuntimeError('SOCKS negotiation')
        sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(destination) + struct.pack('!H', 80))
        reply = exact(sock, 4)
        if reply[1]: raise OSError('CONNECT refused')
        exact(sock, 6 if reply[3] == 1 else 18)
        return sock
    except BaseException:
        sock.close(); raise

def probe(protocol, password='upgrade-password', trusted=True):
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]
    config = OUT / 'client.json'
    config.write_text(json.dumps({'listen': f'socks://127.0.0.1:{port}',
        'proxy': f'{protocol}://upgrade:{password}@upgrade.example.test:443',
        'host-resolver-rules': f'MAP upgrade.example.test {ADDRESS}'}))
    env = {k: os.environ[k] for k in ('PATH', 'HOME', 'LANG') if k in os.environ}
    if trusted: env['SSL_CERT_FILE'] = str(OUT / 'cert.pem')
    label = protocol + ('-wrong-password' if password != 'upgrade-password' else '-untrusted' if not trusted else '')
    with (OUT / (label + '.log')).open('wb') as log:
        client = subprocess.Popen([CLIENT, str(config)], env=env, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and client.poll() is None:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1): break
                except OSError: time.sleep(.05)
            if password != 'upgrade-password' or not trusted:
                try:
                    with socks(port) as conn:
                        conn.sendall(b'must-not-pass'); passed = conn.recv(64) == b'must-not-pass'
                except (OSError, EOFError): passed = False
                check(label + '-rejected', not passed)
                return
            with socks(port) as conn:
                conn.sendall(b'before'); check(protocol + '-echo', exact(conn, 6) == b'before')
                time.sleep(4)  # Longer than the server's explicit 2 s body idle timeout.
                conn.sendall(b'after'); check(protocol + '-idle-CONNECT-survives', exact(conn, 5) == b'after')
                payload = bytes(range(256)) * 1024
                conn.sendall(payload)
                check(protocol + '-256KiB-intact', exact(conn, len(payload)) == payload)
            try:
                with socks(port, '127.0.0.1') as local:
                    local.sendall(b'loopback-must-not-pass')
                    allowed = exact(local,21) == b'loopback-must-not-pass'
            except (OSError, EOFError): allowed = False
            check(protocol + '-loopback-blocked', not allowed)
        finally:
            client.terminate()
            try: client.wait(timeout=8)
            except subprocess.TimeoutExpired: client.kill(); client.wait()
            config.unlink(missing_ok=True)

try:
    if run('docker', 'network', 'inspect', NET).returncode == 0:
        raise RuntimeError('refusing to reuse an existing network')
    need('docker', 'network', 'create', '--label', 'vpnbot.hosted-ci=true', '--internal', '--subnet', '198.51.100.0/24', NET); network = True
    need('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
         '-keyout', OUT / 'key.pem', '-out', OUT / 'cert.pem', '-subj', '/CN=upgrade.example.test',
         '-addext', 'subjectAltName=DNS:upgrade.example.test')
    (OUT / 'Caddyfile').write_text('''{
    admin off
    auto_https off
    order forward_proxy before file_server
    servers {
        protocols h1 h2 h3
        timeouts {
            read_body_idle 2s
        }
    }
}
:443 {
    tls /probe/cert.pem /probe/key.pem
    forward_proxy {
        basic_auth upgrade upgrade-password
        ports 80
    }
}
''')
    (OUT / 'echo.py').write_text('''import socketserver
class Echo(socketserver.BaseRequestHandler):
 def handle(self):
  self.request.settimeout(15)
  try:
   while data:=self.request.recv(65536): self.request.sendall(data)
  except (TimeoutError,ConnectionError): pass
class Server(socketserver.ThreadingTCPServer):
 allow_reuse_address=True
 daemon_threads=True
Server(('0.0.0.0',80),Echo).serve_forever()
''')
    need('docker', 'run', '-d', '--name', TARGET, '--label', 'vpnbot.hosted-ci=true', '--network', NET, '--ip', DEST,
         '--entrypoint', 'python3', '-v', f'{OUT}:/probe:ro', PHP, '/probe/echo.py'); owned.append(TARGET)
    need('docker', 'run', '-d', '--name', SERVER, '--label', 'vpnbot.hosted-ci=true', '--network', NET, '--ip', ADDRESS,
         '--entrypoint', 'caddy', '-v', f'{OUT}:/probe:ro', IMAGE, 'run', '--config', '/probe/Caddyfile'); owned.append(SERVER)
    loopback = NET+'-loopback'
    need('docker','run','-d','--name',loopback,'--label','vpnbot.hosted-ci=true','--network','container:'+SERVER,
         '--entrypoint','python3','-v',f'{OUT}:/probe:ro',PHP,'/probe/echo.py');owned.append(loopback)
    deadline = time.monotonic() + 15
    for address,port in ((ADDRESS,443),(ADDRESS,80),(DEST,80)):
        while True:
            try:
                with socket.create_connection((address,port), timeout=.2): break
            except OSError:
                if time.monotonic() > deadline: raise RuntimeError('fixture listener not ready')
                time.sleep(.1)
    ctx = ssl.create_default_context(cafile=str(OUT / 'cert.pem'))
    with socket.create_connection((ADDRESS,80),timeout=5) as local:
        local.sendall(b'loopback-target')
        check('loopback-test-target-available', exact(local,15)==b'loopback-target')
    with ctx.wrap_socket(socket.create_connection((ADDRESS,443), timeout=5), server_hostname='upgrade.example.test') as conn:
        conn.sendall(f'CONNECT {DEST}:80 HTTP/1.1\r\nHost: {DEST}:80\r\n\r\n'.encode())
        check('unauthenticated-CONNECT-rejected', b' 407 ' in conn.recv(4096).split(b'\r\n')[0])
    for protocol in ('https', 'quic'):
        probe(protocol); probe(protocol, password='wrong'); probe(protocol, trusted=False)
    logs = run('docker', 'logs', SERVER)
    check('QUIC-BBR-controller-installed', b'sing-quic BBRv1' in logs.stdout + logs.stderr)
finally:
    if SERVER in owned:
        logs = run('docker', 'logs', SERVER); (OUT / 'server.log').write_bytes(logs.stdout + logs.stderr)
    for name in reversed(owned): need('docker', 'rm', '-f', name)
    if network: need('docker', 'network', 'rm', NET)
    for name in ('key.pem', 'client.json'): (OUT / name).unlink(missing_ok=True)
print(json.dumps({'passed': sum(row['passed'] for row in rows), 'total': len(rows)}))
