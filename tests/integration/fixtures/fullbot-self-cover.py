#!/usr/bin/env python3
"""Full bot's generated REALITY destination against its actual NGINX listeners.

Only inside the disconnected disposable Docker host; synthetic keys and TLS.
The main bot PHP fixture emits public destination/SNI/xver fields beforehand.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import uuid

def run(args, **kw):
    return subprocess.run(list(map(str, args)), capture_output=True, timeout=30, **kw)

if run(['systemd-detect-virt', '--container']).stdout.strip() != b'docker' or run(['ip', 'route', 'show', 'default']).stdout.strip():
    raise SystemExit('Disconnected disposable Docker host required')
os.umask(0o077)
work = Path(tempfile.mkdtemp(prefix='full-cover-', dir='/run'))
container = 'vpnbot-full-cover-audit'
image = 'ghcr.io/axiomshiftbit/vpnbot-ng@sha256:d766744fec520b177c476e5b8731ca592de75ea6aee03575fd68a551f8f03197'
process = None
failed = 0
addresses = []
try:
    for address in ('10.10.0.2', '10.10.1.2'):
        run(['ip', 'address', 'add', address+'/32', 'dev', 'lo'], check=True)
        addresses.append(address)
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=cover.example.test',
         '-addext', 'subjectAltName=DNS:cover.example.test', '-keyout', work/'key.pem', '-out', work/'cert.pem'], check=True)
    password = os.urandom(24).hex()
    hashed = run(['openssl', 'passwd', '-6', '-stdin'], input=(password+'\n').encode(), check=True).stdout.strip()
    (work/'htpasswd').write_bytes(b'admin:'+hashed+b'\n')
    (work/'index.html').write_text('full-bot-cover-pass')
    # Take the two actual listener declarations from the full bot template.
    source = Path('/lab/config/nginx.conf').read_text()
    listeners = re.findall(r'^\s*listen 10\.10\.[01]\.2:443 ssl[^;]*;', source, re.M)
    if len(listeners) != 2:
        raise RuntimeError('unexpected full bot listener template')
    (work/'nginx.conf').write_text('''worker_processes 1;
pid /tmp/nginx.pid;
error_log /dev/stderr crit;
events { worker_connections 32; }
http { access_log off; client_body_temp_path /tmp/body; proxy_temp_path /tmp/proxy;
fastcgi_temp_path /tmp/fastcgi; uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi;
server {
'''+'\n'.join(line.replace(':443 ', ':24443 ') for line in listeners)+'''
http2 on; server_name cover.example.test;
ssl_certificate /fixture/cert.pem; ssl_certificate_key /fixture/key.pem;
root /fixture;
location / { auth_basic "Restricted Content"; auth_basic_user_file /fixture/htpasswd; index index.html; }
}}
''')
    for path in [work, *work.iterdir()]:
        os.chown(path, 65532, 65532)
    run(['docker', 'run', '-d', '--name', container, '--label', 'vpnbot.audit=managed-node-1031', '--network', 'host',
         '--user', '65532:65532', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--memory', '96m', '--pids-limit', '32',
         '--tmpfs', '/tmp:mode=1777', '-v', str(work)+':/fixture:ro', '--entrypoint', '/usr/sbin/nginx', image,
         '-c', '/fixture/nginx.conf', '-g', 'daemon off;'], check=True)
    generated = run(['/lab/x31', 'x25519'], check=True).stdout.decode()
    fields = dict(line.split(':', 1) for line in generated.splitlines() if ':' in line)
    private = next(v.strip() for k, v in fields.items() if k.lower().replace(' ', '') == 'privatekey')
    for rs in json.loads(Path('/lab/full-cover-public.json').read_text()):
        rs = dict(rs, dest=rs['dest'].replace(':443', ':24443'), privateKey=private, shortIds=['12345678'])
        config = {'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1', 'port': 28443, 'protocol': 'vless',
                  'settings': {'clients': [{'id': str(uuid.uuid4())}], 'decryption': 'none'},
                  'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': rs}}],
                  'outbounds': [{'protocol': 'freedom'}]}
        (work/'xray.json').write_text(json.dumps(config))
        process = subprocess.Popen(['/lab/x31', 'run', '-c', str(work/'xray.json')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(.4)
        for auth, expected in ((None, b'401'), (password, b'200')):
            data = ('user = "admin:'+auth+'"\n').encode() if auth else b''
            result = run(['curl', '--noproxy', '*', '--max-time', '3', '-sS', '--cacert', work/'cert.pem',
                          '--resolve', 'cover.example.test:28443:127.0.0.1', '--config', '-', '-o', '/dev/null', '-w', '%{http_code}',
                          'https://cover.example.test:28443/'], input=data)
            ok = result.returncode == 0 and result.stdout == expected
            print(('PASS ' if ok else 'FAIL ')+f'full bot own password cover xver={rs["xver"]} auth={bool(auth)}', flush=True)
            failed += not ok
        process.terminate(); process.wait(timeout=5); process = None
finally:
    if process is not None:
        process.terminate(); process.wait(timeout=5)
    run(['docker', 'rm', '-f', container])
    for address in addresses:
        run(['ip', 'address', 'del', address+'/32', 'dev', 'lo'])
    shutil.rmtree(work)
raise SystemExit(1 if failed else 0)
