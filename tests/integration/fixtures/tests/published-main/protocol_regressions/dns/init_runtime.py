#!/usr/bin/env python3
"""Генерирует только новую синтетическую PKI/SSH внутри закрытого контейнера."""
import json,os,pathlib,shutil,subprocess
os.umask(0o077)
def cmd(args):
    r=subprocess.run(args,capture_output=True,timeout=30)
    if r.returncode:raise RuntimeError('dependency failed: '+pathlib.Path(args[0]).name)
for d in ['/config','/certs','/logs','/ssh/hosts/ad','/ssh/hosts/ng','/work/pki','/work/routes']:
    pathlib.Path(d).mkdir(parents=True,exist_ok=True)
cmd(['ssh-keygen','-q','-t','ed25519','-N','','-f','/ssh/key'])
for service in ['ad','ng']:
    cmd(['ssh-keygen','-q','-t','ed25519','-N','','-f','/ssh/hosts/'+service+'/ssh_host_ed25519_key'])
    pathlib.Path('/ssh/'+service+'_sshd_config').write_text('Port 22\nListenAddress 0.0.0.0\nHostKey /ssh/hosts/'+service+'/ssh_host_ed25519_key\nAuthorizedKeysFile /ssh/key.pub\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin yes\nUsePAM no\nStrictModes no\nPidFile /tmp/sshd.pid\nLogLevel ERROR\n')
for slot,days,serial in [('old',10,101),('new',90,202),('newer',90,303)]:
    d=pathlib.Path('/work/pki')/slot; d.mkdir()
    cmd(['openssl','req','-x509','-newkey','rsa:2048','-noenc','-keyout',str(d/'key.pem'),'-out',str(d/'cert.pem'),'-days',str(days),'-set_serial',str(serial),'-subj','/CN=tls.audit.test','-addext','subjectAltName=DNS:tls.audit.test'])
shutil.copy2('/work/pki/old/key.pem','/certs/cert_private'); shutil.copy2('/work/pki/old/cert.pem','/certs/cert_public')
pathlib.Path('/config/pac.json').write_text(json.dumps({'language':'ru','hashbot':'synthetic','domain':'tls.audit.test','letsencrypt':'letsencrypt','adpswd':'synthetic-only','telemt_web':False}))
pathlib.Path('/config/protocol-services.json').write_text(json.dumps({'tt':False,'telemt':False}))
pathlib.Path('/config/telegram_api').write_text('https://127.0.0.1:1\n')
template='''pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events { worker_connections 64; }
http {
 access_log off;
 server {
  listen 8443 ssl;
  server_name *.tls.audit.test tls.audit.test;
  ssl_certificate /certs/cert_public;
  ssl_certificate_key /certs/cert_private;
  location / { return 200 "synthetic TLS fixture\\n"; }
 }
}
'''
pathlib.Path('/config/nginx_default.conf').write_text(template)
pathlib.Path('/config/nginx.conf').write_text(template)
print(json.dumps({'synthetic_pki_created':True,'ssh_hostkeys_created':2,'certificate_pairs_created':3}))
