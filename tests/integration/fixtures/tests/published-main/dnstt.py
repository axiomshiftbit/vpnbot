#!/usr/bin/env python3
import json,os,pathlib,subprocess,time
import proxy_helpers as h
h.OUT=h.ROOT/'results/dnstt';h.OUT.mkdir(mode=0o700,exist_ok=True)
run=h.run;exe=h.exe;check=h.check;save=h.save
SSH=['ssh','-o','UserKnownHostsFile=/tmp/dnstt_known_hosts','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8','-o','NumberOfPasswordPrompts=1','-o','ExitOnForwardFailure=yes','-p','17000']
def bot(a):
 r=run('docker','exec','php-audit','php','/tmp/audit-driver.php',a,timeout=120);r.check_returncode();v=json.loads(r.stdout);check('bot-'+a+'-warnings',not v['warnings']);return v['result']
def auth():
 bot('dnstt-export');return json.loads((h.ROOT/'bot/logs/audit-dnstt.json').read_text())
def password(value):
 p=h.OUT/'password';p.write_text(value);run('docker','cp',str(p),h.C+':/tmp/audit-dnstt-password').check_returncode()
def stop():
 exe('pkill','-x','ssh');exe('pkill','-x','sshpass');exe('pkill','-x','dnstt-client');time.sleep(.2)
def start(a):
 stop();password(a['password']);run('docker','exec','-d',h.C,'sh','-c','dnstt-client -udp 10.10.0.16:53 -pubkey '+a['public_key']+' '+a['domain']+' 127.0.0.1:17000 >/tmp/dnstt-client.log 2>&1').check_returncode();time.sleep(.5)
 r=exe('sh','-c','ssh-keyscan -T 6 -p 17000 127.0.0.1 > /tmp/dnstt_known_hosts 2>/dev/null');check('encrypted-dns-tunnel-has-ssh',r.returncode==0)
 run('docker','exec','-d',h.C,'sh','-c','sshpass -f /tmp/audit-dnstt-password '+' '.join(SSH)+' -N -D 127.0.0.1:1089 vpnbot@127.0.0.1 >/tmp/dnstt-ssh.log 2>&1').check_returncode();time.sleep(1)
def ssh(*args):return exe('sshpass','-f','/tmp/audit-dnstt-password',*SSH,*args,timeout=15)
try:
 a=auth();start(a)
 for scheme in ['http','https']:
  r=h.http(scheme+'://example.com/',20);save(scheme,r);check(scheme+'-traffic',r.returncode==0 and 'Example Domain' in r.stdout)
 for name,url in [('docker-api','http://10.10.0.8:2375/version'),('panel','http://10.10.0.7:8090/'),('adguard-admin','http://10.10.0.5:80/')]:
  r=h.http(url,4);check(name+'-isolated',not r.stdout and r.returncode!=0)
 r=exe('python3','-c',h.TCP,timeout=10);check('loopback-isolated',r.returncode==0 and 'blocked' in r.stdout)
 r=ssh('vpnbot@127.0.0.1','id');check('shell-exec-forbidden',r.returncode!=0 and 'uid=' not in r.stdout)
 r=ssh('-s','vpnbot@127.0.0.1','sftp');check('sftp-forbidden',r.returncode!=0)
 r=ssh('-N','-R','127.0.0.1:19000:example.com:80','vpnbot@127.0.0.1');check('remote-forward-forbidden',r.returncode!=0)
 password('wrong-audit-password');r=ssh('vpnbot@127.0.0.1','true');check('wrong-password-rejected',r.returncode!=0 and 'Permission denied' in r.stderr)
 password(a['password']);r=ssh('root@127.0.0.1','true');check('root-password-rejected',r.returncode!=0 and 'Permission denied' in r.stderr)
 # Capture server public identity, restart the full service, then reauthenticate.
 key=run('docker','exec','dnstt-audit','cat','/dnstt/ssh_host_ed25519_key.pub').stdout
 run('docker','restart','dnstt-audit',timeout=45).check_returncode();time.sleep(1)
 check('ssh-host-key-persists',key==run('docker','exec','dnstt-audit','cat','/dnstt/ssh_host_ed25519_key.pub').stdout)
 start(a);r=h.http('https://example.com/',20);check('restart-restores-service',r.returncode==0 and 'Example Domain' in r.stdout)
 bot('dnstt-init');r=h.http('https://example.com/',5);check('password-rotation-stops-old-session',r.returncode!=0)
 start(a);r=h.http('https://example.com/',5);check('old-password-rejected',r.returncode!=0)
 a=auth();start(a);r=h.http('https://example.com/',20);check('new-password-works',r.returncode==0 and 'Example Domain' in r.stdout)
 bot('dnstt-disable');r=h.http('https://example.com/',5);check('disabled-service-stops-traffic',r.returncode!=0)
finally:stop();bot('dnstt-init')
print(json.dumps({'passed':sum(x['passed'] for x in h.results),'total':len(h.results)}))
raise SystemExit(0 if all(x['passed'] for x in h.results) else 1)
