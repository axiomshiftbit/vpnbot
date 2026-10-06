#!/usr/bin/env python3
import json,os,pathlib,subprocess,time
import proxy_helpers as h
h.OUT=h.ROOT/'results/dnstt-identity';h.OUT.mkdir(mode=0o700,exist_ok=True)
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
def identity():
 return run('docker','exec','dnstt-audit','cat','/dnstt/ssh_host_ed25519_key.pub').stdout
try:
 check('identity-export',bot('dnstt-identity-save')['saved']);old=identity();a=auth();start(a)
 r=h.http('https://example.com/',20);check('before-restore-traffic',r.returncode==0 and 'Example Domain' in r.stdout)
 conf=h.ROOT/'bot/config/dnstt'
 for suffix in ['', '.pub']:
  (conf/('ssh_host_ed25519_key'+suffix)).rename(h.OUT/('previous_host_key'+suffix))
 run('docker','exec','dnstt-audit','ssh-keygen','-q','-t','ed25519','-N','','-f','/dnstt/ssh_host_ed25519_key').check_returncode()
 bot('dnstt-reload');check('identity-changed',identity()!=old)
 start(a);r=h.http('https://example.com/',20);check('changed-identity-traffic',r.returncode==0 and 'Example Domain' in r.stdout)
 check('partial-restore-no-errors',bot('dnstt-identity-restore')['error_messages'],0);check('restored-identity',identity()==old)
 start(a);r=h.http('https://example.com/',20);check('restored-identity-traffic',r.returncode==0 and 'Example Domain' in r.stdout)
 # Набор compose-файлов и закреплённые образы стенда приходят из окружения.
 compose=['python3','scripts/protocol_modules.py','compose']
 r=subprocess.run(compose+['up','-d','--no-deps','--force-recreate','--no-build','--pull','never','dnstt'],cwd=h.ROOT/'bot',capture_output=True,text=True,timeout=90);save('recreate',r);check('recreate',r.returncode,0);time.sleep(2)
 check('identity-persists-recreate',identity()==old)
 start(a);r=h.http('https://example.com/',20);check('recreated-traffic',r.returncode==0 and 'Example Domain' in r.stdout)
 # Первый дочерний демон остаётся за tail; последующие сироты собираются init.
 # Проверяем отсутствие накопления при повторных reload (не более одного).
 for i in range(4):bot('dnstt-reload')
 states=run('docker','exec','dnstt-audit','ps','-eo','stat,comm').stdout
 check('init-reaps-restarted-daemons',sum(line.split()[0].startswith('Z') for line in states.splitlines()[1:] if line.split()) <= 1)
finally:stop()
print(json.dumps({'passed':sum(x['passed'] for x in h.results),'total':len(h.results)}))
raise SystemExit(0 if all(x['passed'] for x in h.results) else 1)
