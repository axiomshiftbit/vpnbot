#!/usr/bin/env python3
import json, os, pathlib, re, subprocess, time
ROOT=pathlib.Path('/opt/vpnbot-hosted-ci/stand');OUT=ROOT/'results/openconnect';OUT.mkdir(mode=0o700,exist_ok=True)
os.umask(0o077);C='vpnbot-audit-ovpnclient';results=[]
def run(*a,timeout=45,input=None): return subprocess.run(a,capture_output=True,text=True,timeout=timeout,input=input)
def exe(*a,**kw): return run('docker','exec',C,*a,**kw)
def bot(a):
 r=run('docker','exec','php-audit','php','/tmp/audit-driver.php',a,timeout=120);r.check_returncode();return json.loads(r.stdout)['result']
def check(n,a,e=True):
 ok=a==e;results.append(dict(name=n,passed=ok,actual=a,expected=e));(OUT/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if ok else 'FAIL ')+n,flush=True)
def save(n,r): (OUT/(n+'.log')).write_text(r.stdout+r.stderr)
def stop():exe('pkill','openconnect');time.sleep(.5)
bot('oc-init');bot('oc-export');auth=json.loads((ROOT/'bot/logs/audit-oc.json').read_text());assert auth['password']
run('docker','cp',str(ROOT/'bot/certs/cert_public'),C+':/tmp/audit-oc-ca.crt').check_returncode()
base=['openconnect','https://'+auth['host'],'--resolve='+auth['host']+':10.10.0.10','--user=auditoc','--passwd-on-stdin','--non-inter','--cafile=/tmp/audit-oc-ca.crt']
def connect(label,password,authonly=False):
 args=base+(['--authenticate'] if authonly else ['--background','--pid-file=/tmp/audit-oc.pid','--interface=auditoc','--script=/etc/vpnc/vpnc-script'])
 # Фоновый openconnect наследует stdout; редирект внутри контейнера закрывает
 # pipe Docker после запуска. Пароль передаётся только stdin.
 import shlex
 cmd=shlex.join(args)+' >/tmp/audit-oc-client.log 2>&1'
 r=run('docker','exec','-i',C,'sh','-c',cmd,input=password+'\n',timeout=30);save(label,exe('cat','/tmp/audit-oc-client.log'))
 return r.returncode==0
stop()
exe('sh','-c',"printf 'nameserver 1.1.1.1\n' > /etc/resolv.conf").check_returncode()
try:
 check('wrong-password-rejected',connect('wrong-password','invalid-audit-password',True),False)
 ok=connect('connect',auth['password']);check('tls-certificate-password-handshake',ok)
 if not ok:
  # Server side of a failed handshake (stays on the runner; diagnostics are
  # encrypted): start_oc.sh output, ocserv log tail and the client firewall.
  srv='openconnect-audit'
  save('server-container',run('docker','logs','--tail','200',srv))
  save('server-ocserv',run('docker','exec',srv,'tail','-n','200','/logs/ocserv.log'))
  save('server-firewall',run('docker','exec',srv,'iptables','-S'))
  save('server-processes',run('docker','exec',srv,'ps','-o','pid,args'))
  raise SystemExit(1)
 time.sleep(2)
 dtls=exe('cat','/tmp/audit-oc-client.log');save('dtls',dtls)
 check('dtls-channel-established','Established DTLS connection' in dtls.stdout)
 state=exe('ip','-j','-4','addr','show','auditoc');save('address',state)
 vip=json.loads(state.stdout)[0]['addr_info'][0]['local'];check('address-from-pool',vip.startswith('10.0.2.'))
 for ip in ['10.10.0.5','10.10.0.7','10.10.0.8']:exe('ip','route','replace',ip+'/32','dev','auditoc').check_returncode()
 for scheme in ['http','https']:
  r=exe('curl','-4','--interface','auditoc','--noproxy','*','-sS','--max-time','15',scheme+'://example.com/');save(scheme,r);check(scheme+'-traffic',r.returncode==0 and 'Example Domain' in r.stdout)
 for proto in [[],['+tcp']]:
  r=exe('dig','-b',vip,'@10.10.0.5','example.com','A','+short','+time=3',*proto);save('dns'+str(bool(proto)),r);check('dns-'+('tcp' if proto else 'udp'),r.returncode==0 and bool(re.search(r'(?m)^\d+\.\d+\.\d+\.\d+$',r.stdout)))
 for name,url in [('docker-api','http://10.10.0.8:2375/version'),('panel','http://10.10.0.7:8090/'),('adguard-admin','http://10.10.0.5:80/'),('own-ssh','telnet://10.0.2.1:22')]:
  r=exe('curl','-4','--interface','auditoc','--noproxy','*','-sS','--max-time','3',url);save(name,r);check(name+'-isolated',not r.stdout and r.returncode!=0)
 bot('oc-delete');time.sleep(.5)
 r=exe('curl','-4','--interface','auditoc','--noproxy','*','-sS','--max-time','3','http://example.com/');check('deleted-session-stops',r.returncode!=0)
 stop();check('deleted-login-rejected',connect('deleted',auth['password'],True),False)
finally:
 stop();bot('oc-init');bot('oc-export')
print(json.dumps({'passed':sum(r['passed'] for r in results),'total':len(results)}))
raise SystemExit(0 if all(r['passed'] for r in results) else 1)
