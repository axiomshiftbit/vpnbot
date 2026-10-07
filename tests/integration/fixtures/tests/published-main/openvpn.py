#!/usr/bin/env python3
import json, os, pathlib, re, subprocess, time
ROOT=pathlib.Path('/opt/vpnbot-hosted-ci/stand');OUT=ROOT/'results/openvpn';OUT.mkdir(mode=0o700,exist_ok=True)
os.umask(0o077);C='vpnbot-audit-ovpnclient';results=[]
def run(*a,timeout=45): return subprocess.run(a,capture_output=True,text=True,timeout=timeout)
def exe(*a,timeout=45): return run('docker','exec',C,*a,timeout=timeout)
def bot(a):
 r=run('docker','exec','php-audit','php','/tmp/audit-driver.php',a,timeout=120);r.check_returncode();return json.loads(r.stdout)['result']
def check(n,a,e=True):
 ok=a==e;results.append(dict(name=n,passed=ok,actual=a,expected=e));(OUT/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if ok else 'FAIL ')+n,flush=True)
def save(n,r): (OUT/(n+'.log')).write_text(r.stdout+r.stderr)
def stop(): exe('pkill','openvpn');time.sleep(.3)
def connect(label):
 stop();exe('rm','-f','/tmp/audit-openvpn.log')
 r=exe('openvpn','--config','/tmp/audit.ovpn','--daemon','--log','/tmp/audit-openvpn.log','--connect-retry-max','1','--connect-retry','1','--tls-exit');r.check_returncode()
 for _ in range(100):
  r=exe('cat','/tmp/audit-openvpn.log');save(label,r)
  if 'Initialization Sequence Completed' in r.stdout:return True
  if 'AUTH_FAILED' in r.stdout or 'Exiting due to fatal error' in r.stdout:return False
  time.sleep(.2)
 return False
bot('ovpn-enable');bot('ovpn-export')
profile=(ROOT/'bot/logs/audit-files/auditov.ovpn').read_text()
profile=re.sub(r'^remote \S+ (\d+)$',r'remote 10.10.0.19 \1',profile,flags=re.M)
p=OUT/'client.ovpn';p.write_text(profile);run('docker','cp',str(p),C+':/tmp/audit.ovpn').check_returncode()
try:
 ok=connect('connect');check('generated-profile-tls-handshake',ok)
 if not ok:raise SystemExit(1)
 # С ядерным модулем ovpn (DCO) сервер пишет файл состояния раз в 12-14 с, а не
 # раз в 5, как задано в конфиге: ждём с запасом.
 for _ in range(50):
  if bot('ovpn-status')['online']:break
  time.sleep(.5)
 check('bot-sees-session',bot('ovpn-status')['online'])
 for ip in ['10.10.0.5','10.10.0.7','10.10.0.8']:
  exe('ip','route','replace',ip+'/32','dev','tun0').check_returncode()
 for scheme in ['http','https']:
  r=exe('curl','-4','--interface','tun0','--noproxy','*','-sS','--max-time','15',scheme+'://example.com/');save(scheme,r);check(scheme+'-traffic',r.returncode==0 and 'Example Domain' in r.stdout)
 for proto in [[],['+tcp']]:
  r=exe('dig','@10.10.0.5','example.com','A','+short','+time=3',*proto);save('dns'+str(bool(proto)),r);check('dns-'+('tcp' if proto else 'udp'),r.returncode==0 and bool(re.search(r'(?m)^\d+\.\d+\.\d+\.\d+$',r.stdout)))
 for name,url in [('docker-api','http://10.10.0.8:2375/version'),('panel','http://10.10.0.7:8090/'),('adguard-admin','http://10.10.0.5:80/'),('own-ssh','telnet://10.8.0.1:22')]:
  r=exe('curl','-4','--interface','tun0','--noproxy','*','-sS','--max-time','3',url);save(name,r);check(name+'-isolated',not r.stdout and r.returncode!=0)
 bot('ovpn-disable')
 # Статусный файл OpenVPN обновляется раз в 5 секунд; проверяем также
 # фактическое прекращение трафика, не только асинхронный online-маркер.
 r=exe('curl','-4','--interface','tun0','--noproxy','*','-sS','--max-time','3','http://example.com/')
 check('disabled-traffic-stops',r.returncode!=0)
 for _ in range(50):
  if not bot('ovpn-status')['online']:break
  time.sleep(.5)
 check('disabled-session-kicked',bot('ovpn-status')['online'],False)
 check('disabled-login-rejected',connect('disabled'),False)
 bot('ovpn-enable');check('enabled-login-reconnects',connect('enabled'))
finally:
 stop();bot('ovpn-enable')
print(json.dumps({'passed':sum(r['passed'] for r in results),'total':len(results)}))
raise SystemExit(0 if all(r['passed'] for r in results) else 1)
