#!/usr/bin/env python3
import json, os, pathlib, re, subprocess, time
ROOT=pathlib.Path('/opt/vpnbot-hosted-ci/stand');OUT=ROOT/'results/openvpn-extra';OUT.mkdir(mode=0o700,exist_ok=True)
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

def profile():
 bot('ovpn-export')
 text=(ROOT/'bot/logs/audit-files/auditov.ovpn').read_text()
 text=re.sub(r'^remote \S+ (\d+)$',r'remote 10.10.0.19 \1',text,flags=re.M)
 p=OUT/'client.ovpn';p.write_text(text);run('docker','cp',str(p),C+':/tmp/audit.ovpn').check_returncode()
def traffic(name,expect=True):
 r=exe('curl','-4','--interface','tun0','--noproxy','*','-sS','--max-time','8','https://example.com/');save(name,r);check(name,r.returncode==0 and 'Example Domain' in r.stdout,expect)
bot('ovpn-enable');bot('ovpn-pki-save')
try:
 check('bot-switch-tcp',bot('ovpn-proto')['proto'],'tcp4');profile()
 check('tcp-handshake',connect('tcp'));traffic('tcp-https')
 bot('ovpn-revoke');traffic('revoked-session-stops',False)
 check('crl-rejects-old-certificate',connect('revoked'),False)
 # Возвращаем экспорт состояния до revoke через штатный import PKI.
 r=bot('ovpn-pki-restore');check('pki-restore',r['ok'] is not False)
 profile();check('restored-profile-handshake',connect('restored'));traffic('restored-https')
 check('bot-restores-udp',bot('ovpn-proto')['proto'],'tcp4')
 # Снимок из UDP вернул серверный proto; проверяем второй цикл TCP/UDP.
 check('bot-switch-udp',bot('ovpn-proto')['proto'],'udp4')
 profile();check('udp-after-two-switches',connect('udp-final'));traffic('udp-final-https')
finally:
 stop();bot('ovpn-enable')
print(json.dumps({'passed':sum(r['passed'] for r in results),'total':len(results)}))
raise SystemExit(0 if all(r['passed'] for r in results) else 1)
