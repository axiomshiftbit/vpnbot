#!/usr/bin/env python3
import json, os, pathlib, plistlib, re, subprocess, time
ROOT=pathlib.Path('/opt/vpnbot-hosted-ci/stand'); OUT=ROOT/'results/l2tp'; OUT.mkdir(mode=0o700,exist_ok=True)
os.umask(0o077); C='vpnbot-audit-ipsecclient'; results=[]
def run(*a,timeout=45): return subprocess.run(a,capture_output=True,text=True,timeout=timeout)
def exe(*a,timeout=45): return run('docker','exec',C,*a,timeout=timeout)
def bot(a):
 r=run('docker','exec','php-audit','php','/tmp/audit-driver.php',a,timeout=120);r.check_returncode();return json.loads(r.stdout)['result']
def check(name,actual,expected=True):
 ok=actual==expected;results.append(dict(name=name,passed=ok,actual=actual,expected=expected));(OUT/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if ok else 'FAIL ')+name,flush=True)
def save(name,r): (OUT/(name+'.log')).write_text(r.stdout+r.stderr)
def put(name,body,target):
 p=OUT/name;p.write_text(body);run('docker','cp',str(p),C+':'+target).check_returncode()
def start_charon():
 exe('pkill','charon');time.sleep(.2);exe('rm','-f','/var/run/charon.vici','/var/run/charon.pid')
 run('docker','exec','-d',C,'sh','-c','/usr/lib/strongswan/charon >/tmp/l2-charon.log 2>&1').check_returncode()
 for _ in range(40):
  if exe('swanctl','--stats').returncode==0: break
  time.sleep(.1)
 r=exe('swanctl','--load-all');save('load',r);r.check_returncode()
def connect_ppp(label):
 r=exe('xl2tpd-control','connect-lac','audit');save(label+'-control',r)
 for _ in range(100):
  if exe('sh','-c','ip -4 addr show dev ppp0 2>/dev/null | grep -q "inet 10.9.1."').returncode==0: return True
  time.sleep(.2)
 save(label+'-ppp',exe('cat','/tmp/l2-ppp.log'));return False
def stop_ppp(): exe('xl2tpd-control','disconnect-lac','audit');time.sleep(.5)
password=re.search(r'^#?"auditl2"\s+\*\s+"([^"]+)"', (ROOT/'bot/config/ipsec/chap-secrets').read_text(), re.M)[1]
psk=(ROOT/'bot/config/ipsec/psk').read_text().strip()
# Профиль для iOS/macOS должен нести те самые PSK и пароль, с которыми сервер
# принимает подключение: ниже клиент соединяется значениями из профиля.
issued=bot('l2-profile');check('profile-issued',issued['sent'] and issued['name']=='auditl2-l2tp.mobileconfig')
vpn=plistlib.loads(issued['xml'].encode())['PayloadContent'][0]
check('profile-is-l2tp-for-this-server',(vpn['VPNType'],vpn['PPP']['CommRemoteAddress'],vpn['PPP']['AuthName'],vpn['IPv4']['OverridePrimary']),('L2TP','203.0.113.10','auditl2',1))
check('profile-carries-server-psk',vpn['IPSec']['SharedSecret']==psk.encode())
check('profile-carries-user-password',vpn['PPP']['AuthPassword']==password)
psk=vpn['IPSec']['SharedSecret'].decode();password=vpn['PPP']['AuthPassword']
conf='''connections {
 auditl2 {
  version = 1
  remote_addrs = 10.10.0.21
  encap = yes
  proposals = aes256-sha256-modp2048
  local { auth = psk }
  remote { auth = psk }
  children {
   l2tp {
    local_ts = dynamic[udp/1701]
    remote_ts = dynamic[udp/1701]
    mode = transport
    esp_proposals = aes256-sha256
   }
  }
 }
}
secrets {
 ike-audit { secret = "%s" }
}
'''.replace('%s',psk)
exe('mkdir','-p','/etc/xl2tpd','/etc/ppp','/var/run/xl2tpd');exe('sh','-c','test -c /dev/ppp || mknod /dev/ppp c 108 0')
exe('sh','-c',"printf 'nameserver 1.1.1.1\n' > /etc/resolv.conf").check_returncode()
put('swanctl.conf',conf,'/etc/swanctl/swanctl.conf')
put('xl2tpd.conf','''[global]
port = 1701
[lac audit]
lns = 10.10.0.21
pppoptfile = /etc/ppp/options.audit
length bit = yes
autodial = no
redial = no
''','/etc/xl2tpd/xl2tpd.conf')
put('options.ppp','''ipcp-accept-local
ipcp-accept-remote
noauth
refuse-eap
noccp
mtu 1280
mru 1280
name auditl2
password "%s"
debug
logfile /tmp/l2-ppp.log
'''.replace('%s',password),'/etc/ppp/options.audit')
exe('pkill','xl2tpd');exe('pkill','pppd');exe('rm','-f','/var/run/xl2tpd.pid')
start_charon()
bot('l2-enable')
try:
 r=exe('swanctl','--initiate','--child','l2tp','--timeout','15',timeout=22);save('ike-handshake',r);check('ikev1-transport-handshake',r.returncode,0)
 if r.returncode: raise SystemExit(1)
 run('docker','exec','-d',C,'sh','-c','xl2tpd -D >/tmp/l2-xl2tpd.log 2>&1').check_returncode();time.sleep(.3)
 success=connect_ppp('connect');check('l2tp-ppp-mschapv2',success)
 if not success: raise SystemExit(1)
 for _ in range(30):
  if bot('l2-status')['online']:break
  time.sleep(.2)
 check('bot-sees-session',bot('l2-status')['online'])
 check('server-enforces-address-pool',bot('l2-status')['virtual'].startswith('10.9.1.'))
 # Connected Docker subnet is intentionally routed through PPP for isolation checks.
 exe('ip','route','add','default','dev','ppp0','table','200').check_returncode()
 exe('ip','rule','add','priority','200','iif','lo','lookup','200').check_returncode()
 exe('ip','route','add','10.10.0.21/32','dev','eth0','table','200').check_returncode()
 for scheme in ['http','https']:
  r=exe('curl','-4','--interface','ppp0','--noproxy','*','-sS','--max-time','15',scheme+'://example.com/');save(scheme,r);check(scheme+'-traffic',r.returncode==0 and 'Example Domain' in r.stdout)
 for proto in [[],['+tcp']]:
  r=exe('dig','@10.10.0.5','example.com','A','+short','+time=3',*proto);save('dns'+str(bool(proto)),r);check('dns-'+('tcp' if proto else 'udp'),r.returncode==0 and bool(re.search(r'(?m)^\d+\.\d+\.\d+\.\d+$',r.stdout)))
 for name,url in [('docker-api','http://10.10.0.8:2375/version'),('panel','http://10.10.0.7:8090/'),('adguard-admin','http://10.10.0.5:80/')]:
  r=exe('curl','-4','--interface','ppp0','--noproxy','*','-sS','--max-time','3',url);save(name,r);check(name+'-isolated',r.returncode!=0)
 bot('l2-disable');time.sleep(1);check('disabled-session-kicked',bot('l2-status')['online'],False)
 exe('ip','rule','del','priority','200');exe('ip','route','flush','table','200')
 stop_ppp();check('disabled-login-rejected',connect_ppp('disabled'),False)
 stop_ppp();bot('l2-enable');check('enabled-login-reconnects',connect_ppp('enabled'))
 stop_ppp();exe('swanctl','--terminate','--ike','auditl2','--timeout','5')
 check('unencrypted-l2tp-rejected',connect_ppp('plaintext'),False)
finally:
 exe('ip','rule','del','priority','200');exe('ip','route','flush','table','200');stop_ppp();exe('swanctl','--terminate','--ike','auditl2','--timeout','5');bot('l2-enable')
menu=bot('ipsec-menu');check('client-menu-renders-with-new-button',(menu['l2tp_profile'],menu['l2tp_buttons'],menu['fits']),(True,7,True))
print(json.dumps({'passed':sum(r['passed'] for r in results),'total':len(results)}))
raise SystemExit(0 if all(r['passed'] for r in results) else 1)
