#!/usr/bin/env python3
import copy, json, os, pathlib, plistlib, re, ssl, subprocess, time
ROOT=pathlib.Path('/opt/vpnbot-hosted-ci/stand');OUT=ROOT/'results/ikev2';OUT.mkdir(exist_ok=True,mode=0o700)
os.umask(0o077)
C='vpnbot-audit-ipsecclient';results=[]
def run(*args,timeout=45): return subprocess.run(args,capture_output=True,text=True,timeout=timeout)
def exe(*args,timeout=45): return run('docker','exec',C,*args,timeout=timeout)
def bot(*args):
    r=run('docker','exec','php-audit','php','/tmp/audit-driver.php',*args,timeout=120);r.check_returncode();return json.loads(r.stdout)
def check(name,actual,expected=True):
    ok=actual==expected;results.append(dict(name=name,passed=ok,actual=actual,expected=expected))
    (OUT/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if ok else 'FAIL ')+name,flush=True)
def save(name,r): (OUT/(name+'.log')).write_text(r.stdout+r.stderr)
def connect(name):
    r=exe('swanctl','--initiate','--child','audit-tunnel','--timeout','15',timeout=22);save(name,r);return r.returncode==0
def terminate(): exe('swanctl','--terminate','--ike','auditike','--timeout','5',timeout=10)
def pending():
    # Only the synthetic user's non-secret enforcement state leaves the container.
    program='$u=json_decode(file_get_contents("/config/ipsec/users_ikev2.json"),true);echo json_encode(["disabled"=>!empty($u["auditike"]["disabled"]),"pending"=>$u["auditike"]["pending"]??null]);'
    r=run('docker','exec','php-audit','php','-r',program);r.check_returncode();return json.loads(r.stdout)
def install_reload_fault():
    # This container belongs to the disposable stand. All other swanctl commands
    # still use the original binary; only credential reload deliberately fails.
    script='''set -eu
binary=$(command -v swanctl)
case "$binary" in /usr/bin/swanctl|/usr/sbin/swanctl) ;; *) exit 1;; esac
test ! -e "$binary.audit-real"
printf '%s\n' "$binary" > /tmp/vpnbot-audit-swanctl-path
printf '#!/bin/sh\nif [ "${1:-}" = --load-creds ]; then exit 42; fi\nexec "%s.audit-real" "$@"\n' "$binary" > "$binary.audit-wrapper"
chmod 755 "$binary.audit-wrapper"
mv "$binary" "$binary.audit-real"
mv "$binary.audit-wrapper" "$binary"
'''
    r=run('docker','exec','ipsec-audit','sh','-c',script);r.check_returncode()
def remove_reload_fault():
    script='''set -eu
test -f /tmp/vpnbot-audit-swanctl-path || exit 0
read -r binary < /tmp/vpnbot-audit-swanctl-path
case "$binary" in /usr/bin/swanctl|/usr/sbin/swanctl) ;; *) exit 1;; esac
if [ -f "$binary.audit-real" ]; then mv "$binary.audit-real" "$binary"; fi
rm -f "$binary.audit-wrapper" /tmp/vpnbot-audit-swanctl-path
'''
    run('docker','exec','ipsec-audit','sh','-c',script).check_returncode()
def restart_client():
    exe('pkill','charon')
    time.sleep(.2)
    exe('rm','-f','/var/run/charon.vici','/var/run/charon.pid')
    run('docker','exec','-d',C,'sh','-c','/usr/lib/strongswan/charon >>/tmp/audit-charon.log 2>&1').check_returncode()
    for _ in range(50):
        if exe('swanctl','--stats').returncode==0: break
        time.sleep(.1)
    r=exe('swanctl','--load-all');r.check_returncode()
def http(url,timeout=14): return exe('curl','-4','--interface',vip,'--noproxy','*','-sS','--max-time',str(timeout),url,timeout=timeout+5)

users=json.loads((ROOT/'bot/config/ipsec/users_ikev2.json').read_text())
resolve=OUT/'audit-resolve.conf';resolve.write_text('charon { plugins { resolve { file = /tmp/audit-resolv.conf } } }\n')
run('docker','cp',str(resolve),C+':/etc/strongswan.d/audit-resolve.conf').check_returncode()
exe('sh','-c',"printf 'nameserver 1.1.1.1\n' > /etc/resolv.conf").check_returncode()
password=users['auditike']['pass']
# Профили iOS/macOS: обычный остаётся без автоподключения, вариант «по
# требованию» отличается только двумя ключами; пароль и CA — те же, с которыми
# ниже проходит настоящее подключение.
ca_der=ssl.PEM_cert_to_DER_cert((ROOT/'bot/config/ipsec/pki/ca.crt').read_text())
plain=bot('ike-profile')['result'];auto=bot('ike-profile-auto')['result']
check('profiles-issued',(plain['sent'],plain['name'],auto['sent'],auto['name']),(True,'auditike.mobileconfig',True,'auditike-ondemand.mobileconfig'))
plain=plistlib.loads(plain['xml'].encode());auto=plistlib.loads(auto['xml'].encode())
ike=auto['PayloadContent'][0]['IKEv2']
check('ondemand-profile-connects-by-itself',(ike.get('OnDemandEnabled'),ike.get('OnDemandRules')),(1,[{'Action':'Connect'}]))
check('regular-profile-does-not','OnDemandEnabled' not in plain['PayloadContent'][0]['IKEv2'] and 'OnDemandRules' not in plain['PayloadContent'][0]['IKEv2'])
same=copy.deepcopy(auto);del same['PayloadContent'][0]['IKEv2']['OnDemandEnabled'],same['PayloadContent'][0]['IKEv2']['OnDemandRules']
check('ondemand-differs-only-by-two-keys',same==plain)
check('profile-carries-server-ca-and-credentials',(auto['PayloadContent'][1]['PayloadContent']==ca_der,ike['AuthPassword']==password,ike['AuthName'],ike['RemoteAddress']),(True,True,'auditike','203.0.113.10'))
password=ike['AuthPassword']
conf='''connections {
 auditike {
  version = 2
  local_addrs = %any
  remote_addrs = 10.10.0.21
  vips = 0.0.0.0
  encap = yes
  proposals = aes256gcm16-prfsha384-ecp384
  local {
   auth = eap-mschapv2
   id = auditike
   eap_id = auditike
  }
  remote {
   auth = pubkey
   id = 203.0.113.10
  }
  children {
   audit-tunnel {
    local_ts = dynamic
    remote_ts = 0.0.0.0/0
    esp_proposals = aes256gcm16
    start_action = none
   }
  }
 }
}
secrets {
 eap-audit {
  id = auditike
  secret = "%s"
 }
}
'''.replace('%s',password)
f=OUT/'swanctl.conf';f.write_text(conf)
exe('mkdir','-p','/etc/swanctl/x509ca').check_returncode()
run('docker','cp',str(f),C+':/etc/swanctl/swanctl.conf').check_returncode()
run('docker','cp',str(ROOT/'bot/config/ipsec/pki/ca.crt'),C+':/etc/swanctl/x509ca/audit-ca.crt').check_returncode()
exe('pkill','charon')
run('docker','exec','-d',C,'sh','-c','/usr/lib/strongswan/charon >/tmp/audit-charon.log 2>&1').check_returncode()
for _ in range(40):
    if exe('test','-S','/var/run/charon.vici').returncode==0:break
    time.sleep(.1)
r=exe('swanctl','--load-all');save('load',r);check('client-config-loaded',r.returncode,0)
bot('ike-enable')
try:
    success=connect('connect');check('eap-certificate-handshake',success)
    if success:
        status=bot('ike-status');check('bot-sees-active-session',status['result']['online'])
        vip=status['result']['virtual'];assert re.fullmatch(r'10\.9\.2\.\d+',vip)
        for scheme in ('http','https'):
            r=http(scheme+'://example.com/');save(scheme,r);check(scheme+'-traffic',r.returncode==0 and 'Example Domain' in r.stdout)
        for name,url in [('docker-api','http://10.10.0.8:2375/version'),('panel','http://10.10.0.7:8090/'),('adguard-admin','http://10.10.0.5:80/')]:
            r=http(url,4);save(name,r);check(name+'-network-isolation',r.returncode!=0)
        try:
            install_reload_fault()
            bot('ike-disable')
            check('reload-failure-retains-durable-pending',pending(),{'disabled':True,'pending':'disable'})
            check('reload-failure-does-not-claim-disconnected',bot('ike-status')['result']['online'])
        finally:
            remove_reload_fault()
        bot('ike-disable');time.sleep(.5)
        check('successful-retry-clears-pending',pending(),{'disabled':True,'pending':None})
        check('disabled-session-kicked',bot('ike-status')['result']['online'],False)
        # strongSwan 6.0.7 в этом Alpine-клиенте падает на повторном vici
        # initiate после peer-initiated DELETE. Для независимой проверки
        # отзыва credentials начинаем новый клиентский процесс.
        if os.environ.get('IKE_REUSE_CLIENT') != '1': restart_client()
        check('disabled-credential-rejected',connect('disabled-connect'),False)
        terminate()
        bot('ike-enable')
        if os.environ.get('IKE_REUSE_CLIENT') != '1': restart_client()
        check('enabled-credential-reconnects',connect('enabled-connect'))
finally:
    remove_reload_fault();terminate();bot('ike-enable')
menu=bot('ipsec-menu')['result'];check('client-menu-renders-with-new-button',(menu['ikev2_auto'],menu['ikev2_buttons'],menu['fits']),(True,9,True))
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}))
raise SystemExit(0 if all(x['passed'] for x in results) else 1)
