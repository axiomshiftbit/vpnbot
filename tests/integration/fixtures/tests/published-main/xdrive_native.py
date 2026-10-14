#!/usr/bin/env python3
"""XDRIVE на живых контейнерах: настоящий сервер Xray бота, настоящий клиент Xray
и хранилище WebDAV внутри стенда. Клиент и сервер встречаются только в папке
хранилища; внешние сервисы не используются."""
import json,os,pathlib,subprocess,time
os.umask(0o077);R=pathlib.Path('/opt/vpnbot-hosted-ci/stand');O=R/'results/xdrive-native';O.mkdir(mode=0o700,exist_ok=True);results=[]
C='vpnbot-audit-ssclient';TARGET='vpnbot-protocol-target';NET='vpnbot-protocol-test'
# Узел-цель живёт в сети с непривилегированными адресами: внутренние адреса
# бот для хранилища не принимает, а ядро не пускает к ним пользователей.
DAV='http://11.77.0.2:8098';FOLDER='vpnbot-xdrive';LOGIN='disk-user';PASSWORD='app-pass-'+os.urandom(6).hex()
SOCKS=15510
def run(*a,timeout=60):return subprocess.run(list(map(str,a)),capture_output=True,text=True,timeout=timeout)
def check(n,v):results.append({'name':n,'passed':bool(v)});(O/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if v else 'FAIL ')+n,flush=True)
def bot(*a):
 r=run('docker','exec','php-audit','php','/tmp/audit-driver.php',*a,timeout=180);r.check_returncode();j=json.loads(r.stdout)
 (O/('bot-'+a[0]+'.json')).write_text(json.dumps({k:v for k,v in j.items() if k!='result'}|{'result_keys':sorted(j['result'])}));check(a[0]+'-no-PHP-warnings',not j['warnings']);return j['result']
def exe(*a,timeout=60):return run('docker','exec',C,*a,timeout=timeout)
def stop_client():exe('pkill','-f','/tmp/xdrive-xray');time.sleep(.3)
def start_client(profile):
 stop_client();p=json.loads(profile.read_text())
 p['inbounds']=[{'listen':'127.0.0.1','port':SOCKS,'protocol':'socks'}];local=O/'client.json';local.write_text(json.dumps(p))
 run('docker','cp',local,C+':/tmp/xdrive-client.json').check_returncode()
 run('docker','exec','-d',C,'sh','-c','/tmp/xdrive-xray run -c /tmp/xdrive-client.json >/tmp/xdrive-client.log 2>&1').check_returncode();time.sleep(2)
def fetch(path='/',limit=25):
 r=exe('curl','--socks5-hostname','127.0.0.1:'+str(SOCKS),'--noproxy','','-sS','-o','/tmp/xdrive-out','-w','%{http_code} %{size_download}','--max-time',limit,'http://11.77.0.2:8081'+path,timeout=limit+20)
 parts=(r.stdout.split()+['000','0'])[:2];return parts[0],int(float(parts[1]))
def stored():
 r=run('docker','exec',TARGET,'sh','-c','cat /tmp/xdrive-dav/'+FOLDER+'/* 2>/dev/null | od -An -c | tr -d " \\n"',timeout=30);return r.stdout
connected=[]
try:
 # Хранилище: WebDAV в контейнере-цели, папка создана заранее, как в настоящем сервисе.
 run('docker','cp','/opt/vpnbot-hosted-ci/xdrive/webdav_server.py',TARGET+':/tmp/xdrive-webdav.py').check_returncode()
 run('docker','exec',TARGET,'sh','-c','rm -rf /tmp/xdrive-dav && mkdir -p /tmp/xdrive-dav/'+FOLDER).check_returncode()
 run('docker','exec','-d',TARGET,'python3','/tmp/xdrive-webdav.py','/tmp/xdrive-dav','0.0.0.0','8098',LOGIN,PASSWORD).check_returncode()
 for name in ('xray-audit','php-audit',C):
  r=run('docker','network','connect','--gw-priority','-1',NET,name)
  if r.returncode==0:connected.append(name)
 check('storage-network-attached',len(connected)==3);time.sleep(1.5)
 run('docker','cp','/opt/vpnbot-hosted-ci/tests/xray',C+':/tmp/xdrive-xray').check_returncode()
 before=bot('xdrive-state');check('disabled-before-the-test',before['inbounds']==0 and not before['active'])
 # Включение теми же действиями, что из меню.
 state=bot('xdrive-enable',DAV,FOLDER,LOGIN,PASSWORD)
 check('enabled-without-error',state['error']=='' and state['active'] and state['inbounds']==1)
 check('same-users-as-the-main-inbound',state['clients']==state['main'] and len(state['clients'])>=1)
 check('inbound-is-always-encrypted',state['encrypted'])
 check('selected-core-supports-the-transport',state['core_ready'])
 check('storage-probe-passes',bot('xdrive-probe')['error']=='')
 menu=bot('xdrive-menu');check('menu-hides-the-storage-password',menu['shown'] and menu['secret_hidden'] and menu['problems']==[])
 check('xray-running-after-enable',run('docker','exec','xray-audit','sh','-c','pgrep -f "[x]ray run" >/dev/null').returncode==0)
 config=json.loads((R/'bot/config/xray.json').read_text());inbound=[i for i in config['inbounds'] if i.get('tag')=='xdrive']
 check('inbound-written-to-xray-json',len(inbound)==1 and inbound[0]['streamSettings']['method']=='xdrive' and config['inbounds'][0].get('tag')!='xdrive')
 guarded=[t for rule in config['routing']['rules'] for t in (rule.get('inboundTag') or [])]
 check('internal-network-guard-covers-xdrive','xdrive' in guarded)
 # Профиль пользователя и настоящий обмен через хранилище.
 for old in (R/'bot/logs/audit-files').glob('xdrive-*.json'):old.unlink()
 files=bot('xdrive-profile','0')['files'];check('profile-sent-as-a-file',len(files)==1)
 profile=R/'bot/logs/audit-files'/files[0];text=profile.read_text()
 check('profile-is-for-one-user',sum(text.count(i['id']) for i in config['inbounds'][0]['settings']['clients'])==1)
 start_client(profile)
 code,size=fetch();check('page-through-the-storage',code=='200' and size>0)
 for name,url in [('docker-api','http://10.10.0.8:2375/version'),('panel','http://10.10.0.7:8090/'),('adguard-admin','http://10.10.0.5:80/')]:
  r=exe('curl','--socks5-hostname','127.0.0.1:'+str(SOCKS),'--noproxy','','-sS','--max-time','5',url,timeout=30)
  check('internal-'+name+'-isolated',r.returncode!=0 and not r.stdout)
 code,size=fetch('/large');check('large-answer-through-the-storage',code=='200' and size==len('VPNBot controlled payload\n')*40960)
 ok=0
 for attempt in range(5):ok+=fetch()[0]=='200'
 check('repeated-requests',ok==5)
 log=(R/'bot/logs/xray').read_text(errors='replace') if (R/'bot/logs/xray').is_file() else ''
 check('server-sees-the-user-on-the-xdrive-inbound','[xdrive >> ' in log and 'email: '+state['clients'][0] in log)
 # Во время обмена в папке лежат только зашифрованные данные.
 job=subprocess.Popen(['docker','exec',C,'curl','--socks5-hostname','127.0.0.1:'+str(SOCKS),'--noproxy','','-s','-o','/dev/null','--max-time','60','http://11.77.0.2:8081/stream'])
 seen=''
 for attempt in range(40):
  seen+=stored()
  if len(seen)>4000:break
  time.sleep(.25)
 job.kill();job.wait()
 check('exchange-files-observed-in-the-storage',len(seen)>400)
 check('storage-holds-no-plaintext','VPNBotcontrolledpayload' not in seen and 'XXXXXXXXXXXXXXXX' not in seen and '11.77.0.2' not in seen)
 # «Новые ключи»: прежний профиль перестаёт работать, новый работает.
 check('rotate-without-error',bot('xdrive-rotate')['error']=='');time.sleep(2)
 start_client(profile);code,size=fetch(limit=8);check('old-profile-rejected-after-rotation',code!='200')
 for old in (R/'bot/logs/audit-files').glob('xdrive-*.json'):old.unlink()
 files=bot('xdrive-profile','0')['files'];fresh=R/'bot/logs/audit-files'/files[0]
 check('new-profile-differs',fresh.read_text()!=text)
 start_client(fresh);code,size=fetch();check('new-profile-works',code=='200' and size>0)
 # Выключение: вход исчезает, остальной Xray продолжает работать.
 check('disable-without-error',bot('xdrive-disable')['error']=='')
 state=bot('xdrive-state');check('inbound-removed',state['inbounds']==0 and not state['active'])
 time.sleep(2);code,size=fetch(limit=8);check('profile-dead-after-disable',code!='200')
 check('xray-running-after-disable',run('docker','exec','xray-audit','sh','-c','pgrep -f "[x]ray run" >/dev/null').returncode==0)
 config=json.loads((R/'bot/config/xray.json').read_text())
 check('main-inbound-untouched',config['inbounds'][0].get('tag')!='xdrive' and len(config['inbounds'][0]['settings']['clients'])==len(state['main']))
finally:
 stop_client();run('docker','exec',TARGET,'pkill','-f','xdrive-webdav.py')
 try:bot('xdrive-disable')
 except Exception:pass
 for name in connected:run('docker','network','disconnect',NET,name)
 for old in (R/'bot/logs/audit-files').glob('xdrive-*.json'):old.unlink()
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}))
raise SystemExit(0 if all(x['passed'] for x in results) else 1)
