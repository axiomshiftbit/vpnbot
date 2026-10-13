#!/usr/bin/env python3
"""Файлы .dat на живых контейнерах: настоящий бот и настоящее ядро Xray,
источник файлов — HTTPS-сервер внутри стенда. Проверяются загрузка, сверка
суммы, категории, правила block/WARP в рабочем конфиге, обновление, отказы и
расписание. Внешние сервисы не используются."""
import hashlib,json,os,pathlib,subprocess,time
os.umask(0o077);R=pathlib.Path('/opt/vpnbot-hosted-ci/stand');O=R/'results/dat-routes';O.mkdir(mode=0o700,exist_ok=True);results=[]
TARGET='vpnbot-protocol-target';NET='vpnbot-protocol-test'
# Адрес из сети с непривилегированными адресами: внутренние адреса бот как
# источник не принимает (та же защита, что у внешних подписок).
BASE='https://11.77.0.2:8449';SRC='/tmp/dat-src';TRUST=''
def run(*a,timeout=60):return subprocess.run(list(map(str,a)),capture_output=True,text=True,timeout=timeout)
def check(n,v):results.append({'name':n,'passed':bool(v)});(O/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if v else 'FAIL ')+n,flush=True)
calls=0
def bot(*a):
 global calls;calls+=1
 r=run('docker','exec','php-audit','php','/tmp/audit-driver.php',*a,timeout=240)
 if r.returncode not in (0,91):raise RuntimeError('bot '+a[0]+' failed: '+r.stderr[-300:])
 j=json.loads(r.stdout);(O/('bot-%02d-%s.json'%(calls,a[0]))).write_text(json.dumps(j,ensure_ascii=False,indent=1))
 if j['warnings']:check(a[0]+'-no-PHP-warnings',False)
 return j['result']
def said(state,text):return any(text in m for m in state['messages'])
# Наименьшие настоящие файлы формата ядра: GeoSiteList и GeoIPList.
def varint(n):
 out=b''
 while True:
  b=n&0x7f;n>>=7
  if n:out+=bytes([b|0x80])
  else:return out+bytes([b])
def field(number,payload):return bytes([number<<3|2])+varint(len(payload))+payload
def geosite(categories):
 return b''.join(field(1,field(1,code.encode())+b''.join(field(2,b'\x08\x02'+field(2,d.encode())) for d in domains)) for code,domains in categories.items())
def geoip(categories):
 return b''.join(field(1,field(1,code.encode())+b''.join(field(2,field(1,bytes(map(int,ip.split('.'))))+b'\x10'+varint(prefix)) for ip,prefix in nets)) for code,nets in categories.items())
def publish(name,data):
 local=O/('src-'+name);local.write_bytes(data)
 run('docker','cp',local,TARGET+':'+SRC+'/'+name).check_returncode();return hashlib.sha256(data).hexdigest()
def remove(name):run('docker','exec',TARGET,'rm','-f',SRC+'/'+name)
def requests():return run('docker','exec',TARGET,'cat',SRC+'/requests.log').stdout.splitlines()
def xray_alive():return run('docker','exec','xray-audit','sh','-c','pgrep -f "[x]ray run" >/dev/null').returncode==0
SITES={'ADS':['ads.example.org','track.example.net'],'VIDEO':['video.example.org']}
NETS={'LAN':[('198.51.100.0',24)],'CDN':[('203.0.113.0',24)]}
connected=False
try:
 # Источник: сертификат на адрес узла, сервер в контейнере-цели.
 run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-keyout',O/'key.pem','-out',O/'ca.pem','-subj','/CN=11.77.0.2','-addext','subjectAltName=IP:11.77.0.2').check_returncode()
 (O/'ca.pem').chmod(0o644)
 # PHP стенда доверяет своему файлу CA из php.ini и каталогу /etc/ssl/certs:
 # сертификат источника кладём в каталог под именем-хешем, как это делает
 # c_rehash, и убираем в конце.
 TRUST='/etc/ssl/certs/'+run('openssl','x509','-hash','-noout','-in',O/'ca.pem').stdout.strip()+'.0'
 run('docker','cp',O/'ca.pem','php-audit:'+TRUST).check_returncode()
 run('docker','exec',TARGET,'sh','-c','rm -rf '+SRC+' && mkdir -p '+SRC).check_returncode()
 for local,remote in ((O/'ca.pem','/tmp/dat-cert.pem'),(O/'key.pem','/tmp/dat-key.pem'),(pathlib.Path('/opt/vpnbot-hosted-ci/dat/dat_server.py'),'/tmp/dat-server.py')):
  run('docker','cp',local,TARGET+':'+remote).check_returncode()
 run('docker','exec','-d',TARGET,'python3','/tmp/dat-server.py',SRC,'0.0.0.0','8449','/tmp/dat-cert.pem','/tmp/dat-key.pem').check_returncode()
 connected=run('docker','network','connect','--gw-priority','-1',NET,'php-audit').returncode==0
 check('source-network-attached',connected);time.sleep(1.5)
 probe=run('docker','exec','php-audit','curl','-sS','--cacert',TRUST,'-o','/dev/null','-w','%{http_code}',BASE+'/requests.log')
 check('source-answers-over-https',probe.stdout.strip()=='404')
 sites_sha=publish('sites.dat',geosite(SITES));publish('nets.dat',geoip(NETS));publish('geosite.dat',geosite({'ADS':['core.example.org']}))
 publish('page.dat',b'<html>502 Bad Gateway</html>')
 before=bot('dat-reset');check('clean-before-the-test',before['files']=={} and before['datlist']=={} and before['schedule']=={})

 # Реестр: добавление, сверка суммы, категории, отказы с причиной.
 s=bot('dat-add','sites.dat:%s/sites.dat|nets.dat:%s/nets.dat'%(BASE,BASE))
 check('two-sources-downloaded',set(s['files'])=={'sites.dat','nets.dat'} and len(s['datlist'])==2 and s['files']['sites.dat']['sha']==sites_sha)
 check('published-sums-verified',all(f['verified'] and f['error']=='' for f in s['files'].values()))
 check('categories-parsed',s['files']['sites.dat']['cats']==['ads','video'] and s['files']['nets.dat']['cats']==['lan','cdn'])
 check('menu-shows-file-status',said(s,'sites.dat — ') and said(s,'sha256 ✅'))
 s=bot('dat-add','nofile.dat:%s/nofile.dat'%BASE)
 check('missing-file-rejected-with-reason',len(s['datlist'])==2 and said(s,'nofile.dat') and said(s,'http 404'))
 s=bot('dat-add','page.dat:%s/page.dat'%BASE)
 check('error-page-rejected-with-reason',len(s['datlist'])==2 and said(s,'не похоже на .dat'))
 s=bot('dat-add','sites.dat:%s/nets.dat'%BASE)
 check('name-conflict-rejected',len(s['datlist'])==2 and said(s,'имя занято') and s['files']['sites.dat']['sha']==sites_sha)
 check('rejected-edits-leave-no-files',set(s['files'])=={'sites.dat','nets.dat'} and s['stray']==[])
 s=bot('dat-cats','sites.dat','vid');check('category-search',said(s,'<code>video</code>') and not said(s,'<code>ads</code>'))

 # Правила: настоящее ядро принимает конфиг и продолжает работать.
 s=bot('dat-list','blocklist','ext:sites.dat:ads','on')
 check('block-rule-accepted',s['ok'] is True and '"ext:sites.dat:ads"' in s['rules'] and '"outboundTag":"block"' in s['rules'])
 check('xray-running-with-the-rule',xray_alive())
 s=bot('dat-list','warplist','extip:nets.dat:lan','on')
 check('warp-ip-rule-accepted',s['ok'] is True and '"ip":["ext:nets.dat:lan"]' in s['rules'])
 s=bot('dat-list','blocklist','ext:SITES.DAT:video','on')
 check('file-name-case-resolved',s['ok'] is True and '"ext:sites.dat:video"' in s['rules'])
 s=bot('dat-list','blocklist','ext:sites.dat:nope','on')
 check('unknown-category-rejected',s['ok'] is False and said(s,'нет категории nope') and 'ext:sites.dat:nope' not in s['blocklist'])
 s=bot('dat-list','blocklist','ext:absent.dat:ads','on')
 check('unknown-file-rejected',s['ok'] is False and said(s,'нет файла absent.dat'))
 # Встроенное имя geosite.dat со своим источником: запись geosite: работает
 # без обращения к внешней сети.
 s=bot('dat-add','geosite.dat:%s/geosite.dat'%BASE)
 check('own-source-for-the-built-in-name','geosite.dat' in s['files'] and len(s['datlist'])==3)
 s=bot('dat-list','blocklist','geosite:ads','on');check('geosite-rule-accepted',s['ok'] is True and '"geosite:ads"' in s['rules'])
 s=bot('dat-list','blocklist','geosite:nope','on');check('geosite-unknown-category-rejected',s['ok'] is False and said(s,'нет категории nope'))
 check('xray-running-after-the-rules',xray_alive())

 # Обновление: без изменений — условный запрос; новая версия — замена.
 mark=len(requests());mtime=s['files']['sites.dat']['mtime']
 s=bot('dat-refresh');log=requests()[mark:]
 check('unchanged-refresh-uses-304',[l for l in log if l.startswith('304 ')]!=[] and not [l for l in log if l.startswith('200 ')] and s['files']['sites.dat']['mtime']==mtime)
 check('refresh-records-success',s['schedule'].get('dat_update_last_success',0)>=s['now']-60 and not said(s,'ошибки загрузки'))
 newer=dict(SITES,GAMES=['games.example.org']);new_sha=publish('sites.dat',geosite(newer))
 s=bot('dat-refresh')
 check('new-version-installed',s['files']['sites.dat']['sha']==new_sha and s['files']['sites.dat']['cats']==['ads','video','games'] and s['files']['sites.dat']['verified'])
 check('xray-running-after-the-update',xray_alive() and '"ext:sites.dat:ads"' in s['rules'])
 # Версия без используемой категории: ядро её не примет, прежний файл остаётся.
 publish('sites.dat',geosite({'GAMES':['games.example.org']}))
 s=bot('dat-refresh')
 check('harmful-version-rejected-by-the-core',s['files']['sites.dat']['sha']==new_sha and said(s,'Xray отклонил') and 'Xray отклонил' in s['files']['sites.dat']['error'])
 # Сумма рядом не совпала с файлом: подмена содержимого не проходит.
 publish('sites.dat',geosite(dict(newer,EXTRA=['extra.example.org'])));publish('sites.dat.sha256sum',('0'*64+'  sites.dat\n').encode())
 s=bot('dat-refresh')
 check('checksum-mismatch-rejected',s['files']['sites.dat']['sha']==new_sha and said(s,'sha256'))
 remove('sites.dat.sha256sum');publish('sites.dat',geosite(newer))
 s=bot('dat-refresh');check('status-clean-after-recovery',s['files']['sites.dat']['error']=='' and s['stray']==[])
 check('xray-running-after-the-failures',xray_alive())

 # Расписание: свой интервал, плановый запуск, отказ и возврат.
 s=bot('dat-interval','90m');check('custom-interval-saved',s['schedule'].get('dat_update_interval')==5400)
 s=bot('dat-cron')
 check('scheduled-run-succeeds',abs(s['schedule'].get('dat_update_next',0)-s['now']-5400)<120 and s['schedule'].get('dat_update_last_success',0)>=s['now']-60 and not s['schedule'].get('dat_update_failed'))
 remove('nets.dat')
 s=bot('dat-cron')
 check('failed-run-retries-in-an-hour',abs(s['schedule'].get('dat_update_next',0)-s['now']-3600)<120 and s['schedule'].get('dat_update_failed')==1)
 check('failed-run-reported-once',s['admins']==0 or (said(s,'автообновление не удалось') and said(s,'nets.dat — http 404')))
 check('failed-run-keeps-the-files','nets.dat' in s['files'])
 s=bot('dat-cron');check('repeated-failure-is-silent',not said(s,'автообновление не удалось'))
 publish('nets.dat',geoip(NETS))
 s=bot('dat-cron')
 check('recovery-reported',not s['schedule'].get('dat_update_failed') and (s['admins']==0 or said(s,'снова работает')))

 # Выключение источника с действующими правилами и возврат.
 s=bot('dat-list','datlist','sites.dat:%s/sites.dat'%BASE,'off')
 check('disabled-source-drops-its-rules',s['ok'] is True and 'sites.dat' not in s['files'] and 'ext:sites.dat' not in s['rules'] and said(s,'sites.dat — 2'))
 check('other-rules-stay','"geosite:ads"' in s['rules'] and '"ip":["ext:nets.dat:lan"]' in s['rules'] and xray_alive())
 s=bot('dat-list','datlist','sites.dat:%s/sites.dat'%BASE,'on')
 check('enabled-source-restores-its-rules',s['ok'] is True and 'sites.dat' in s['files'] and '"ext:sites.dat:ads"' in s['rules'] and '"ext:sites.dat:video"' in s['rules'])
finally:
 try:
  after=bot('dat-reset')
  check('stand-restored',after['files']=={} and after['datlist']=={} and after['schedule']=={} and 'ext:' not in after['rules'] and 'geosite:' not in after['rules'])
 except Exception:check('stand-restored',False)
 check('xray-running-at-the-end',xray_alive())
 run('docker','exec',TARGET,'pkill','-f','dat-server.py')
 if connected:run('docker','network','disconnect',NET,'php-audit')
 if TRUST:run('docker','exec','php-audit','rm','-f',TRUST)
 for path in (O/'ca.pem',O/'key.pem'):path.unlink(missing_ok=True)
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}))
raise SystemExit(0 if all(x['passed'] for x in results) else 1)
