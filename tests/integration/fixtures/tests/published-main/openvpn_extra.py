#!/usr/bin/env python3
import json, os, pathlib, re, subprocess, time
ROOT=pathlib.Path('/opt/vpnbot-hosted-ci/stand');OUT=ROOT/'results/openvpn-extra';OUT.mkdir(mode=0o700,exist_ok=True)
os.umask(0o077);C='vpnbot-audit-ovpnclient';results=[]
def run(*a,timeout=45): return subprocess.run(a,capture_output=True,text=True,timeout=timeout)
def exe(*a,timeout=45): return run('docker','exec',C,*a,timeout=timeout)
def bot(*a):
 r=run('docker','exec','php-audit','php','/tmp/audit-driver.php',*a,timeout=120);r.check_returncode();return json.loads(r.stdout)['result']
def check(n,a,e=True):
 ok=a==e;results.append(dict(name=n,passed=ok,actual=a,expected=e));(OUT/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if ok else 'FAIL ')+n,flush=True)
def save(n,r): (OUT/(n+'.log')).write_text(r.stdout+r.stderr)
def stop(): exe('pkill','openvpn');time.sleep(.3)
def hook_state():
 r=run('docker','exec','openvpn-audit','python3','-c',
       'import json;v=json.load(open("/etc/openvpn/traffic.json"));s=[x for x in v.get("sessions",{}).values() if x.get("cn")=="auditov"];'
       'print(json.dumps({"hook":v.get("hook_version"),"closed":sum(bool(x.get("closed")) for x in s),"live":len(v.get("users",{}).get("auditov",{}).get("live",{}))}))')
 r.check_returncode();return json.loads(r.stdout)
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
 # В режиме udp+tcp строк remote две, и протокол записан в каждой.
 text=re.sub(r'^remote \S+ (\d+)( \S+)?$',r'remote 10.10.0.19 \1\2',text,flags=re.M)
 p=OUT/'client.ovpn';p.write_text(text);run('docker','cp',str(p),C+':/tmp/audit.ovpn').check_returncode()
def link(): return ' '.join(re.findall(r'(UDPv4|TCPv4_CLIENT) link remote',exe('cat','/tmp/audit-openvpn.log').stdout)[-1:])
def routes(): return exe('ip','-4','route','show','dev','tun0').stdout
def offline():
 for _ in range(60):
  if not bot('ovpn-status')['online']:return True
  time.sleep(.5)
 return False
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
 # Третье состояние переключателя: сервер слушает UDP и TCP сразу, клиент
 # сам переходит на TCP, когда UDP не проходит.
 check('bot-switch-udp-tcp',bot('ovpn-proto'),{'proto':'udp4','listen':'udp+tcp'})
 profile();check('dual-profile-has-both-remotes',len(re.findall(r'(?m)^remote 10\.10\.0\.19 \d+ (?:udp4|tcp4)$',(OUT/'client.ovpn').read_text())),2)
 check('dual-prefers-udp',(connect('dual-udp'),link()),(True,'UDPv4'));traffic('dual-udp-https')
 # UDP «не проходит»: первый адрес профиля уводится на порт, где сервер не слушает.
 dead=OUT/'client-udp-dead.ovpn';dead.write_text(re.sub(r'(?m)^(remote 10\.10\.0\.19) \d+ udp4$',r'\1 9 udp4',(OUT/'client.ovpn').read_text()))
 run('docker','cp',str(dead),C+':/tmp/audit.ovpn').check_returncode()
 check('dual-falls-back-to-tcp',(connect('dual-tcp'),link()),(True,'TCPv4_CLIENT'));traffic('dual-tcp-https')
 # Тот же режим снаружи приходит через nginx сборки (upstream 10.10.0.10): бот
 # обязан открыть там оба протокола, иначе запасной TCP работал бы только в стенде.
 for _ in range(30):
  if exe('sh','-c','nc -z -w1 10.10.0.10 1194').returncode==0:break
  time.sleep(.5)
 for label,source,expect in (('udp',OUT/'client.ovpn','UDPv4'),('tcp',dead,'TCPv4_CLIENT')):
  via=OUT/('client-nginx-'+label+'.ovpn');via.write_text(source.read_text().replace('remote 10.10.0.19 ','remote 10.10.0.10 '))
  run('docker','cp',str(via),C+':/tmp/audit.ovpn').check_returncode()
  check('dual-through-nginx-'+label,(connect('nginx-'+label),link()),(True,expect));traffic('dual-through-nginx-'+label+'-https')
 check('bot-switch-udp',bot('ovpn-proto'),{'proto':'udp4','listen':'udp'})
 profile();check('udp-after-three-switches',connect('udp-final'));traffic('udp-final-https')
 # Выборочная маршрутизация: шлюз клиента не меняется, приходят только заданные сети и путь к DNS.
 check('full-tunnel-pushes-gateway','0.0.0.0/1' in routes())
 check('bot-split-mode',bot('ovpn-gateway')['full'],False)
 check('bot-sets-networks',bot('ovpn-routes','198.51.100.77/24 203.0.113.9')['routes'],['198.51.100.0/24','203.0.113.9/32'])
 check('split-handshake',connect('split'));table=routes()
 check('split-keeps-client-gateway','0.0.0.0/1' not in table and not re.search(r'(?m)^default ',table))
 check('split-pushes-networks-and-dns',all(net in table for net in ('198.51.100.0/24','203.0.113.9','10.10.0.5')))
 bot('ovpn-routes','-');check('bot-full-tunnel-again',bot('ovpn-gateway')['full'])
 # MSS: сервер запускается с mssfix и принимает клиента; затем возврат к умолчанию.
 check('bot-sets-mss',bot('ovpn-mss')['mss'],1360);check('mss-handshake',connect('mss'));traffic('mss-https')
 check('full-tunnel-restored','0.0.0.0/1' in routes())
 check('bot-mss-cycle',[bot('ovpn-mss')['mss'] for _ in range(3)],[1280,1200,0])
 # Учёт трафика: счётчик растёт при живой сессии, переживает отключение и сбрасывается.
 check('default-handshake',connect('traffic'));traffic('counted-https')
 for _ in range(60):
  used=bot('ovpn-traffic')
  if used['rx']+used['tx']>0:break
  time.sleep(.5)
 check('traffic-is-counted',used['rx']>0 and used['tx']>0)
 # Сессию закрывает сам сервер (блокировка): иначе он ждал бы пропавшего клиента минуту.
 bot('ovpn-disable');stop();check('session-ends',offline());kept=bot('ovpn-traffic')
 check('traffic-survives-disconnect',kept['rx']>=used['rx'] and kept['tx']>=used['tx'])
 state=hook_state();check('disconnect-hook-closed-durable-session',state['hook']==1 and state['closed']>0 and state['live']==0)
 bot('ovpn-enable')
 # Лимит: клиент блокируется, включить его нельзя, пока лимит исчерпан.
 check('limit-blocks-client',bot('ovpn-limit','1')['disabled']);check('limited-login-rejected',connect('limited'),False)
 bot('ovpn-enable');check('limited-client-stays-blocked',bot('ovpn-traffic')['disabled'])
 check('reset-clears-counter',(lambda t:t['rx']+t['tx'])(bot('ovpn-traffic-reset')),0)
 bot('ovpn-limit','0');bot('ovpn-enable');check('unlimited-login-reconnects',connect('unlimited'))
 # Перевыпуск: прежний профиль отвергается, новый подключается.
 old=(OUT/'client.ovpn').read_text()
 check('bot-reissues-certificate',bot('ovpn-renew'),{'reissued':True,'listed':True})
 check('reissued-old-profile-rejected',connect('old-profile'),False)
 profile();check('reissued-profile-differs',(OUT/'client.ovpn').read_text()!=old)
 check('reissued-profile-handshake',connect('reissued'));traffic('reissued-https')
 menu=bot('ovpn-menu');check('menus-and-help-render',menu,{'main':True,'client':True,'help':8})
finally:
 stop();bot('ovpn-limit','0');bot('ovpn-enable')
print(json.dumps({'passed':sum(r['passed'] for r in results),'total':len(results)}))
raise SystemExit(0 if all(r['passed'] for r in results) else 1)
