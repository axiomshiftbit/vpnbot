#!/usr/bin/env python3
import json,os,pathlib,subprocess,time
os.umask(0o077);R=pathlib.Path('/opt/vpnbot-hosted-ci/stand');O=R/'results/ssh-host-keys';O.mkdir(mode=0o700,exist_ok=True);results=[]
SERVICES=['up','ng','service','wg','wg1','ad','telemt','xr','oc','np','wp','proxy','ss','dnstt','ovpn','ipsec','tt','hy']
def run(*a,timeout=60):return subprocess.run(list(map(str,a)),capture_output=True,text=True,timeout=timeout)
def check(n,v):results.append({'name':n,'passed':bool(v)});(O/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if v else 'FAIL ')+n,flush=True)
def probe(*services):
 r=run('docker','exec','php-audit','php','/tmp/ssh-host-key.php',*services,timeout=180);r.check_returncode();v=json.loads(r.stdout)
 (O/'last-probe.json').write_text(json.dumps(v,indent=2));return v
def sshd(container,*command):return run('docker','exec',container,'sh','-c',' '.join(command))
# sshd отдаёт ключ, загруженный при старте: после замены файла его перечитывает SIGHUP.
RELOAD='kill -HUP "$(pgrep -o -x sshd)"'
run('docker','cp','/opt/vpnbot-hosted-ci/suite/ssh_host_key.php','php-audit:/tmp/ssh-host-key.php').check_returncode()
v=probe(*SERVICES);check('no-PHP-warnings',v['warning_count']==0);check('keys-issued-strict-mode',v['strict'])
live=[s for s in SERVICES if v['result'][s]['reachable']]
check('enough-services-running',len(live)>=12)
for s in live:
 check(s+'-accepted-with-its-own-key',v['result'][s]['ok'] and not v['result'][s]['failed'])
 check(s+'-key-known-to-the-bot',v['result'][s]['pinned'])
keys={}
for s in live:
 if s=='dnstt':continue
 p=R/'bot/ssh/hosts'/s/'ssh_host_ed25519_key'
 check(s+'-private-key-mode',p.is_file() and (p.stat().st_mode&0o777)==0o600);keys[s]=p.with_suffix('.pub').read_text().split()[1]
check('every-service-has-a-different-key',len(set(keys.values()))==len(keys))
# Сосед получает только свой ключ: каталога со всеми ключами в сервисе нет.
r=run('docker','exec','xray-audit','sh','-c','ls /hostkey; ls /ssh');check('service-sees-only-its-own-key',r.stdout.split()==['ssh_host_ed25519_key','ssh_host_ed25519_key.pub','key.pub'])
r=run('docker','exec','xray-audit','sh','-c','touch /hostkey/x');check('key-mount-is-read-only',r.returncode!=0)
# Подмена: в контейнере xray поднимается sshd с другим ключом — так выглядел бы
# чужой узел, ответивший вместо сервиса.
try:
 r=sshd('xray-audit','rm -f /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.pub','&&','ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key','&&',RELOAD)
 check('impostor-key-installed',r.returncode==0);time.sleep(1.5)
 v=probe('xr','ng');check('impostor-rejected',v['result']['xr']['reachable'] and not v['result']['xr']['ok'] and v['result']['xr']['failed'])
 check('other-service-unaffected',v['result']['ng']['ok'])
 # Ключ соседа тоже не годится: сервис не может выдать себя за другой.
 other=R/'bot/ssh/hosts/ng/ssh_host_ed25519_key'
 run('docker','cp',other,'xray-audit:/etc/ssh/ssh_host_ed25519_key').check_returncode();run('docker','cp',str(other)+'.pub','xray-audit:/etc/ssh/ssh_host_ed25519_key.pub').check_returncode()
 r=sshd('xray-audit','chown root:root /etc/ssh/ssh_host_ed25519_key*','&&','chmod 600 /etc/ssh/ssh_host_ed25519_key','&&',RELOAD);check('neighbour-key-installed',r.returncode==0);time.sleep(1.5)
 v=probe('xr');check('neighbour-key-rejected',v['result']['xr']['reachable'] and not v['result']['xr']['ok'] and v['result']['xr']['failed'])
finally:
 r=sshd('xray-audit','cp -p /hostkey/ssh_host_ed25519_key /hostkey/ssh_host_ed25519_key.pub /etc/ssh/','&&',RELOAD);check('own-key-restored',r.returncode==0);time.sleep(1.5)
v=probe('xr');check('accepted-again-after-restore',v['result']['xr']['ok'] and not v['result']['xr']['failed'])
# Пересоздание контейнера ключ не меняет: бот узнаёт сервис без своего перезапуска.
before=keys.get('ss')
if before:
 r=subprocess.run(['python3','scripts/protocol_modules.py','compose','up','-d','--no-deps','--force-recreate','--no-build','--pull','never','ss'],cwd=R/'bot',capture_output=True,text=True,timeout=120)
 (O/'recreate.log').write_text(r.stdout+r.stderr);check('recreate',r.returncode==0)
 ok=False
 for attempt in range(30):
  v=probe('ss')
  if v['result']['ss']['ok']:ok=True;break
  time.sleep(1)
 check('recreated-service-keeps-its-key',ok and (R/'bot/ssh/hosts/ss/ssh_host_ed25519_key.pub').read_text().split()[1]==before)
def wait_ok(service,seconds=60):
 for attempt in range(seconds):
  if probe(service)['result'][service]['ok']:return True
  time.sleep(1)
 return False
def public(service):
 p=R/'bot/ssh/hosts'/service/'ssh_host_ed25519_key.pub';return p.read_text().split()[1] if p.is_file() and p.stat().st_size else None
if before:
 # Перезапуск контейнера без пересоздания: ключ тот же.
 check('restart',run('docker','restart','shadowsocks-audit',timeout=90).returncode==0)
 check('restarted-service-keeps-its-key',wait_ok('ss') and public('ss')==before)
 # Ключ сервиса утрачен. Сервис при старте ждёт ключ от php и sshd не поднимает:
 # со случайным ключом бот его всё равно не принял бы.
 for suffix in ('','.pub'):(R/'bot/ssh/hosts/ss'/('ssh_host_ed25519_key'+suffix)).unlink()
 others={s:public(s) for s in live if s not in ('ss','dnstt')}
 run('docker','restart','shadowsocks-audit',timeout=90);time.sleep(6)
 v=probe('ss');check('service-without-a-key-waits-for-php',not v['result']['ss']['reachable'] and not v['result']['ss']['ok'])
 # Перезапуск php: утраченный ключ выдаётся заново, остальные не меняются.
 check('php-restart',run('docker','restart','php-audit',timeout=120).returncode==0)
 healthy=False
 for attempt in range(180):
  if run('docker','inspect','--format','{{.State.Health.Status}}','php-audit').stdout.strip()=='healthy':healthy=True;break
  time.sleep(1)
 check('php-healthy-after-restart',healthy)
 check('lost-key-reissued',public('ss') not in (None,before))
 check('waiting-service-starts-with-the-new-key',wait_ok('ss',90))
 check('php-restart-keeps-other-keys',{s:public(s) for s in others}==others)
 v=probe(*others);check('running-services-still-accepted-after-php-restart',all(v['result'][s]['ok'] for s in others))
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}))
raise SystemExit(0 if all(x['passed'] for x in results) else 1)
