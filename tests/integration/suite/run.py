#!/usr/bin/env python3
"""Disposable synthetic VPN fixture. Raw logs/backups never leave the runner."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,re,shutil,signal,subprocess,sys,time
os.umask(0o077)
p=argparse.ArgumentParser();p.add_argument('--checkout',type=Path,required=True);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--results',type=Path,required=True);a=p.parse_args()
B=Path('/opt/vpnbot-hosted-ci/stand/bot');R=Path('/opt/vpnbot-hosted-ci/tests');O=a.results
sys.path.insert(0,str(a.checkout/'scripts'));import image_bundle as ib
candidate=ib.read(a.manifest)
baseenv={k:os.environ[k] for k in ("PATH","HOME","LANG","LC_ALL","SHELL","TERM","TMPDIR") if k in os.environ}
for n in ('VPNBOT_BUNDLE_FILE','GHCR_TOKEN','GHCR_USER','GITHUB_TOKEN','GH_TOKEN'):baseenv.pop(n,None)
baseenv.update(VER='audit',COMPOSE_PROJECT_NAME='vpnbot-audit',COMPOSE_FILE='docker-compose.yml:compose.audit.yml:compose.migration.json:compose.fresh.json',COMPOSE_ENV_FILES='.env,override.env',VPNBOT_BUNDLE_FILE=str(O/'baseline.json'))
env=baseenv|{'VPNBOT_BUNDLE_FILE':str(O/'candidate.json')}
ib.atomic(O/'candidate.json',ib.canonical(candidate))
counts=dict.fromkeys(('unit','native','modules','backup_restore','update_rollback','faults','telegram_http'),0)
worker=None;restored=False;paths=[];mutated=False;retained=[]
def interrupted(signum,frame):raise InterruptedError('test interrupted')
signal.signal(signal.SIGTERM,interrupted)
transaction=Path('/opt/vpnbot-hosted-ci/transaction.json')
if transaction.exists():raise RuntimeError('unfinished previous test transaction; recover before retrying')
if 'TELEGRAM_API=tg-audit:8443' not in (B/'.env').read_text():raise RuntimeError('synthetic Telegram endpoint required')
if (B/'update/pipe').read_text().strip():raise RuntimeError('another update request is pending')
# The archive-based stand has no usable Git HEAD; keep an explicit immutable
# baseline manifest for both preflight and finally, just as normal stand startup.
baseline_bundle=ib.read('/opt/vpnbot-hosted-ci/active-test-bundle.json')
baseline_services=ib.SERVICES
ib.atomic(O/'baseline.json',ib.canonical(baseline_bundle))

def run(name,cmd,timeout=180,work=B,environ=None,good=True):
 print('START '+name,flush=True)
 with (O/(name+'.log')).open('wb') as out:
  q=subprocess.run(cmd,cwd=work,env=environ or env,stdout=out,stderr=subprocess.STDOUT,timeout=timeout)
 if good and q.returncode:raise RuntimeError(name+' exit '+str(q.returncode))
 return q.returncode

retries=[]
def twice(name,attempt):
 # Самостоятельный набор (свои контейнеры с уборкой в finally, на стенде и так
 # идёт не раз) при отказе повторяется один раз: случайный сетевой сбой не должен
 # стоить перезапуска всего стенда (~80 мин), устойчивая ошибка провалит обе
 # попытки. Тайм-аут (subprocess.TimeoutExpired) не повторяется.
 try:return attempt()
 except RuntimeError as error:print('RETRY '+name+': '+str(error),flush=True)
 if (O/(name+'.log')).exists():(O/(name+'.log')).replace(O/(name+'.attempt1.log'))
 retries.append(name);(O/'retries.json').write_text(json.dumps(retries))
 return attempt()

def capture(cmd,timeout=60,environ=None):
 q=subprocess.run(cmd,cwd=B,env=environ or env,capture_output=True,text=True,timeout=timeout)
 if q.returncode:raise RuntimeError('command failed: '+cmd[0])
 return q.stdout

def check(group,name,ok):
 print(('PASS ' if ok else 'FAIL ')+name,flush=True)
 if not ok:raise RuntimeError(name)
 counts[group]+=1
 (O/'partial.json').write_text(json.dumps(counts))

def containers():
 ids=capture(['docker','ps','-aq','--filter','label=com.docker.compose.project=vpnbot-audit']).split()
 data=json.loads(capture(['docker','inspect',*ids])) if ids else []
 return {d['Config']['Labels']['com.docker.compose.service']:d for d in data if d['Config']['Labels']['com.docker.compose.service']!='tg-audit'}

def ready():
 end=time.monotonic()+150
 while time.monotonic()<end:
  try:ds=containers()
  except RuntimeError:
   time.sleep(1);continue
  if all(k in ds and ds[k]['State']['Running'] and ds[k]['State'].get('Health',{}).get('Status')=='healthy' for k in ('php','ng')):return
  time.sleep(1)
 raise RuntimeError('frontend readiness timeout')

def stopworker():
 global worker
 run('stop-worker',['sh','scripts/stop_update.sh','update/update_pid'],environ=baseenv)
 if worker:
  try:worker.wait(timeout=15)
  except subprocess.TimeoutExpired:raise RuntimeError('test update worker did not stop')
  worker=None

def startworker(current):
 global worker
 with (O/'host-worker.log').open('ab') as out:
  worker=subprocess.Popen(['bash','update/update.sh'],cwd=B,env=current,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
 time.sleep(1)
 if worker.poll() is not None:raise RuntimeError('host worker failed to start')

def deploy(current,name):
 run(name,['python3','scripts/protocol_modules.py','compose','up','-d','--force-recreate'],timeout=400,environ=current)
 ready()

def drivers():
 for f,dst in [(R/'fresh-restore/restore-driver.php','audit-driver.php'),(R/'module-cycle.php','module-cycle.php'),(R/'telegram-http-e2e.php','telegram-http-e2e.php')]:
  capture(['docker','cp',str(f),'php-audit:/tmp/'+dst])

def bot(action):
 d=json.loads(capture(['docker','exec','php-audit','php','-d','error_reporting=-1','/tmp/audit-driver.php',action],timeout=300))
 if d['warnings']:raise RuntimeError('PHP warnings: '+action)
 return d['result']

def identities():
 names=['config/clients.json','config/clients1.json','ssh/key','ssh/key.pub','certs/self_private','certs/self_public']
 return {n:hashlib.sha256(ib.canonical(json.loads((B/n).read_text())) if n.endswith('.json') else (B/n).read_bytes()).hexdigest() for n in names}

def php(code):return capture(['docker','exec','php-audit','php','-r',code]).strip()

def executable_mounts(data):
 roots=('/bin','/sbin','/lib','/lib64','/usr','/opt')
 return [m['Destination'] for m in data.get('Mounts',[]) if m['Destination']!='/opt/adguardhome/work' and any(m['Destination']==r or m['Destination'].startswith(r+'/') or r.startswith(m['Destination'].rstrip('/')+'/') for r in roots)]

def verify_images(expected,group):
 actual=containers()
 for service,image in expected.items():
  want=capture(['docker','image','inspect','--format','{{.Id}}',image]).strip()
  check(group,'exact-image-'+service,service in actual and actual[service]['Image']==want and actual[service]['State']['Running'] and not actual[service]['State']['OOMKilled'] and actual[service]['RestartCount']==0)
  check(group,'unmasked-executables-'+service,not executable_mounts(actual[service]))
 if 'hy' in expected:
  path='/usr/local/bin/hysteria'
  want=capture(['docker','run','--rm','--network=none','--entrypoint','sha256sum',expected['hy'],path]).split()[0]
  found=capture(['docker','exec',actual['hy']['Id'],'sha256sum',path]).split()[0]
  check(group,'running-hysteria-matches-image',want==found)


run('prepare-fixtures',[sys.executable,str(Path(__file__).with_name('prepare_fixture.py'))],timeout=120,environ=baseenv)
def core_logs():
 names={'php_error','requests_error','unit_error','upstream_error','nginx_error','xray','xray_stdout','telemt','adguard','caddy','shadowsocks','shadowsocks_proxy','wireguard','wireguard1','warp','hysteria'}
 return [p for p in (B/'logs').rglob('*') if p.is_file() and not p.is_symlink() and (p.suffix=='.log' or str(p.relative_to(B/'logs')) in names)]

before=containers();baseline={s:d['Image'] for s,d in before.items()}
check('faults','baseline-manifest-matches-running-images',set(baseline)==set(baseline_services) and all(capture(['docker','image','inspect','--format','{{.Id}}',baseline_bundle['images'][name]]).strip()==baseline[service] for service,name in baseline_services.items()))
baseline_compose=json.loads(capture(['python3','scripts/protocol_modules.py','compose','config','--format','json'],environ=baseenv))['services']
check('faults','baseline-compose-resolves-before-mutation',all(baseline_compose[service]['image']==baseline_bundle['images'][name] for service,name in baseline_services.items()))
pending_file=B/'update/image-bundle.pending.json'
old_pending=pending_file.read_bytes() if pending_file.exists() else None
baseline_flags=(B/'config/protocol-services.json').read_bytes()
(O/'original-module-settings.json').write_bytes(baseline_flags)
# Keep a readable code snapshot, separate from runtime state; rollback never
# restores an old client/usage backup over data written during this test.
tracked=subprocess.check_output(['git','ls-files','-z'],cwd=a.checkout).decode().split('\0')
for name in tracked:
 if not name or not (name.startswith(('app/','scripts/','update/')) or name in ('.env','docker-compose.yml','makefile')):continue
 if name=='app/config.php':raise RuntimeError('private runtime config entered Git')
 paths.append(name)
 src=B/name
 if src.is_file():
  dst=O/'old-code'/name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
ib.atomic(transaction,ib.canonical({'results':str(O),'paths':paths,'baseline':baseline}))
try:
 # Pin rollback images while the candidate is running, including against image GC.
 missing_images=any(subprocess.run(['docker','image','inspect',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode for image in candidate['images'].values())
 reserve=3*1024**3 if missing_images else 512*1024**2
 check('faults','test-host-disk-reserve',shutil.disk_usage(B).free >= reserve)
 for index,image in enumerate(sorted(set(baseline.values()))):
  name='vpnbot-ci-retain-'+str(candidate['run'])+'-'+str(index)
  capture(['docker','create','--name',name,'--network','none','--entrypoint','/bin/true',image]);retained.append(name)
 # Preload images before modifying services. A failed pull must not take down
 # the current deployment, even if some candidates are already downloaded.
 for name,image in candidate['images'].items():run('preloaded-'+name,['docker','image','inspect',image],timeout=30)
 check('faults','post-pull-disk-reserve',shutil.disk_usage(B).free >= 512*1024**2)
 mutated=True
 stopworker();run('pause-cron',['docker','stop','service-audit'])
 for name in paths:
  dst=B/name;dst.parent.mkdir(parents=True,exist_ok=True)
  if (a.checkout/name).is_file():shutil.copy2(a.checkout/name,dst)
  else:dst.unlink(missing_ok=True)
 # Only this test fixture overrides the Telegram endpoint; all application,
 # supervisor and protocol code is the exact checkout being admitted.
 f=B/'.env';f.write_text(re.sub(r'^TELEGRAM_API=.*$', 'TELEGRAM_API=tg-audit:8443',f.read_text(),flags=re.M))
 ib.atomic(pending_file,ib.canonical(candidate))
 log_offsets={str(p):(p.stat().st_ino,p.stat().st_size) for p in core_logs()}
 candidate_started=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
 deploy(env,'deploy-candidate');startworker(env);drivers()
 verify_images({s:candidate['images'][im] for s,im in ib.SERVICES.items()},'native')
 for name in paths:
  if name=='.env':continue
  check('native','source-'+name,(B/name).read_bytes()==(a.checkout/name).read_bytes())
 # Check the cold-start DNS return route BEFORE module cycles can repair it.
 current=containers();oc_address=current['oc']['NetworkSettings']['Networks']['vpnbot-audit_default']['IPAddress']
 for _ in range(40):
  route=capture(['docker','exec',current['ad']['Id'],'ip','route','show','10.0.2.0/24'])
  if 'via '+oc_address+' ' in route:break
  time.sleep(.5)
 check('native','cold-start-OpenConnect-DNS-route','via '+oc_address+' ' in route)
 # Exercise PHP CLI/FreeUnit against the immutable runtime image.
 run('php-runtime',['docker','run','--rm','--network','none','--entrypoint','sh','-v',str(a.checkout/'tests/php_runtime_test.sh')+':/test.sh:ro','-v',str(a.checkout/'config/php.ini')+':/etc/php85/php.ini:ro',candidate['images']['php'],'/test.sh'])
 counts['unit']+=4
 unit=O/'unit';unit.mkdir()
 archive=subprocess.check_output(['git','archive','HEAD'],cwd=a.checkout)
 subprocess.run(['tar','-x','-C',str(unit)],input=archive,check=True)
 unitcode='''apk add --no-cache bash util-linux coreutils findutils make jq openssl php85-pcntl php85-sodium php85-tokenizer py3-yaml >/tmp/packages.log 2>&1
mkdir -p /logs
python3 -m unittest discover -s tests -p '*_test.py' || exit 1
python3 - <<'INNER'
import pathlib,subprocess,re,json
rows=[]
for f in sorted(pathlib.Path('tests').glob('*_test.php')):
 p=subprocess.run(['php','-d','error_reporting=-1','-d','error_log=/dev/stderr','-d','display_errors=1',str(f)],capture_output=True,text=True,timeout=150)
 bad=p.returncode!=0 or bool(re.search(r'(?:PHP )?(?:Warning|Deprecated|Fatal error):',p.stdout+p.stderr))
 rows.append({'file':f.name,'ok':not bad})
 if bad: print('FAIL',f.name,p.stdout,p.stderr)
pathlib.Path('/results/unit.json').write_text(json.dumps(rows))
raise SystemExit(any(not x['ok'] for x in rows))
INNER'''
 # Как у сервисов Compose: init убирает осиротевшие процессы после проверки
 # супервизоров, иначе pgrep видит зомби вместо перезапущенного ядра.
 run('unit-php85',['docker','run','--rm','--init','--name','vpnbot-ci-unit','-v',str(unit)+':/workspace','-v',str(O)+':/results','-v',str(R/'xray')+':/audit-xray:ro','-e','VLESS_TEST_XRAY=/audit-xray','-v',str(R/'xray-fork')+':/audit-xray-fork:ro','-e','XRAY_FORK_TEST_BINARY=/audit-xray-fork','-w','/workspace','--entrypoint','sh',candidate['images']['php'],'-ec',unitcode],timeout=1500)
 rows=json.loads((O/'unit.json').read_text());check('unit','all-PHP85-test-files',len(rows)>=121 and all(x['ok'] for x in rows));counts['unit']+=len(rows)
 php("require '/app/bot.php';$b=(new ReflectionClass('Bot'))->newInstanceWithoutConstructor();$b->cleanDocker();")
 for name,ref in candidate['images'].items():
  check('faults','cleanup-keeps-candidate-'+name,bool(capture(['docker','image','inspect','--format','{{.Id}}',ref])))
 # Both full off/on cycles, including shared IKEv2/L2TP and deleted TeleMT.
 (R/'module-cycle-results.json').unlink(missing_ok=True)
 run('module-cycles',['python3',str(R/'module-cycles.py')],timeout=1500)
 rows=json.loads((R/'module-cycle-results.json').read_text());check('modules','full-module-cycles',len(rows)==357 and all(x['ok'] for x in rows));counts['modules']+=len(rows)
 verify_images({s:candidate['images'][im] for s,im in ib.SERVICES.items()},'modules')
 # Regression found on a production server: settings/status say ON, Docker container vanished
 # during an external compose deployment. No toggle/settings change is sent.
 for service in ('telemt','oc','tt','ovpn'):
  prior=containers()[service]['Id'];capture(['docker','rm','-f',prior])
  end=time.monotonic()+95
  while time.monotonic()<end:
   d=containers().get(service)
   if d and d['Id']!=prior and d['State']['Running']:break
   time.sleep(.6)
  else:raise RuntimeError('missing enabled container was not recovered: '+service)
  check('faults','external-removal-recovered-'+service,True)
 time.sleep(6)
 def native(label):
  output=R/'published-main/results.json';output.unlink(missing_ok=True)
  # 25 наборов идут ~1300 с; запас — на повтор упавшего набора (published-main/run.py).
  run(label,['python3',str(R/'published-main/run.py')],timeout=2700)
  rows=json.loads(output.read_text())
  # Каталог наборов общий для обоих проходов: журнал первой попытки уносим в результаты с меткой прохода.
  for x in rows:
   if x.get('retried'):retries.append(label+'/'+x['case']);(R/'published-main'/(x['case']+'.attempt1.log')).replace(O/(label+'-'+x['case']+'.attempt1.log'));(O/'retries.json').write_text(json.dumps(retries))
  check('native',label+'-complete',len(rows)==25 and all(x['exit']==0 and x.get('passed',0)>0 and x['passed']==x['total'] for x in rows));counts['native']+=sum(x['total'] for x in rows)
  shutil.copy2(output,O/(label+'.json'))
  for name,script in [("warp-udp",'/opt/vpnbot-hosted-ci/warp-udp-native/run.py'),("nginx-transports","/opt/vpnbot-hosted-ci/nginx-transport-native.py"),("warp-modules","/opt/vpnbot-hosted-ci/warp-modules-native.py")]:
   def attempt(name=label+"-"+name,script=script):
    result=O/name
    run(name,["python3",script,str(result)],timeout=900)
    extra=json.loads((result/"results.json").read_text())
    check("native",name+"-complete",len(extra)>40 and all(r["passed"] for r in extra));counts["native"]+=len(extra)
   twice(label+"-"+name,attempt)
 native('native-before-restore')
 # Native backup roundtrip: change real saved client data, restore all sections,
 # then prove that the previously issued profiles still pass actual traffic.
 run('backup-pause-cron',['docker','stop','service-audit']);saved=bot('backup-save');check('backup_restore','full-export-sections',saved['sections']>=23)
 baseline_identity=identities()
 clients=B/'config/clients.json';v=json.loads(clients.read_text());first=next(iter(v)) if isinstance(v,dict) else 0
 v[first]['name']='CI changed before restore';clients.write_text(json.dumps(v))
 check('backup_restore','runtime-changed-before-restore',identities()!=baseline_identity)
 restored_result=bot('backup-restore');check('backup_restore','full-restore',restored_result.get('ok') and restored_result.get('error_messages')==0)
 check('backup_restore','restored-clients-and-identities',identities()==baseline_identity)
 run('backup-resume-cron',['docker','start','service-audit']);native('native-after-restore')
 # Optional native client probes use the established isolated target network.
 for service in ('masque',):
  d=containers()[service]
  if 'vpnbot-protocol-test' in d['NetworkSettings']['Networks']:
   capture(['docker','network','disconnect','vpnbot-protocol-test',d['Id']])
 (R/'published-optional-results.json').unlink(missing_ok=True)
 run('native-optional',['python3',str(R/'published-optional.py')],timeout=300)
 rows=json.loads((R/'published-optional-results.json').read_text());check('native','optional-HTTP-HTTPS-TCP-UDP',len(rows)==38 and all(x['ok'] for x in rows));counts['native']+=len(rows)
 run('naive-idle',['python3',str(Path(__file__).with_name('naive_idle.py'))],environ=env|{'VPNBOT_TEST_RESULTS':str(O)},timeout=140)
 rows=json.loads((O/'naive-idle.json').read_text());check('native','Naive75-seconds-idle',len(rows)==5 and all(x['ok'] for x in rows));counts['native']+=len(rows)
 run('naive-upgrade',['python3',str(Path('/opt/vpnbot-hosted-ci/naive-upgrade/run.py')),candidate['images']['np'],candidate['images']['php'],str(Path('/opt/vpnbot-hosted-ci/stand/bin/naive')),str(O/'naive-upgrade')],timeout=180)
 rows=json.loads((O/'naive-upgrade/results.json').read_text());check('native','Naive-H2-H3-auth-idle',len(rows)==15 and all(x['passed'] for x in rows));counts['native']+=len(rows)
 run('mieru-idle',['python3','/opt/vpnbot-hosted-ci/mieru-idle/run.py',str(a.checkout),candidate['images']['mieru'],candidate['images']['php'],'/opt/vpnbot-hosted-ci/stand/bin/mieru-previous',str(O/'mieru-idle')],timeout=150)
 rows=json.loads((O/'mieru-idle/results.json').read_text());check('native','Mieru-idle-old-client',len(rows)==5 and all(x['passed'] for x in rows));counts['native']+=len(rows)
 run('ocserv-upgrade',['python3','/opt/vpnbot-hosted-ci/ocserv-upgrade/run.py',candidate['images']['oc'],'vpnbot-hosted-clients:current',str(O/'ocserv-upgrade')],timeout=240)
 rows=json.loads((O/'ocserv-upgrade/results.json').read_text());check('native','ocserv-TLS13-DTLS-strict-config',len(rows)==15 and all(x['passed'] for x in rows));counts['native']+=len(rows)
 # Отдельные мини-стенды на настоящих ядрах проверяемых образов Telemt, MASQUE, Hysteria и snolc.
 for name,extra in [('telemt-native',[candidate['images']['telemt'],candidate['images']['php'],candidate['images']['ng']]),('masque-native',[candidate['images']['masque'],candidate['images']['php'],str(R/'xray')]),('hysteria-native',[candidate['images']['hysteria'],candidate['images']['php']]),('snolc-native',[candidate['images']['snolc'],candidate['images']['php']])]:
  def attempt(name=name,extra=extra):
   result=Path('/opt/vpnbot-hosted-ci')/name/'results.json';result.unlink(missing_ok=True)
   run(name,['python3',str(result.with_name('run.py')),str(a.checkout),*extra],timeout=1500)
   rows=json.loads(result.read_text());check('native',name+'-complete',bool(rows) and all(x['exit']==0 and x['total']>0 and x['passed']==x['total'] for x in rows));counts['native']+=sum(x['total'] for x in rows)
   shutil.copy2(result,O/(name+'.json'))
  twice(name,attempt)
 # FreeUnit must replace a killed PHP application worker without losing config.
 script='''import pathlib,json,os
pids=[]
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit():continue
 try:t=(p/'cmdline').read_bytes().replace(b'\\0',b' ').decode()
 except (OSError,UnicodeError):continue
 if t.startswith('unit: "php" application'):pids.append(int(p.name))
assert pids
os.kill(pids[0],9)
print('killed-one-application-worker')'''
 run('kill-one-unit-worker',['docker','exec','php-audit','python3','-c',script]);time.sleep(2);ready();check('faults','FreeUnit-worker-respawn',True)
 (R/'published/telegram-http-results.json').unlink(missing_ok=True)
 # Ignore the deliberately induced Unit worker exit; only PHP/application
 # warnings and failed API calls are failures in this subsequent end-to-end run.
 run('telegram-http',['python3',str(R/'telegram-http-e2e.py')],timeout=500)
 rows=json.loads((R/'published/telegram-http-results.json').read_text());check('telegram_http','real-webhook-and-synthetic-HTTPS-API',len(rows)==33 and all(x['ok'] for x in rows));counts['telegram_http']+=len(rows)
 # A process crash/OOM is not an expected authentication or configuration error.
 for service,d in containers().items():
  q=subprocess.run(['docker','logs','--since',candidate_started,d['Id']],capture_output=True,text=True)
  text=q.stdout+q.stderr
  bad=bool(re.search(r'PHP Fatal error|PHP Deprecated|PHP Warning|panic:|fatal error:|segmentation fault',text,re.I))
  check('faults','no-unexpected-crash-'+service,not bad)
 for file in core_logs():
  if not file.is_file() or file.is_symlink():continue
  st=file.stat();inode,offset=log_offsets.get(str(file),(-1,0))
  with file.open('rb') as f:
   if inode==st.st_ino and st.st_size>=offset:f.seek(offset)
   new=f.read().decode(errors='replace')
  bad=bool(re.search(r'PHP Fatal error|PHP Deprecated|PHP Warning|panic:|panicked at|segmentation fault',new,re.I))
  check('faults','no-new-core-crash-'+str(file.relative_to(B/'logs')),not bad)
 # Real-image rollback retains post-update client data and accumulated usage.
 run('rollback-pause-cron',['docker','stop','service-audit']);stopworker()
 code="require '/app/bot.php';$b=(new ReflectionClass('Bot'))->newInstanceWithoutConstructor();$s=$b->getXrayStats();$s['users'][0]['global']['download']=($s['users'][0]['global']['download']??0)+7779;exit($b->setXrayStats($s)?0:1);"
 php(code);preserve=identities()
 traffic="require '/app/bot.php';$b=(new ReflectionClass('Bot'))->newInstanceWithoutConstructor();echo $b->xrUserTraffic($b->getXrayStats(),0);"
 used=int(php(traffic))
 previous=json.loads(Path('/opt/vpnbot-hosted-ci/rollback-images.json').read_text())
 expected_php=capture(['docker','run','--rm','--network','none','--entrypoint','php',previous['php'],'-r','echo PHP_VERSION;']).strip()
 rollback=dict(services={s:{'image':previous['php']} for s in ('php','service')})
 rollback['services'].update({s:{'image':previous['ng']} for s in ('ng','up','dockerproxy')})
 (O/'rollback-previous.json').write_text(json.dumps(rollback))
 # Pin all candidate protocols while reverting only the old PHP/NGINX pair.
 ib.atomic(O/'candidate-compose.json',ib.canonical(ib.overlay(candidate)))
 renv=baseenv|{'COMPOSE_FILE':baseenv['COMPOSE_FILE']+':'+str(O/'candidate-compose.json')+':'+str(O/'rollback-previous.json')}
 run('rollback-previous-release',['docker','compose','--env-file','.env','--env-file','override.env','up','-d','--no-deps','php','service','ng','up','dockerproxy'],environ=renv,timeout=400);ready()
 check('update_rollback','previous-PHP-actually-running',php('echo PHP_VERSION;')==expected_php)
 check('update_rollback','rollback-keeps-new-clients',identities()==preserve)
 check('update_rollback','rollback-keeps-new-usage',int(php(traffic))>=used)
 deploy(env,'return-candidate');drivers();startworker(env)
 check('update_rollback','PHP85-actually-running',php('echo (PHP_VERSION_ID >= 80512 && PHP_VERSION_ID < 80600) ? 1 : 0;')=='1')
 check('update_rollback','forward-keeps-new-clients',identities()==preserve)
 check('update_rollback','forward-keeps-new-usage',int(php(traffic))>=used)
 verify_images({s:candidate['images'][im] for s,im in ib.SERVICES.items()},'update_rollback')
 # Test the candidate's rejection and atomic-write cases inside the real test
 # host as well as hosted CI. These include all unsuccessful job outcomes.
 run('bundle-faults',['python3','-m','unittest','discover','-s','tests','-p','image_bundle_test.py'],work=a.checkout,timeout=180)
 counts['faults']+=10
finally:
 if mutated:
  stopworker()
  run('final-pause-cron',['docker','stop','service-audit'],good=False)
  for name in paths:
   source=O/'old-code'/name;dest=B/name
   if source.exists():
    dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,dest)
   else:dest.unlink(missing_ok=True)
  # Restore original module intent even when a cycle failed while OFF.
  (B/'config/protocol-services.json').write_bytes(baseline_flags)
  if old_pending is None:pending_file.unlink(missing_ok=True)
  else:ib.atomic(pending_file,old_pending)
  # The original fixture pins all baseline images, preserving current data.
  deploy(baseenv,'restore-baseline');startworker(baseenv)
  verify_images(baseline,'update_rollback')
  restored=True;transaction.unlink()
 else:
  restored=True;transaction.unlink()
 if restored:
  for name in retained:capture(['docker','rm',name])
if not restored:raise RuntimeError('rollback incomplete')
(O/'summary.json').write_text(json.dumps(counts,indent=2))
print(json.dumps(counts),flush=True)

# Only successful disposable unit checkouts are removed; failure evidence stays.
if (O/'summary.json').is_file() and (O/'unit').is_dir():shutil.rmtree(O/'unit')
