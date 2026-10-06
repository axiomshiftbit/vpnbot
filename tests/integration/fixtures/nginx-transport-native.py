import pathlib,subprocess,json,os,time,shutil,hashlib,signal,sys
os.umask(0o077)
B=pathlib.Path('/opt/vpnbot-hosted-ci/stand/bot');O=pathlib.Path(sys.argv[1]);O.mkdir(parents=True,exist_ok=True)
P=O/'private';P.mkdir(exist_ok=True)
env={k:os.environ[k] for k in ('PATH','HOME','LANG') if k in os.environ}
env.update(VER='audit',COMPOSE_PROJECT_NAME='vpnbot-audit',COMPOSE_FILE='docker-compose.yml:compose.audit.yml:compose.migration.json:compose.fresh.json',COMPOSE_ENV_FILES='.env,override.env',VPNBOT_BUNDLE_FILE=os.environ.get('VPNBOT_BUNDLE_FILE','/opt/vpnbot-hosted-ci/active-test-bundle.json'))
rows=[];changed=False;connected=False
files=['config/pac.json','config/xray.json','config/nginx.conf','config/nginx_default.conf','config/upstream.conf']
def run(*args,timeout=180,good=True):
 p=subprocess.run(args,cwd=B,env=env,capture_output=True,text=True,timeout=timeout)
 if good and p.returncode:raise RuntimeError(str(args[:4])+': '+p.stderr[-600:])
 return p

def check(n,v):
 rows.append({'name':n,'passed':bool(v)});(O/'results.json').write_text(json.dumps(rows,indent=2));print(('PASS ' if v else 'FAIL ')+n,flush=True)
 if not v:raise AssertionError(n)
def bot(*args):
 p=run('docker','exec','php-audit','php','/tmp/audit-driver.php',*args);j=json.loads(p.stdout)
 (O/('bot-'+args[0]+'.json')).write_text(json.dumps(j,ensure_ascii=False));check('bot-'+','.join(args)+'-no-warnings',not j['warnings']);return j
def default_route():
 pid=run('docker','inspect','--format','{{.State.Pid}}','xray-audit').stdout.strip()
 routes=json.loads(run('nsenter','-t',pid,'-n','ip','-j','route','show','default').stdout)
 with (O/'routes.jsonl').open('a') as log:log.write(json.dumps(routes)+'\n')
 # Docker can rename eth0/eth1 when the core container is recreated. The
 # default gateway and route attributes must survive, not the interface name.
 return [{k:v for k,v in route.items() if k!='dev'} for route in routes]
try:
 assert 'TELEGRAM_API=tg-audit:8443' in (B/'.env').read_text()
 for n in files:
  target=P/n;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(B/n,target)
 cron=run('docker','inspect','--format','{{.State.Running}}','service-audit').stdout.strip()=='true'
 if cron:run('docker','stop','service-audit')
 changed=True
 original_route=default_route()
 run('docker','network','connect','--gw-priority','-1','vpnbot-protocol-test','xray-audit');connected=True
 check('controlled-network-preserves-default',original_route==default_route() and original_route[0]['gateway']=='10.10.0.1')
 source=pathlib.Path('/opt/vpnbot-hosted-ci/stand/tests/mux_final_vps.py')
 code=source.read_text().split("\ntry:\n bot('xray-core'")[0].replace("RUN=BASE.parent/'results/sing-mux-final-fix'","RUN=pathlib.Path("+repr(str(O/'clients'))+")").replace("'203.0.113.10'","'127.0.0.1'")
 ns={'__file__':str(source)};exec(compile(code,str(source),'exec'),ns)
 for i,transport in enumerate(('Websocket','trojan-grpc','Websocket','xhttp','trojan-grpc','Websocket')):
  bot('transport',transport)
  p=json.loads((B/'config/pac.json').read_text());x=json.loads((B/'config/xray.json').read_text());network=x['inbounds'][0]['streamSettings']['network']
  check(str(i)+'-saved-transport',p['transport']==transport)
  check(str(i)+'-running-nginx-valid',run('docker','exec','nginx-audit','nginx','-t',good=False).returncode==0)
  active='grpc' if network=='grpc' else 'ws';inactive='ws' if active=='grpc' else 'grpc';h=p['hashbot']
  path='/'+inactive+h+('/Tun' if inactive=='grpc' else '')
  r=run('curl','-ksS','--noproxy','*','--http2','--connect-to','vpnbot.test:443:127.0.0.1:443','--max-time','5','-o','/dev/null','-w','%{http_code}','https://vpnbot.test'+path)
  check(str(i)+'-inactive-'+inactive+'-returns-404',r.stdout=='404')
  ns['fetch']()
  for engine in ('xray','mihomo') if transport=='xhttp' else ('xray','mihomo','sing-box'):
   before=len(ns['lab'].RESULTS);ns['exchange'](str(i)+'-'+transport,engine,binary=pathlib.Path('/opt/vpnbot-hosted-ci/tests/xray') if engine=='xray' else pathlib.Path('/opt/vpnbot-hosted-ci/clients')/engine)
   check(str(i)+'-'+engine+'-real-traffic',all(r['passed'] for r in ns['lab'].RESULTS[before:]))
 # Parser rejection must keep the already running core and saved selection.
 oldpac=(B/'config/pac.json').read_bytes();oldx=(B/'config/xray.json').read_bytes();ng=(B/'config/nginx.conf').read_bytes()
 with (B/'config/nginx.conf').open('ab') as f:f.write(b'\nvpn_bot_test_invalid_directive on;\n')
 rejected=run('docker','exec','php-audit','php','/tmp/audit-driver.php','transport','trojan-grpc')
 check('invalid-nginx-does-not-change-pac',(B/'config/pac.json').read_bytes()==oldpac)
 check('invalid-nginx-does-not-change-xray',(B/'config/xray.json').read_bytes()==oldx)
 (B/'config/nginx.conf').write_bytes(ng)
 check('original-nginx-valid-after-rejection',run('docker','exec','nginx-audit','nginx','-t',good=False).returncode==0)
 ns['fetch']();before=len(ns['lab'].RESULTS);ns['exchange']('after-rejected-nginx','xray',binary=pathlib.Path('/opt/vpnbot-hosted-ci/tests/xray'));check('old-profile-still-works',all(r['passed'] for r in ns['lab'].RESULTS[before:]))
finally:
 try:
  if connected:
   run('docker','network','disconnect','vpnbot-protocol-test','xray-audit')
   check('controlled-network-cleanup',original_route==default_route())
 finally:
  if changed:
   for n in files:(B/n).write_bytes((P/n).read_bytes())
   run('docker','restart','xray-audit');run('docker','exec','nginx-audit','nginx','-t');run('docker','exec','nginx-audit','nginx','-s','reload');run('docker','exec','upstream-audit','nginx','-t');run('docker','exec','upstream-audit','nginx','-s','reload')
   if cron:run('docker','start','service-audit')
   check('original-settings-restored',all((B/n).read_bytes()==(P/n).read_bytes() for n in files))
 print(json.dumps({'passed':sum(x['passed'] for x in rows),'total':len(rows),'restored':changed}),flush=True)
