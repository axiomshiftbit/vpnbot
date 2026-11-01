import pathlib,subprocess,json,os,time,shutil,hashlib,signal,sys,re,socket,ssl,uuid
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
  # /ws: XHTTP идёт через grpc_pass (HTTP/2 до Xray), WebSocket — через
  # proxy_pass. Активна ровно одна строка в каждой копии блока.
  conf=(B/'config/nginx.conf').read_text();h2=network=='xhttp'
  handler=re.findall(r'(?m)^[ \t]*((?:proxy|grpc)_pass) \S+; # vpnbot-(?:xray-h1|xhttp-h2)$',conf)
  # После настройки домена оба server-блока могут быть активны.
  check(str(i)+'-ws-handler-'+('grpc' if h2 else 'proxy'),bool(handler) and all(h==('grpc_pass' if h2 else 'proxy_pass') for h in handler))
  ns['fetch']()
  if h2:
   full=json.loads((O/'clients/full-xray.json').read_text());node=next(o for o in full['outbounds'] if o['protocol']=='vless')
   check(str(i)+'-xray-profile-stream-up',node['streamSettings']['xhttpSettings']['mode']=='stream-up')
   node=next(n for n in json.loads((O/'clients/full-mihomo.json').read_text())['proxies'] if n['type']=='vless')
   check(str(i)+'-mihomo-profile-stream-up',node['xhttp-opts']['mode']=='stream-up')
  for engine in ('xray','mihomo') if transport=='xhttp' else ('xray','mihomo','sing-box'):
   before=len(ns['lab'].RESULTS);ns['exchange'](str(i)+'-'+transport,engine,binary=pathlib.Path('/opt/vpnbot-hosted-ci/tests/xray') if engine=='xray' else pathlib.Path('/opt/vpnbot-hosted-ci/clients')/engine)
   check(str(i)+'-'+engine+'-real-traffic',all(r['passed'] for r in ns['lab'].RESULTS[before:]))
  if h2:
   # packet-up читает всё тело до проверки VLESS. Незавершённый POST без
   # авторизации должен закрыться за 60 с + lingering_time nginx (30 с).
   context=ssl._create_unverified_context()  # Только сертификат vpnbot.test стенда.
   with context.wrap_socket(socket.create_connection(('127.0.0.1',443),5),server_hostname='vpnbot.test') as slow:
    slow.settimeout(100)
    path='/ws'+h+'/'+str(uuid.uuid4())+'/invalid-sequence?x_padding='+'X'*150
    slow.sendall(('POST '+path+' HTTP/1.1\r\nHost: vpnbot.test\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n').encode()+b'\0')
    closed=False
    try:
     while slow.recv(4096):pass
     closed=True
    except socket.timeout:pass
    check(str(i)+'-unauthorized-incomplete-packet-bounded',closed)
   # Подписки до перехода (packet-up) проходят и через grpc_pass.
   for kind,key in (('xray',None),('mihomo','xhttp-opts')):
    f=O/('clients/full-'+kind+'.json');full=json.loads(f.read_text())
    if kind=='xray':next(o for o in full['outbounds'] if o['protocol']=='vless')['streamSettings']['xhttpSettings']['mode']='packet-up'
    else:next(n for n in full['proxies'] if n['type']=='vless')[key]['mode']='packet-up'
    f.write_text(json.dumps(full))
    before=len(ns['lab'].RESULTS);ns['exchange'](str(i)+'-legacy-packet-up',kind,binary=pathlib.Path('/opt/vpnbot-hosted-ci/tests/xray') if kind=='xray' else pathlib.Path('/opt/vpnbot-hosted-ci/clients')/kind)
    check(str(i)+'-'+kind+'-legacy-packet-up-real-traffic',len(ns['lab'].RESULTS)>before and all(r['passed'] for r in ns['lab'].RESULTS[before:]))
   ns['fetch']()
 # Mux.Cool поверх XHTTP (форк 26.10.5+): сервер с KeepAlive, клиент Xray берёт
 # блок mux из подписки. Ядро возвращаем сами: маркер ядра не входит в files.
 core0=json.loads((B/'config/pac.json').read_text()).get('xray_core','origin')
 bot('transport','xhttp');check('muxcool-fork-selected',bot('xray-core','fork')['result'].get('ok'));bot('xray-smux','off')
 try:
  check('muxcool-enabled',bot('xray-xhttp-mux','on')['result']=={'error':'','enabled':True})
  x=json.loads((B/'config/xray.json').read_text());extra=x['inbounds'][0]['streamSettings']['xhttpSettings']['extra']
  check('muxcool-server-keepalive',extra.get('muxKeepAliveSecs')=='20-40' and extra.get('muxKeepAliveBytes')=='64-512')
  ns['fetch']();node=next(o for o in json.loads((O/'clients/full-xray.json').read_text())['outbounds'] if o['protocol']=='vless')
  check('muxcool-client-profile',node.get('mux',{}).get('enabled') is True and node['mux'].get('concurrency')==8 and 'smux' not in node)
  for engine in ('xray','mihomo'):
   before=len(ns['lab'].RESULTS);ns['exchange']('muxcool-xhttp',engine,binary=pathlib.Path('/opt/vpnbot-hosted-ci/tests/xray') if engine=='xray' else pathlib.Path('/opt/vpnbot-hosted-ci/clients')/engine)
   check('muxcool-'+engine+'-real-traffic',len(ns['lab'].RESULTS)>before and all(r['passed'] for r in ns['lab'].RESULTS[before:]))
  check('muxcool-disabled',bot('xray-xhttp-mux','off')['result']=={'error':'','enabled':False})
  x=json.loads((B/'config/xray.json').read_text())
  check('muxcool-server-keepalive-removed','muxKeepAliveSecs' not in x['inbounds'][0]['streamSettings']['xhttpSettings'].get('extra',{}))
  ns['fetch']();node=next(o for o in json.loads((O/'clients/full-xray.json').read_text())['outbounds'] if o['protocol']=='vless')
  check('muxcool-client-profile-clean','mux' not in node)
  before=len(ns['lab'].RESULTS);ns['exchange']('muxcool-off-xhttp','xray',binary=pathlib.Path('/opt/vpnbot-hosted-ci/tests/xray'));check('muxcool-off-xray-real-traffic',all(r['passed'] for r in ns['lab'].RESULTS[before:]))
 finally:
  check('muxcool-core-returned',bot('xray-core',core0)['result'].get('ok'))
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
