import pathlib, subprocess, json, os, time, sys, shutil, signal
os.umask(0o077)
B=pathlib.Path('/opt/vpnbot-hosted-ci/stand/bot');S=pathlib.Path(__file__).parent
O=pathlib.Path(sys.argv[1]);O.mkdir(parents=True,exist_ok=True);P=O/'private';P.mkdir(exist_ok=True)
shutil.copyfile(__file__,O/'executed.py')
rows=[];children=[];cases=[];changed=False;made=False;cron=False;stopped=None
protocols=('anytls','mieru','tuic','shadowtls','masque');peer='vpnbot-warp-modules-peer'
env=dict(os.environ);env.update(VER='audit',COMPOSE_PROJECT_NAME='vpnbot-audit',COMPOSE_FILE='docker-compose.yml:compose.audit.yml:compose.migration.json:compose.fresh.json',COMPOSE_ENV_FILES='.env,override.env')
files=['config/pac.json']+['config/protocols/'+p+'/desired.json' for p in protocols]
def run(*args,input=None,timeout=90,good=True):
 p=subprocess.run(args,input=input,cwd=B,env=env,capture_output=True,text=True,timeout=timeout)
 if good and p.returncode:raise RuntimeError(str(args[:4])+': '+p.stderr[-500:])
 return p
def dx(c,*args,**kw):return run('docker','exec',c,*args,**kw)
def check(n,v,detail=None,strict=True):
 rows.append({'name':n,'passed':bool(v),'detail':detail});(O/'results.json').write_text(json.dumps(rows,indent=2));print(('PASS ' if v else 'FAIL ')+n,flush=True)
 if not v and strict:raise AssertionError(n)
def wait_proxy():
 end=time.monotonic()+85
 while time.monotonic()<end:
  if dx('warp-audit','pgrep','-x','warp-socks',good=False).returncode==0:return True
  time.sleep(.5)
 return False
def wait_module(p):
 desired=json.loads((B/'config/protocols'/p/'desired.json').read_text());end=time.monotonic()+25
 while time.monotonic()<end:
  try:
   status=json.loads((B/'config/protocols'/p/'runtime/status.json').read_text())
   if status['revision']==desired['revision'] and status['phase']=='running':return True
  except (OSError,ValueError):pass
  time.sleep(.3)
 return False
def bot(*args):
 j=json.loads(dx('php-audit','php','/tmp/audit-driver.php',*args).stdout);(P/('bot-'+args[0]+'.json')).write_text(json.dumps(j));print('bot result '+str(j.get('result')),flush=True);check('bot-'+','.join(args)+'-warnings',not j['warnings']);return j
def driver(*args):return json.loads(dx('php-audit','php','/tmp/warp-module-driver.php',*args).stdout)
def probe(kind,target='203.0.113.20'):
 q={'kind':kind,'proxy':'127.0.0.1','proxy_port':19090,'target':target}
 return json.loads(run('python3','/opt/vpnbot-hosted-ci/warp-udp-native/client.py',input=json.dumps(q),timeout=12).stdout)
def stop_client(p,f):
 if p.poll() is None:p.terminate()
 try:p.wait(timeout=10)
 except subprocess.TimeoutExpired:p.kill();p.wait()
 f.close()
try:
 assert 'TELEGRAM_API=tg-audit:8443' in (B/'.env').read_text()
 assert run('docker','inspect',peer,good=False).returncode
 for n in files:
  q=P/n;q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(B/n,q)
 run('docker','cp','warp-audit:/etc/warp',str(P/'warp'))
 cron=dx('service-audit','true',good=False).returncode==0
 if cron:run('docker','stop','service-audit')
 changed=True
 image=run('docker','inspect','--format','{{.Config.Image}}','warp-audit').stdout.strip()
 network=next(iter(json.loads(run('docker','inspect','--format','{{json .NetworkSettings.Networks}}','warp-audit').stdout)))
 run('docker','create','--name',peer,'--network',network,'--ip','10.10.0.251','--cap-add','NET_ADMIN','--entrypoint','sh',image,'-c','sleep infinity');made=True
 run('docker','start',peer)
 server=dx(peer,'wg','genkey').stdout.strip();client=dx(peer,'wg','genkey').stdout.strip()
 spub=run('docker','exec','-i',peer,'wg','pubkey',input=server).stdout.strip();cpub=run('docker','exec','-i',peer,'wg','pubkey',input=client).stdout.strip()
 run('docker','exec','-i',peer,'sh','-c','umask 077; cat > /tmp/wg.key',input=server)
 dx(peer,'sh','-ec','ip link add modulewarp type wireguard; ip addr add 172.31.0.1/24 dev modulewarp; ip link set modulewarp up; ip addr add 203.0.113.20/32 dev lo')
 dx(peer,'wg','set','modulewarp','private-key','/tmp/wg.key','listen-port','51820','peer',cpub,'allowed-ips','172.31.0.2/32')
 server_code=pathlib.Path('/opt/vpnbot-hosted-ci/warp-udp-native/server.py').read_text().replace("('203.0.113.20','10.80.0.245','127.0.0.1')","('203.0.113.20',)").replace("for host in ('1.1.1.1','1.0.0.1'):","for host in ():")
 (O/'server.py').write_text(server_code)
 pid=run('docker','inspect','--format','{{.State.Pid}}',peer).stdout.strip()
 f=(O/'server.log').open('wb');p=subprocess.Popen(['nsenter','-t',pid,'-n','python3',str(O/'server.py')],stdout=f,stderr=f);children.append((p,f))
 dx('warp-audit','wg-quick','down','/etc/warp/wgcf-profile.conf',good=False)
 conf='[Interface]\nPrivateKey = '+client+'\nAddress = 172.31.0.2/32\nMTU = 1280\n[Peer]\nPublicKey = '+spub+'\nAllowedIPs = 0.0.0.0/0\nEndpoint = 10.10.0.251:51820\nPersistentKeepalive = 25\n'
 # Old backup without ListenPort exercises migration in the real ON path.
 (P/'module-profile.conf').write_text(conf);run('docker','cp',str(P/'module-profile.conf'),'warp-audit:/etc/warp/wgcf-profile.conf')
 pac=json.loads((B/'config/pac.json').read_text());pac['warpoff']=1;(B/'config/pac.json').write_text(json.dumps(pac));run('docker','restart','warp-audit')
 end=time.monotonic()+20
 while time.monotonic()<end:
  if dx('warp-audit','iptables','-S','WARP_SOCKS_OUT',good=False).returncode==0:break
  time.sleep(.5)
 dx('warp-audit','iptables','-I','WARP_SOCKS_OUT','1','-p','udp','-d','10.10.0.251','--dport','51820','-j','RETURN')
 bot('warp-toggle');check('proxy-on-old-profile',wait_proxy())
 check('old-profile-listen-port-migrated',dx('warp-audit','wg','show','wgcf-profile','listen-port').stdout.strip()=='51820')
 # Allow only the controlled private WireGuard endpoint; destinations are still denied.
 dx('warp-audit','iptables','-I','WARP_SOCKS_OUT','1','-p','udp','-d','10.10.0.251','--dport','51820','-j','RETURN')
 run('docker','cp',str(S/'warp-module-driver.php'),'php-audit:/tmp/warp-module-driver.php')
 run('docker','cp','/opt/vpnbot-hosted-ci/tests/optional-native/managed_protocol_fixture.php','php-audit:/tmp/managed_protocol_fixture.php')
 for protocol,transport in [('anytls',''),('mieru','TCP'),('mieru','UDP'),('tuic',''),('shadowtls',''),('masque','')]:
  uid=driver(protocol,'prepare',transport)['id'];check(protocol+'-'+transport+'-applied',wait_module(protocol))
  formats=('native','mihomo') if protocol=='mieru' else ('native',) if protocol=='masque' else ('singbox','mihomo')
  for engine in formats:
   label='-'.join(x for x in (protocol,transport,engine) if x);cfg=driver(protocol,'profile',uid,engine)
   address={'anytls':'10.10.0.22','mieru':'10.10.0.23','tuic':'10.10.0.24','shadowtls':'10.10.0.25','masque':'10.10.0.27'}[protocol]
   port=8443 if protocol=='anytls' else json.loads((B/'config/protocols'/protocol/'desired.json').read_text())['settings']['listen_port']
   for mode in (('h3','h2') if protocol=='masque' else ('',)):
    localenv=dict(env);localenv['SSL_CERT_FILE']='/opt/vpnbot-hosted-ci/stand/bot/certs/vpnbot-protocol-test/server.pem'
    path=P/(label+mode+'.json')
    if engine=='mihomo':
     cfg['proxies'][0]['server']=address;cfg['proxies'][0]['port']=port;cfg['mixed-port']=19090;cfg['bind-address']='127.0.0.1';cmd=['/opt/vpnbot-hosted-ci/clients/mihomo','-d',str(P/'mihomo'),'-f',str(path)]
    elif engine=='singbox':
     for node in cfg['outbounds']:
      if node.get('type')==protocol:node['server']=address;node['server_port']=port
     cfg['inbounds'][0]['listen_port']=19090;cmd=['/opt/vpnbot-hosted-ci/clients/sing-box','run','-c',str(path)]
    elif protocol=='mieru':
     for profile in cfg['profiles']:
      for endpoint in profile['servers']:
       endpoint.pop('domainName',None);endpoint['ipAddress']=address
     cfg['socks5Port']=19090;cfg['rpcPort']=19091;localenv['MIERU_CONFIG_JSON_FILE']=str(path);cmd=['/opt/vpnbot-hosted-ci/tests/optional-native/bin/mieru','run']
    else:
     cfg['inbounds'][0]['port']=19090;out=cfg['outbounds'][0];out['settings']['address']=address;out['streamSettings']['tlsSettings']['alpn']=[mode]
     out['streamSettings']['tlsSettings']['useSystemCa']=True  # Xray 26.10.10+: иначе SSL_CERT_FILE не читается
     localenv['SSL_CERT_FILE']=str(B/'certs/vpnbot-migration/server.crt');cmd=['/opt/vpnbot-hosted-ci/tests/xray','run','-config',str(path)]
    path.write_text(json.dumps(cfg));cases.append((label+mode,protocol,transport,cmd,dict(localenv)));f=(O/(label+mode+'.log')).open('ab');p=subprocess.Popen(cmd,cwd=P,env=localenv,stdout=f,stderr=f);children.append((p,f))
    try:
     time.sleep(1)
     for kind in ('tcp','udp'):
      r=probe(kind);check(label+mode+'-'+kind+'-via-warp',r['ok'],r,strict=False)
      if kind=='tcp':check(label+mode+'-source-is-tunnel',r.get('result','').endswith('172.31.0.2'),strict=False)
     r=probe('tcp','10.10.0.7');check(label+mode+'-private-denied',not r['ok'])
    finally:stop_client(p,f);children.remove((p,f))
 # The fresh default is TCP-only. Explicitly test server-side rejection even
 # when an already exported client still requests UDP-over-TCP.
 driver('shadowtls','udp','off');check('shadowtls-TCP-only-applied',wait_module('shadowtls'))
 for label,protocol,transport,cmd,localenv in cases:
  if protocol!='shadowtls':continue
  f=(O/(label+'-TCP-only.log')).open('ab');p=subprocess.Popen(cmd,cwd=P,env=localenv,stdout=f,stderr=f);children.append((p,f))
  try:
   time.sleep(1)
   check(label+'-TCP-only-retains-TCP',probe('tcp')['ok'])
   check(label+'-TCP-only-rejects-UDP',not probe('udp')['ok'])
  finally:stop_client(p,f);children.remove((p,f))
 driver('shadowtls','udp','on');check('shadowtls-UDP-over-TCP-applied',wait_module('shadowtls'))
 # Stop only the watchdog, keeping its SOCKS/SSH children active during fault injection.
 stopped=int(run('docker','inspect','--format','{{.State.Pid}}','warp-audit').stdout);os.kill(stopped,signal.SIGSTOP)
 # With a real reachable direct path after link loss, no proxy traffic may leak.
 dx('warp-audit','wg-quick','down','/etc/warp/wgcf-profile.conf')
 dx('warp-audit','ip','route','add','203.0.113.20/32','via','10.10.0.251')
 check('root-direct-path-after-loss',dx('warp-audit','curl','-sS','--max-time','4','http://203.0.113.20:18080/').returncode==0)
 def client_matrix(stage,expected):
  for label,protocol,transport,cmd,localenv in cases:
   if protocol=='mieru' and json.loads((B/'config/protocols/mieru/desired.json').read_text())['settings']['transport']!=transport:
    driver('mieru','transport',transport);check(stage+'-mieru-'+transport+'-applied',wait_module('mieru'))
   f=(O/(label+'-'+stage+'.log')).open('ab');p=subprocess.Popen(cmd,cwd=P,env=localenv,stdout=f,stderr=f);children.append((p,f))
   try:
    time.sleep(1)
    for kind in ('tcp','udp'):
     r=probe(kind);check(label+'-'+kind+'-'+stage,r['ok']==expected,r,strict=False)
   finally:stop_client(p,f);children.remove((p,f))
 client_matrix('no-direct-leak-after-loss',False)
 bot('warp-toggle');check('off-stops-proxy',dx('warp-audit','pgrep','-x','warp-socks',good=False).returncode!=0)
 os.kill(stopped,signal.SIGCONT);stopped=None
 dx('warp-audit','ip','route','del','203.0.113.20/32','via','10.10.0.251')
 bot('warp-toggle');check('on-recovers-proxy',wait_proxy());check('on-retains-distinct-WG-port',dx('warp-audit','wg','show','wgcf-profile','listen-port').stdout.strip()=='51820')
 client_matrix('traffic-restored-after-on',True)
finally:
 if stopped and int(run('docker','inspect','--format','{{.State.Pid}}','warp-audit').stdout)==stopped:os.kill(stopped,signal.SIGCONT)
 for p,f in children:stop_client(p,f)
 if changed:
  (O/'warp-startup.log').write_text(dx('warp-audit','tail','-n','220','/logs/warp',good=False).stdout)
  (O/'warp-diagnostic.json').write_text(json.dumps({'range':dx('warp-audit','cat','/proc/sys/net/ipv4/ip_local_port_range',good=False).stdout,'processes':dx('warp-audit','ps','-o','pid,ppid,comm',good=False).stdout,'inspect':json.loads(run('docker','inspect','warp-audit').stdout)[0]['State'],'image':run('docker','inspect','--format','{{.Config.Image}}','warp-audit').stdout}))
  (O/'warp-firewall.txt').write_text(dx('warp-audit','iptables-save',good=False).stdout)
  for n in files:(B/n).write_bytes((P/n).read_bytes())
  dx('warp-audit','wg-quick','down','/etc/warp/wgcf-profile.conf',good=False)
  run('docker','cp',str(P/'warp')+'/.','warp-audit:/etc/warp/')
  run('docker','restart','warp-audit')
  for protocol in protocols:check(protocol+'-settings-restored',wait_module(protocol))
  if cron:run('docker','start','service-audit')
  check('original-settings-bytes-restored',all((B/n).read_bytes()==(P/n).read_bytes() for n in files))
 if made:run('docker','rm','-f',peer)
 print(json.dumps({'passed':sum(x['passed'] for x in rows),'total':len(rows)}),flush=True)

if not all(r["passed"] for r in rows):sys.exit(1)
