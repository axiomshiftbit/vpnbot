from pathlib import Path
import sys,runpy,json,subprocess,time,copy,importlib.util,os,socket
r=Path('/opt/vpnbot-hosted-ci/tests');o=r/'optional-native';b=Path('/opt/vpnbot-hosted-ci/stand/bot');rows=[]
def check(name,ok):
 rows.append({'name':name,'ok':bool(ok)});print(('PASS ' if ok else 'FAIL ')+name,flush=True);(r/'published-optional-results.json').write_text(json.dumps(rows,indent=2))
 if not ok:raise RuntimeError(name)
def run(args):return subprocess.run(args,capture_output=True,text=True,timeout=60)
def attach(name,address=None):
 networks=json.loads(run(['docker','inspect',name]).stdout)[0]['NetworkSettings']['Networks']
 if 'vpnbot-protocol-test' in networks:return
 run(['docker','network','connect']+(['--ip',address] if address else [])+['vpnbot-protocol-test',name]).check_returncode()
def client_ready(proc):
 deadline=time.monotonic()+10
 while proc.poll() is None and time.monotonic()<deadline:
  try:
   with socket.create_connection(('127.0.0.1',1088),timeout=.2) as sock:
    sock.sendall(b'\x05\x01\x00')
    if sock.recv(2)==b'\x05\x00':return
  except OSError:pass
  time.sleep(.05)
 raise RuntimeError('MASQUE client SOCKS listener not ready')
for proto,file,boundary,engines in [('anytls','integration_anytls.py',"\ndriver('cards')",['singbox','mihomo']),('mieru','mieru_client.py',None,['native','mihomo']),('tuic','integration_tuic.py','\nwait_applied()', ['singbox','mihomo']),('shadowtls','shadowtls_client.py',None,['singbox','mihomo'])]:
 ns={'__name__':'postrestore_optional','__file__':str(o/file)};s=(o/file).read_text();exec(compile(s.split(boundary)[0] if boundary else s,str(o/file),'exec'),ns)
 for engine in engines:
  with ns['Client'](engine) as c:
   ok,body=c.request();check(proto+'/'+engine+'/restored-profile-HTTP',ok and body==b'VPNBOT-PROTOCOL-TARGET\n')
   ok,body=c.request('https://anytls.test:8443/',https=True);check(proto+'/'+engine+'/restored-profile-HTTPS',ok and body==b'VPNBOT-PROTOCOL-TARGET\n')
# MASQUE использует реальный основной контейнер, прежнего пользователя и TLS.
attach('masque-audit')
code="require '/app/ManagedProtocol.php';$s=new ManagedProtocol('masque','/config/protocols');foreach($s->read()['users'] as $id=>$u){if($s->allowed($u,$id)){file_put_contents('/logs/audit-masque-afterrestore.json',json_encode($s->profile($id,'native')));exit;}}exit(1);"
run(['docker','exec','php-audit','php','-r',code]).check_returncode()
cfg=json.loads((b/'logs/audit-masque-afterrestore.json').read_text());cfg['inbounds'][0]['port']=1088
out=cfg['outbounds'][0];out['settings']['address']='10.10.0.27';out['settings']['port']=24449
settings=json.loads((b/'config/protocols/masque/desired.json').read_text())['settings']
cert=b/'certs'/settings['certificate'].removeprefix('/certs/')
out['streamSettings']['tlsSettings']['certificates']=[{'certificateFile':str(cert),'usage':'verify'}]
for http in ['h2','h3']:
 out['streamSettings']['tlsSettings']['alpn']=[http];path=r/f'masque-postrestore-{http}.json';path.write_text(json.dumps(cfg))
 with (r/f'masque-postrestore-{http}.log').open('w') as log:
  proc=subprocess.Popen([str(r/'xray'),'run','-config',str(path)],stdout=log,stderr=log)
  try:
   client_ready(proc);p=run(['curl','--noproxy','','--socks5-hostname','127.0.0.1:1088','--max-time','8','-fsS','http://11.77.0.2:8081/']);(r/f'masque-postrestore-{http}-curl.log').write_text('exit='+str(p.returncode)+'\n'+p.stderr);check('masque/'+http+'/restored-profile-TCP',p.returncode==0 and p.stdout=='VPNBOT-PROTOCOL-TARGET\n')
  finally:proc.terminate();proc.wait(timeout=10)
print(json.dumps({'passed':sum(x['ok'] for x in rows),'total':len(rows)}))
