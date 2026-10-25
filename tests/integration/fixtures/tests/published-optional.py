from pathlib import Path
import sys,runpy,json,subprocess,time,copy,importlib.util,os,socket,shutil,struct,zipfile
r=Path('/opt/vpnbot-hosted-ci/tests');o=r/'optional-native';b=Path('/opt/vpnbot-hosted-ci/stand/bot');rows=[]
def check(name,ok):
 rows.append({'name':name,'ok':bool(ok)});print(('PASS ' if ok else 'FAIL ')+name,flush=True);(r/'published-optional-results.json').write_text(json.dumps(rows,indent=2))
 if not ok:raise RuntimeError(name)
def run(args):return subprocess.run(args,capture_output=True,text=True,timeout=60)
def attach(name,address=None):
 networks=json.loads(run(['docker','inspect',name]).stdout)[0]['NetworkSettings']['Networks']
 if 'vpnbot-protocol-test' in networks:return
 run(['docker','network','connect']+(['--ip',address] if address else [])+['vpnbot-protocol-test',name]).check_returncode()
# Без -f: любой ответ HTTP (даже 403 панели) значит, что соединение с внутренней
# сетью состоялось. Изоляция — это отсутствие ответа вовсе.
INTERNAL=['http://10.10.0.8:2375/version','http://10.10.0.7:8090/','http://10.10.0.5:80/']
def isolated(port):
 for url in INTERNAL:
  p=run(['curl','--noproxy','','--socks5-hostname',f'127.0.0.1:{port}','-sS','--max-time','4',url])
  if p.returncode==0 or p.stdout:return False
 return True
def client_ready(proc,port=1088):
 deadline=time.monotonic()+10
 while proc.poll() is None and time.monotonic()<deadline:
  try:
   with socket.create_connection(('127.0.0.1',port),timeout=.2) as sock:
    sock.sendall(b'\x05\x01\x00')
    if sock.recv(2)==b'\x05\x00':return
  except OSError:pass
  time.sleep(.05)
 raise RuntimeError('client SOCKS listener not ready')
def udp_echo(port,host='11.77.0.2',target=9999):
 try:
  with socket.create_connection(('127.0.0.1',port),timeout=5) as c:
   c.sendall(b'\x05\x01\x00');assert c.recv(2)==b'\x05\x00'
   c.sendall(b'\x05\x03\x00\x01'+b'\0'*6);head=c.recv(4)
   if head[1]:return False
   c.recv(4 if head[3]==1 else 16);relay=struct.unpack('!H',c.recv(2))[0]
   with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
    s.settimeout(8);data=os.urandom(1200)
    s.sendto(b'\0\0\0\x01'+socket.inet_aton(host)+struct.pack('!H',target)+data,('127.0.0.1',relay))
    return s.recv(65535).endswith(data)
 except (OSError,AssertionError):return False
for proto,file,boundary,engines in [('anytls','integration_anytls.py',"\ndriver('cards')",['singbox','mihomo']),('mieru','mieru_client.py',None,['native','native-previous','mihomo']),('tuic','integration_tuic.py','\nwait_applied()', ['singbox','mihomo']),('shadowtls','shadowtls_client.py',None,['singbox','mihomo'])]:
 ns={'__name__':'postrestore_optional','__file__':str(o/file)};s=(o/file).read_text();exec(compile(s.split(boundary)[0] if boundary else s,str(o/file),'exec'),ns)
 for engine in engines:
  client=ns['Client']('native' if engine=='native-previous' else engine)
  if engine=='native-previous':client.binary='/opt/vpnbot-hosted-ci/stand/bin/mieru-previous'
  with client as c:
   ok,body=c.request();check(proto+'/'+engine+'/restored-profile-HTTP',ok and body==b'VPNBOT-PROTOCOL-TARGET\n')
   ok,body=c.request('https://anytls.test:8443/',https=True);check(proto+'/'+engine+'/restored-profile-HTTPS',ok and body==b'VPNBOT-PROTOCOL-TARGET\n')
   check(proto+'/'+engine+'/internal-network-isolated',isolated(c.port))
   if proto=='mieru':check(proto+'/'+engine+'/restored-profile-UDP',udp_echo(c.port))
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
   check('masque/'+http+'/internal-network-isolated',isolated(1088))
  finally:proc.terminate();proc.wait(timeout=10)
# snolc: ZIP выдаёт бот после восстановления; клиент для glibc ставится из него
# и ходит через опубликованный порт стенда 127.0.0.1:24448.
code="require '/app/ManagedProtocol.php';$s=new ManagedProtocol('snolc','/config/protocols');foreach($s->read()['users'] as $id=>$u){if($s->allowed($u,$id)){file_put_contents('/logs/audit-snolc-afterrestore.zip',$s->profileDocument($id,'native')['body']);exit;}}exit(1);"
run(['docker','exec','php-audit','php','-r',code]).check_returncode()
client=r/'snolc-postrestore';shutil.rmtree(client,ignore_errors=True)
with zipfile.ZipFile(b/'logs/audit-snolc-afterrestore.zip') as bundle:bundle.extractall(client)
# Без сети: всё нужное для установки обязано лежать в ZIP.
p=subprocess.run(['unshare','--net',sys.executable,'client.py','--install','--prepare'],cwd=client,capture_output=True,text=True,timeout=60)
check('snolc/restored-profile-installs-offline',p.returncode==0)
with (r/'snolc-postrestore.log').open('w') as log:
 proc=subprocess.Popen([sys.executable,str(client/'client.py'),'--socks-port','1089'],cwd=client,stdout=log,stderr=log,start_new_session=True)
 try:
  client_ready(proc,1089);ok=False
  for _ in range(20):
   p=run(['curl','--noproxy','','--socks5-hostname','127.0.0.1:1089','--max-time','8','-fsS','http://11.77.0.2:8081/'])
   if p.returncode==0 and p.stdout=='VPNBOT-PROTOCOL-TARGET\n':ok=True;break
   time.sleep(1)
  check('snolc/restored-profile-TCP',ok)
  check('snolc/restored-profile-UDP',udp_echo(1089))
  check('snolc/internal-network-isolated',isolated(1089))
 finally:
  os.killpg(proc.pid,15);proc.wait(timeout=10)
print(json.dumps({'passed':sum(x['ok'] for x in rows),'total':len(rows)}))
