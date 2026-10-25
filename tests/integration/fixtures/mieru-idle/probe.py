from pathlib import Path
import json, os, socket, socketserver, struct, subprocess, sys, threading, time

ROOT = Path('/probe'); rows=[]; processes=[]; sockets=[]; supervisor=None
os.umask(0o077)

def check(name,ok):
 rows.append({'name':name,'passed':bool(ok)});(ROOT/'results.json').write_text(json.dumps(rows,indent=2))
 print(('PASS ' if ok else 'FAIL ')+name,flush=True)
 if not ok:raise RuntimeError(name)

def exact(conn,size):
 data=b''
 while len(data)<size:
  chunk=conn.recv(size-len(data))
  if not chunk:raise EOFError('closed')
  data+=chunk
 return data

class Echo(socketserver.BaseRequestHandler):
 def handle(self):
  while data:=self.request.recv(65536):self.request.sendall(data)

class Target(socketserver.ThreadingTCPServer):
 allow_reuse_address=True
 daemon_threads=True

def launch(args,env,log):
 f=(ROOT/log).open('wb');p=subprocess.Popen(args,env=env,stdout=f,stderr=f);processes.append((p,f));return p

def ready(port,process):
 deadline=time.monotonic()+10
 while time.monotonic()<deadline and process.poll() is None:
  try:
   with socket.create_connection(('127.0.0.1',port),timeout=.1):return
  except OSError:time.sleep(.05)
 raise RuntimeError('listener not ready')

base=json.loads((ROOT/'server.json').read_text());profile=json.loads((ROOT/'client.json').read_text())
env={k:os.environ[k] for k in ('PATH','HOME','LANG') if k in os.environ}
target=Target(('198.51.100.2',8081),Echo);threading.Thread(target=target.serve_forever,daemon=True).start()
try:
 for label,port,enabled in [('enabled',24445,True),('disabled',24446,False)]:
  cfg=json.loads(json.dumps(base));cfg['portBindings'][0]['port']=port
  if not enabled:cfg['advancedSettings'].pop('tcpIdleTimeout')
  path=ROOT/(label+'.json');path.write_text(json.dumps(cfg))
  process=launch(['/usr/local/bin/mita','run'],env|{'MITA_CONFIG_JSON_FILE':str(path),'MITA_UDS_PATH':str(ROOT/(label+'.sock'))},label+'.log')
  ready(port,process)
  conn=socket.create_connection(('127.0.0.1',port),timeout=2);sockets.append(conn)
 profile['socks5Port']=18080;profile['rpcPort']=18081
 clientcfg=ROOT/'live-client.json';clientcfg.write_text(json.dumps(profile))
 client=launch(['/probe/mieru-client','run'],env|{'MIERU_CONFIG_JSON_FILE':str(clientcfg)},'client.log');ready(18080,client)
 active=socket.create_connection(('127.0.0.1',18080),timeout=5);sockets.append(active)
 active.sendall(b'\x05\x01\x00');check('old-client-SOCKS',exact(active,2)==b'\x05\x00')
 active.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('198.51.100.2')+struct.pack('!H',8081))
 head=exact(active,4);check('old-client-CONNECT',head[1]==0);exact(active,6 if head[3]==1 else 18)
 start=time.monotonic();count=0
 while time.monotonic()-start<75:
  payload=('active-'+str(count)).encode();active.sendall(payload)
  if exact(active,len(payload))!=payload:raise RuntimeError('active traffic changed')
  count+=1;time.sleep(5)
 check('active-connection-survives-idle-timeout',count>=15 and client.poll() is None)
 sockets[0].settimeout(2)
 try:closed=sockets[0].recv(1)==b''
 except ConnectionResetError:closed=True
 except TimeoutError:closed=False
 check('inactive-TCP-closed-after-1m',closed)
 sockets[1].settimeout(.3)
 try:open_default=sockets[1].recv(1)!=b''
 except TimeoutError:open_default=True
 check('disabled-timeout-keeps-idle-TCP',open_default)
 # Exercise the bot's real supervisor and configs produced by reset/restore.
 for process,log in reversed(processes):
  process.terminate();process.wait(timeout=5);log.close()
 processes.clear()
 sys.path.insert(0,'/source')
 from mieru_service import MieruSupervisor, atomic_json
 state=ROOT/'state/mieru';supervisor=MieruSupervisor(state/'runtime')
 supervisor.desired=state/'desired.json'
 atomic_json(supervisor.desired,json.loads((ROOT/'initial-state.json').read_text()))
 supervisor.tick()
 check('supervisor-applies-idle-timeout',supervisor.alive() and json.loads((supervisor.current/'config.json').read_text())['advancedSettings']['tcpIdleTimeout']=='1m')
 atomic_json(supervisor.desired,json.loads((ROOT/'reset-state.json').read_text()));supervisor.tick()
 check('supervisor-reset-disables-timeout',supervisor.alive() and 'tcpIdleTimeout' not in json.loads((supervisor.current/'config.json').read_text()).get('advancedSettings',{}))
 atomic_json(supervisor.desired,json.loads((ROOT/'restored-state.json').read_text()));supervisor.tick()
 check('supervisor-restores-idle-timeout',supervisor.alive() and json.loads((supervisor.current/'config.json').read_text())['advancedSettings']['tcpIdleTimeout']=='1m')
 client=launch(['/probe/mieru-client','run'],env|{'MIERU_CONFIG_JSON_FILE':str(clientcfg)},'restored-client.log');ready(18080,client)
 with socket.create_connection(('127.0.0.1',18080),timeout=5) as restored:
  restored.sendall(b'\x05\x01\x00');assert exact(restored,2)==b'\x05\x00'
  restored.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('198.51.100.2')+struct.pack('!H',8081))
  head=exact(restored,4);assert head[1]==0;exact(restored,6 if head[3]==1 else 18)
  restored.sendall(b'restored-profile')
  check('old-profile-works-after-reset-and-restore',exact(restored,16)==b'restored-profile')
finally:
 for s in sockets:s.close()
 for p,f in reversed(processes):
  p.terminate()
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:p.kill();p.wait()
  f.close()
 if supervisor is not None:supervisor.stop()
 target.shutdown();target.server_close()
print(json.dumps({'passed':sum(x['passed'] for x in rows),'total':len(rows)}))
