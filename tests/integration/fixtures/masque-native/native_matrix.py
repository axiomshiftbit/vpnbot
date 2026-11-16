import os,sys,json,time,socket,struct,subprocess,threading,select,copy,pathlib,hashlib
ROOT=pathlib.Path('/lab'); STATE=pathlib.Path('/state'); DESIRED=ROOT/'desired-current.json'
RESULTS={}; children=[]; stops=[]; clients=[]
BASE=json.loads((ROOT/'desired.json').read_text()); ids=json.loads((ROOT/'users.json').read_text()); A=ids['a']; B=ids['b']
class Failure(Exception):pass

def check(name,ok):
 RESULTS[name]=bool(ok); (ROOT/'results/native.json').write_text(json.dumps(RESULTS,indent=2)+'\n');print(name, 'PASS' if ok else 'FAIL',flush=True)
 if not ok: raise Failure(name)

def write(path,value):
 tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(value));os.replace(tmp,path)

def status():
 try:return json.loads((STATE/'status.json').read_text())
 except (OSError,ValueError):return {}

def wait_for(fn,seconds=12):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  result=fn()
  if result:return result
  time.sleep(.15)
 return False

def apply(state):
 state['revision']=max(state['revision'],status().get('desired_revision') or 0)+1;write(DESIRED,state)
 return wait_for(lambda:status().get('revision')==state['revision'] and status().get('phase') in ('running','idle','disabled'))

def server_start():
 # A clean protocol store writes its empty usage ledger before its first desired state.
 if not (STATE/'usage.json').exists():write(STATE/'usage.json',{'users':{}})
 env=os.environ|{'PROTOCOL_DESIRED':str(DESIRED)}
 f=open(ROOT/'supervisor.log','ab');p=subprocess.Popen(['python3','/lab/source/scripts/masque_service.py','/state'],env=env,stdout=f,stderr=f);children.append(p);f.close();return p

def stop(p):
 if p.poll() is None:
  p.terminate()
  try:p.wait(timeout=8)
  except subprocess.TimeoutExpired:p.kill();p.wait()

def recv(s,n):
 data=b''
 while len(data)<n:
  v=s.recv(n-len(data))
  if not v:raise EOFError()
  data+=v
 return data

def address(host,port):
 family=socket.AF_INET6 if ':' in host else socket.AF_INET
 return (b'\x04' if family==socket.AF_INET6 else b'\x01')+socket.inet_pton(family,host)+struct.pack('!H',port)

def socks(command,host,port,local=1080):
 s=socket.create_connection(('127.0.0.1',local),timeout=3);s.settimeout(3);s.sendall(b'\x05\x01\x00');assert recv(s,2)==b'\x05\x00'
 s.sendall(b'\x05'+bytes([command])+b'\x00'+address(host,port));reply=recv(s,4)
 if reply[1]:s.close();raise OSError('SOCKS rejected')
 bind=recv(s,4 if reply[3]==1 else 16);p=struct.unpack('!H',recv(s,2))[0]
 return s,(socket.inet_ntop(socket.AF_INET if len(bind)==4 else socket.AF_INET6,bind),p)

def tcp(host='198.51.100.23',port=18080,payload=b'vpnbot-masque-traffic'*20,local=1080):
 s=None
 try:
  s,_=socks(1,host,port,local);s.sendall(payload);return recv(s,len(payload))==payload
 except (OSError,EOFError,AssertionError):return False
 finally:
  if s:s.close()

def udp(host='198.51.100.23',port=18081,size=128,local=1080):
 control=None
 try:
  control,endpoint=socks(3,'0.0.0.0',0,local)
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
   sock.settimeout(3);data=os.urandom(size);header=b'\x00\x00\x00'+address(host,port)
   sock.sendto(header+data,('127.0.0.1',endpoint[1]));reply=sock.recv(65535)
   return reply[3] in (1,4) and reply[(10 if reply[3]==1 else 22):]==data
 except (OSError,EOFError,AssertionError):return False
 finally:
  if control:control.close()

def echo(host,port,udp_mode=False):
 family=socket.AF_INET6 if ':' in host else socket.AF_INET
 s=socket.socket(family,socket.SOCK_DGRAM if udp_mode else socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind((host,port));s.settimeout(.2);stops.append(s)
 def connection(c):
  with c:
   c.settimeout(15)
   try:
    while data:=c.recv(65535):c.sendall(data)
   except OSError:pass
 def loop():
  if not udp_mode:s.listen(64)
  while True:
   try:
    if udp_mode:
     data,peer=s.recvfrom(65535);s.sendto(data,peer)
    else:
     c,_=s.accept();threading.Thread(target=connection,args=(c,),daemon=True).start()
   except socket.timeout:continue
   except OSError:return
 threading.Thread(target=loop,daemon=True).start()

def client(http='h3',noise=False,password=None,sni=None,port=1080,serverport=24449):
 cfg=json.loads((ROOT/('client-noise.json' if noise else 'client-'+http+'.json')).read_text());cfg['inbounds'][0]['port']=port
 out=cfg['outbounds'][0];out['settings']['port']=serverport
 out['streamSettings']['tlsSettings']['certificates']=[{'certificateFile':'/certs/cert_public','usage':'verify'}]
 if password is not None:out['streamSettings']['masqueSettings']['pass']=password
 if sni:out['streamSettings']['tlsSettings']['serverName']=sni
 path=ROOT/('client-'+str(port)+'-current.json');write(path,cfg)
 f=open(ROOT/('client-'+str(port)+'.log'),'ab');p=subprocess.Popen(['/client-xray','run','-config',str(path)],stdout=f,stderr=f);f.close();children.append(p);clients.append(p)
 time.sleep(.3);return p

def usage():return json.loads((STATE/'usage.json').read_text())['users']

def noise_relay():
 downstream=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);downstream.bind(('127.0.0.1',25449));upstream=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);upstream.bind(('127.0.0.1',0));stops.extend([downstream,upstream]);packets={'client':[],'server':[]}
 def loop():
  peer=None
  while True:
   try:
    ready,_,_=select.select([downstream,upstream],[],[],.2)
    for s in ready:
     data,addr=s.recvfrom(65535)
     direction='client' if s==downstream else 'server'
     if data.startswith(bytes.fromhex('0d0a0d0a')):packets[direction].append(data)
     if s==downstream:peer=addr;upstream.sendto(data,('127.0.0.1',24449))
     elif peer:downstream.sendto(data,peer)
   except (OSError,ValueError):return
 threading.Thread(target=loop,daemon=True).start();return packets

try:
 for host in ['198.51.100.23','2001:db8::23','127.0.0.1']:
  echo(host,18080);echo(host,18081,True)
 # A listening echo service on a blocked Docker/private address proves ACL enforcement.
 echo('10.10.0.27',18080);echo('10.10.0.27',18081,True)
 write(DESIRED,copy.deepcopy(BASE));supervisor=server_start()
 check('start_native_supervisor',wait_for(lambda:status().get('phase')=='running'))
 for http in ['h3','h2']:
  c=client(http)
  check(http+'_tcp_ipv4',wait_for(lambda:tcp()))
  check(http+'_tcp_ipv6',tcp('2001:db8::23'))
  for ip in ['198.51.100.23','2001:db8::23']:
   for size in [16,512,1200]:check(http+'_udp_'+('v6' if ':' in ip else 'v4')+'_'+str(size),udp(ip,size=size))
  check(http+'_blocks_loopback_tcp',not tcp('127.0.0.1'))
  check(http+'_blocks_private_tcp',not tcp('10.10.0.27'))
  check(http+'_blocks_mapped_private_tcp',not tcp('::ffff:10.10.0.27'))
  check(http+'_blocks_private_udp',not udp('10.10.0.27'))
  stop(c)
 check('durable_per_user_stats',wait_for(lambda: usage().get(A,{}).get('upload',0)>0 and usage().get(A,{}).get('download',0)>0,8))
 check('unused_user_has_zero_traffic',sum(usage()[B].get(k,0) for k in ['upload','download'])==0)
 for label,kwargs in [('bad_password',{'password':'incorrect'}),('wrong_tls_identity',{'sni':'wrong.example.test'})]:
  c=client(**kwargs);check(label,not tcp());stop(c)
 # Persistent API loss must fail closed for limited users (not endlessly reopen them).
 s=copy.deepcopy(BASE);s['users'][A]['quota']=100000000
 check('quota_state_applied',apply(s));c=client();check('quota_initial_traffic',tcp())
 (ROOT/'fail-stats').touch();check('stats_loss_closes_limited_access',wait_for(lambda:not status().get('running',True),24));check('stats_loss_blocks_new_traffic',not tcp());(ROOT/'fail-stats').unlink();stop(c)
 check('stats_recovery',wait_for(lambda:status().get('phase')=='running',12))
 # Existing connections close after revocation even if the new certificate is invalid.
 c=client();live,_=socks(1,'198.51.100.23',18080);live.sendall(b'before');check('live_before_revoke',recv(live,6)==b'before')
 bad=copy.deepcopy(BASE);bad['settings']['sni']='wrong.example.test';bad['users'][A]['enabled']=False
 bad['revision']=status()['revision']+1;write(DESIRED,bad)
 check('revocation_wins_over_bad_certificate',wait_for(lambda:status().get('phase')=='error' and not status().get('running',True)))
 try:live.sendall(b'after');closed=live.recv(10)==b''
 except OSError:closed=True
 live.close();check('revoked_existing_connection_closed',closed);stop(c)
 check('restore_valid_state',apply(copy.deepcopy(BASE)))
 before=status()['pid'];bad=copy.deepcopy(BASE);bad['settings']['sni']='wrong.example.test';bad['revision']=status()['revision']+1;write(DESIRED,bad)
 check('invalid_tls_preserves_process',wait_for(lambda:status().get('phase')=='error' and status().get('pid')==before));c=client();check('invalid_tls_old_traffic_survives',tcp());stop(c)
 check('restore_after_invalid_tls',apply(copy.deepcopy(BASE)))
 bad=copy.deepcopy(BASE);bad['config']['_auditFailLaunch']=True;bad['revision']=status()['revision']+1;write(DESIRED,bad)
 check('failed_launch_recovers_old_core',wait_for(lambda:status().get('phase')=='error' and status().get('running') and status().get('error')=='start_failed',15))
 c=client();check('rollback_restores_traffic',tcp());stop(c);check('state_after_rollback',apply(copy.deepcopy(BASE)))
 # Byte quota is polled every 5 seconds, and persisted over supervisor restart.
 s=copy.deepcopy(BASE);s['users'][A]['reset']='1'*16;s['users'][A]['quota']=4096
 check('small_quota_applied',apply(s));c=client();check('quota_payload_accounted',tcp(payload=b'x'*16384))
 check('exhausted_user_removed',wait_for(lambda:A not in status().get('active',[]),9));check('exhausted_user_rejected',not tcp());stop(c)
 totals=usage()[A]['upload']+usage()[A]['download'];check('quota_totals_persisted',totals>=4096)
 stop(supervisor);supervisor=server_start();check('restart_keeps_exhausted_user_blocked',wait_for(lambda:status().get('phase')=='running' and A not in status().get('active',[])))
 check('restart_does_not_reset_totals',usage()[A]['upload']+usage()[A]['download']>=totals)
 s['users'][A]['reset']='2'*16;s['users'][A]['quota']=None;check('quota_reset_applied',apply(s));c=client();check('quota_reset_allows_access',tcp());stop(c)
 s['users'][A]['expires']=int(time.time())+2;check('expiry_state_applied',apply(s));check('expired_user_removed',wait_for(lambda:A not in status().get('active',[]),6));c=client();check('expired_user_rejected',not tcp());stop(c)
 # Actual UDP noise on both directions; fields regenerate after reset.
 masked=json.loads((ROOT/'desired-noise.json').read_text());check('noise_state_applied',apply(masked));packets=noise_relay();c=client(noise=True,serverport=25449)
 check('noise_h3_tcp',wait_for(lambda:tcp()));check('noise_h3_udp',udp(size=1200))
 for _ in range(3):time.sleep(4);check('noise_flow_'+str(_),tcp())
 for direction,values in packets.items():
  check('noise_'+direction+'_captured',len(values)>=2)
  check('noise_'+direction+'_dynamic',len(set(values))>=2)
  check('noise_'+direction+'_timestamp',all(abs(int.from_bytes(v[4:8],'big')-int(time.time()))<60 for v in values))
  check('noise_'+direction+'_counter',len(set(v[8:12] for v in values))==len(values))
  check('noise_'+direction+'_nonce',len(set(v[12:20] for v in values))==len(values))
 stop(c)
 c=client('h2');check('h2_works_with_server_udp_noise',tcp());stop(c)
 s=copy.deepcopy(BASE);check('noise_disabled_state',apply(s));c=client(serverport=25449);before=sum(map(len,packets.values()));check('noise_disabled_traffic',tcp());time.sleep(1.2);check('no_noise_after_disable',sum(map(len,packets.values()))==before);stop(c)
 # Bounded repeated client lifetimes and a modest concurrent TCP/UDP load.
 c=client();start=time.monotonic();ok=[]
 def load():
  for _ in range(12):ok.append(tcp());ok.append(udp(size=512))
 jobs=[threading.Thread(target=load) for _ in range(3)]
 for t in jobs:t.start()
 for t in jobs:t.join()
 check('parallel_72_tcp_udp_exchanges',len(ok)==72 and all(ok));stop(c)
 for _ in range(6):
  c=client();check('reconnect_'+str(_),tcp());stop(c)
 check('supervisor_alive_after_load',supervisor.poll() is None and status().get('running'))
 s=copy.deepcopy(BASE);s['enabled']=False;check('disable_stops_core',apply(s) and not status().get('running'));check('saved_credentials_unchanged',json.loads(DESIRED.read_text())['users']==BASE['users']);check('reenable_restores_core',apply(copy.deepcopy(BASE)));c=client();check('reenable_restores_traffic',tcp());stop(c)
 stop(supervisor)
 print('NATIVE COMPLETED',len(RESULTS),flush=True)
finally:
 for p in reversed(children):stop(p)
 for s in stops:s.close()
