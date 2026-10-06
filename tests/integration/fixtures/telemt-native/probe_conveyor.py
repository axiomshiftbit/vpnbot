from pathlib import Path
import sys,os,json,time,concurrent.futures
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'support'))
import probe_limits as p
import probe_relay as r
import probe_carrier_data as d
p.ROOT=HERE/'conveyor-cases';p.ROOT.mkdir(exist_ok=True)
p.BINARY=Path(os.environ['TELEMT_BINARY'])
checks=[]
def check(name,ok,**details):
 checks.append(dict(name=name,ok=bool(ok),**details));(HERE/'conveyor-results.json').write_text(json.dumps(checks,indent=2))
 print(name,'OK' if ok else 'FAIL',flush=True)
 if not ok:raise AssertionError(name)
class Client(d.Client):
 def __init__(self,core):
  self.confirmed=0;self.offer=None;self.page=b''
  super().__init__(core)
 def request(self,method,path,body=None,headers=None):
  headers=dict(headers or {})
  if path=='/api/v1/session':headers['X-Telemt-Up-Window']='4'
  if path in ['/api/v1/up','/api/v1/down']:method=self.core.method
  response=super().request(method,path,body,headers)
  if path.startswith('/?bridge='):self.page=response[2]
  if path=='/api/v1/session':self.offer=response[1].get('x-telemt-up-window')
  return response
 def send_seq(self,seq,data,confirmed):
  return self.request(self.core.method,'/api/v1/up',data,{'Content-Type':'application/octet-stream','X-Up-Seq':str(seq),'X-Telemt-Up-Confirmed':str(confirmed)})
 def up(self,data):
  if 'websocket' in self.core.carrier:return super().up(data)
  if self.offer=='1':return p.Web.up(self,data)
  self.seq+=1
  response=self.send_seq(self.seq,data,self.confirmed)
  if response[0]==204 and response[1].get('x-up-ack')==str(self.seq):self.confirmed=self.seq
  return response
 def receive(self,size,label):
  output=bytearray();replayed=False;end=time.monotonic()+8
  while len(output)<size and time.monotonic()<end:
   cursor=str(self.cursor)
   status,h,body=self.request(self.core.method,'/api/v1/down',b'',{'X-Down-Cursor':cursor})
   if status==200 and not replayed:
    status2,h2,body2=self.request(self.core.method,'/api/v1/down',b'',{'X-Down-Cursor':cursor})
    check(label+'/downlink_exact_replay',status2==status and body2==body and h2.get('x-down-cursor')==h.get('x-down-cursor'))
    replayed=True
   self.cursor=int(h.get('x-down-cursor',self.cursor))
   for typ,sid,payload in p.frames(body):
    if typ==2 and sid==1:output.extend(self.dec.update(payload))
  return bytes(output)
for carrier in ['https','https-lanes']:
 for method in ['POST','PUT']:
  for mode in ['dd','plain']:
   for path in ['', 'audit/path']:
    label='-'.join([carrier,method,mode,'path' if path else 'root'])
    c=p.Core(label,limit=1,quota=400000);c.carrier=carrier;c.secret_mode=mode;c.path=path;c.method=method
    c.config=c.config.replace('carrier = "https"',f'carrier = "{carrier}"\ncarrier_method = "{method.lower()}"').replace('secret_mode = "dd"',f'secret_mode = "{mode}"')
    if path:c.config=c.config.replace('host = "'+p.HOST+'"','host = "'+p.HOST+'"\nbase_path = "'+path+'"')
    (c.root/'telemt.toml').write_text(c.config);front=None
    try:
     c.start();front=r.Front(c).start();client=Client(c);c.children.append(client)
     check(label+'/negotiated_default_conveyor',client.offer=='4')
     check(label+'/bridge_http_method',f"const carrierMethod='{method}'".encode() in client.page)
     first=os.urandom(8192);second=os.urandom(8192)
     head=p.frame(2,1,client.enc.update(first));tail=p.frame(2,1,client.enc.update(second))
     with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
      pending=pool.submit(client.send_seq,3,tail,1);time.sleep(.15)
      check(label+'/future_waits_for_missing_head',not pending.done() and c.used()==0)
      response=client.send_seq(2,head,1);response2=pending.result(timeout=5)
     check(label+'/ordered_acknowledgements',response[0]==204 and response[1].get('x-up-ack')=='2' and response2[0]==204 and response2[1].get('x-up-ack')=='3')
     replay=client.send_seq(2,head,1)
     check(label+'/uplink_replay_ack',replay[0]==204 and replay[1].get('x-up-ack')=='2')
     client.seq=3;client.confirmed=3
     check(label+'/encrypted_payload_order',client.receive(len(first)+len(second),label)==first+second)
     check(label+'/no_double_quota_on_replay',c.used()==2*(len(first)+len(second)),used=c.used())
     check(label+'/native_web_share_ip_slot',c.native('127.0.0.3').echo()==b'')
     payload=os.urandom(192*1024)
     try:out=client.echo(payload)
     except (OSError,EOFError):out=b''
     check(label+'/quota_blocks_conveyor',len(out)<len(payload) and c.used()<=400000)
    finally:
     c.close()
     if front:front.close()
for carrier in ['https','https-lanes','websocket','websocket-lanes']:
 label='disabled-'+carrier;c=p.Core(label,limit=1,quota=400000);c.carrier=carrier;c.secret_mode='dd';c.path='';c.method='PUT'
 c.config=c.config.replace('carrier = "https"',f'carrier = "{carrier}"\ncarrier_method = "put"\nconveyor = false');(c.root/'telemt.toml').write_text(c.config);front=None
 try:
  c.start();front=r.Front(c).start();client=Client(c);c.children.append(client)
  check(label+'/single_request_window',client.offer=='1')
  check(label+'/legacy_echo',client.echo()==b'test-data'*8)
  check(label+'/legacy_accounting',c.used()==144)
 finally:
  c.close()
  if front:front.close()
print('TOTAL',len(checks))
