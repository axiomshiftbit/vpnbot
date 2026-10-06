import base64,hashlib,hmac,json,os,re,socket,struct,time
import probe_limits as p
import probe_relay as r
results=[]
def check(name,ok,**detail):
 results.append(dict(name=name,ok=bool(ok),**detail));(p.ROOT/'carrier-data-results.json').write_text(json.dumps(results,indent=2))
 print(name+': '+('OK' if ok else 'FAIL'),flush=True)
 if not ok:raise AssertionError(name)
class Client(r.TLSWeb):
 def __init__(self,core):
  self.core,self.ip,self.source=core,'198.51.100.99','127.0.0.2';self.seq=0;self.cursor=0;self.token='';self.closed=False;self.ws=None
  ctx='tdesktop-web-proxy-bridge-v'+('2\n'+p.HOST+'\n'+core.path if core.path else '1\n'+p.HOST)
  cap=base64.urlsafe_b64encode(hmac.new((b'\xdd' if core.secret_mode=='dd' else b'')+p.SECRET,ctx.encode(),hashlib.sha256).digest()).decode().rstrip('=')
  _,_,body=self.request('GET','/?bridge='+cap);boot=re.search(rb'let bootstrap="([A-Za-z0-9_-]{43})"',body)
  if not boot:raise RuntimeError('No bootstrap')
  _,headers,_=self.request('POST','/api/v1/session',p.frame(0x10,payload=b'\1'),{'Authorization':'Bearer '+boot[1].decode(),'Content-Type':'application/octet-stream'})
  self.token=headers.get('x-session-token','')
  if not self.token:raise RuntimeError('No session')
  raw=bytearray(os.urandom(64));raw[0]=0x42;raw[56:60]=(b'\xdd' if core.secret_mode=='dd' else b'\xee')*4;raw[60:62]=struct.pack('<h',2)
  self.enc=p.aes(hashlib.sha256(raw[8:40]+p.SECRET).digest(),bytes(raw[40:56]));rev=raw[8:56][::-1];self.dec=p.aes(hashlib.sha256(rev[:32]+p.SECRET).digest(),bytes(rev[32:]))
  enc=self.enc.update(bytes(raw));hello=bytes(raw[:56])+enc[56:]
  self.up(p.frame(1,1)+p.frame(2,1,hello))
 def request(self,method,path,body=None,headers=None):
  headers=dict(headers or {})
  if self.core.carrier=='https-lanes' and path in ['/api/v1/up','/api/v1/down']:headers['X-Lane-Id']='1'
  if self.core.path:path='/'+self.core.path+path
  return super().request(method,path,body,headers)
 def open_ws(self):
  raw=socket.create_connection(('127.0.0.1',self.core.front),3,(self.source,0));self.ws=self.core.tlscontext.wrap_socket(raw,server_hostname=p.HOST)
  key=base64.b64encode(os.urandom(16)).decode();proto=('tproxy-lane-v1.'+self.token+'.1') if self.core.carrier=='websocket-lanes' else 'tproxy-v1.'+self.token
  path=('/'+self.core.path if self.core.path else '')+'/api/v1/ws'
  self.ws.sendall(('GET '+path+' HTTP/1.1\r\nHost: '+p.HOST+'\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: '+key+'\r\nSec-WebSocket-Protocol: '+proto+'\r\n\r\n').encode())
  head=b''
  while not head.endswith(b'\r\n\r\n'):head+=p.exact(self.ws,1)
  accept=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
  if not head.startswith(b'HTTP/1.1 101') or accept not in head:raise RuntimeError('Invalid websocket upgrade')
 def send_ws(self,data,op=2):
  mask=os.urandom(4);n=len(data);head=bytes([128|op])
  head+=(bytes([128|n]) if n<126 else b'\xfe'+struct.pack('>H',n) if n<=65535 else b'\xff'+struct.pack('>Q',n))
  self.ws.sendall(head+mask+bytes(b^mask[i%4] for i,b in enumerate(data)))
 def up(self,data):
  if 'websocket' not in self.core.carrier:return super().up(data)
  if not self.ws:self.open_ws()
  self.send_ws(data)
 def echo(self,data=b'test-data'*8):
  if 'websocket' not in self.core.carrier:return super().echo(data)
  self.up(p.frame(2,1,self.enc.update(data)));out=bytearray();pending=b'';end=time.monotonic()+4
  while len(out)<len(data) and time.monotonic()<end:
   h=p.exact(self.ws,2);op=h[0]&15;n=h[1]&127
   if n==126:n=int.from_bytes(p.exact(self.ws,2),'big')
   elif n==127:n=int.from_bytes(p.exact(self.ws,8),'big')
   b=p.exact(self.ws,n)
   if op==9:self.send_ws(b,10);continue
   if op==8:break
   if op not in (0,2):raise RuntimeError('Unexpected WS opcode')
   pending+=b
   if not h[0]&128:continue
   for t,sid,payload in p.frames(pending):
    if t==2 and sid==1:out.extend(self.dec.update(payload))
    elif t==3 and sid==1:self.closed=True
   pending=b''
   if self.closed:break
  return bytes(out)
 def close(self):
  if self.ws:self.ws.close();self.ws=None
  super().close()
if __name__=='__main__':
 for carrier in ['https','https-lanes','websocket','websocket-lanes']:
  for secret_mode in ['dd','plain']:
   for path in ['', 'test-path']:
    label=carrier+'-'+secret_mode+'-'+('path' if path else 'root');p.HOST=r.ORIGIN
    c=p.Core('data-'+label,limit=1,quota=400000);c.carrier=carrier;c.secret_mode=secret_mode;c.path=path
    c.config=c.config.replace('carrier = "https"','carrier = "'+carrier+'"').replace('secret_mode = "dd"','secret_mode = "'+secret_mode+'"')
    if path:c.config=c.config.replace('host = "'+p.HOST+'"','host = "'+p.HOST+'"\nbase_path = "'+path+'"')
    (c.root/'telemt.toml').write_text(c.config);c.start();front=None
    try:
     front=r.Front(c).start();client=Client(c);c.children.append(client)
     check(label+'/small_echo',client.echo()==b'test-data'*8)
     payload=os.urandom(192*1024);check(label+'/large_echo',client.echo(payload)==payload)
     check(label+'/actual_usage',c.used()==2*(len(payload)+72),used=c.used())
     try:received=client.echo(os.urandom(16384))
     except (OSError,EOFError):received=b''
     check(label+'/quota_blocks_oversized_transfer',len(received)<16384)
     check(label+'/quota_never_exceeded',c.used()<=400000,used=c.used())
    finally:
     c.close()
     if front:front.close()
 print(json.dumps({'checks':len(results),'passed':sum(x['ok'] for x in results)}))
