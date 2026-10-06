from pathlib import Path
import base64, hashlib, hmac, http.client, json, os, re, socket, socketserver, struct, subprocess, threading, time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
ROOT=Path(__file__).resolve().parent
BINARY=Path(os.environ['TELEMT_BINARY'])
HOST='web.audit.example'
SECRET=bytes.fromhex('00112233445566778899aabbccddeeff')
BOB=bytes.fromhex('ffeeddccbbaa99887766554433221100')
results=[]
def check(name,ok,**detail):
 results.append(dict(name=name,ok=bool(ok),**detail));(ROOT/'limits-results.json').write_text(json.dumps(results,indent=2))
 print(name+': '+('OK' if ok else 'FAIL')+((' '+json.dumps(detail)) if detail else ''),flush=True)
 if not ok:raise AssertionError(name)
def wait(fn,seconds=3):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  v=fn()
  if v:return v
  time.sleep(.03)
 return False
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def aes(key,iv):return Cipher(algorithms.AES(key),modes.CTR(iv)).encryptor()
def exact(s,n):
 out=b''
 while len(out)<n:
  b=s.recv(n-len(out))
  if not b:raise EOFError()
  out+=b
 return out
def client_crypto(secret=SECRET):
 b=bytearray(os.urandom(64));b[0]=0x42;b[56:60]=b'\xdd'*4;b[60:62]=struct.pack('<h',2)
 enc=aes(hashlib.sha256(b[8:40]+secret).digest(),bytes(b[40:56]));rev=b[8:56][::-1]
 dec=aes(hashlib.sha256(rev[:32]+secret).digest(),bytes(rev[32:]))
 encrypted=enc.update(bytes(b));return bytes(b[:56])+encrypted[56:],enc,dec
class DC(socketserver.BaseRequestHandler):
 def handle(self):
  s=self.request;s.settimeout(6)
  try:
   ver,n=exact(s,2);exact(s,n);s.sendall(b'\5\0');head=exact(s,4)
   if head[3]==1:exact(s,4)
   elif head[3]==4:exact(s,16)
   elif head[3]==3:exact(s,exact(s,1)[0])
   exact(s,2);s.sendall(b'\5\0\0\1\x7f\0\0\1\0\0')
   nonce=exact(s,64);dec=aes(nonce[8:40],nonce[40:56]);dec.update(nonce);rev=nonce[8:56][::-1];enc=aes(rev[:32],rev[32:])
   while True:
    b=s.recv(65536)
    if not b:break
    s.sendall(enc.update(dec.update(b)))
  except (OSError,EOFError):pass
class DCS(socketserver.ThreadingTCPServer):
 allow_reuse_address=True;daemon_threads=True
class Core:
 def __init__(self,name,limit=1,quota=1000000,policy='active_window',window=1):
  self.root=ROOT/name;self.root.mkdir(exist_ok=True);(self.root/'decoy').mkdir(exist_ok=True)
  (self.root/'quota.json').unlink(missing_ok=True)
  (self.root/'decoy/index.html').write_text('<!doctype html><title>Cover</title>Cover')
  self.n,self.w,self.a=port(),port(),port();self.dc=DCS(('127.0.0.1',0),DC)
  threading.Thread(target=self.dc.serve_forever,daemon=True).start();self.proc=None;self.children=[]
  self.config=f'''[general]
log_level = "normal"
disable_colors = true
use_middle_proxy = false
fast_mode = true
quota_state_path = "{self.root}/quota.json"
[general.modes]
classic = false
secure = true
tls = false
[server]
port = {self.n}
listen_addr_ipv4 = "127.0.0.1"
[server.api]
enabled = true
listen = "127.0.0.1:{self.a}"
whitelist = ["127.0.0.1/32"]
read_only = false
[[server.listeners]]
ip = "127.0.0.1"
port = {self.n}
[[server.listeners]]
ip = "127.0.0.1"
port = {self.w}
transport = "web"
proxy_protocol = false
web_client_ip_source = "x_forwarded_for"
web_trusted_proxy_cidrs = ["127.0.0.1/32"]
[network]
ipv6 = false
stun_use = false
http_ip_detect_urls = []
[censorship]
tls_domain = "localhost"
mask = false
tls_emulation = false
[access]
user_max_unique_ips_mode = "{policy}"
user_max_unique_ips_window_secs = {window}
[access.users]
alice = "{SECRET.hex()}"
bob = "{BOB.hex()}"
[access.user_max_unique_ips]
alice = {limit}
'''+(('\n[access.user_data_quota]\nalice = '+str(quota)+'\n') if quota is not None else '')+f'''
[[upstreams]]
type = "socks5"
address = "127.0.0.1:{self.dc.server_address[1]}"
enabled = true
weight = 10
[web]
enabled = true
carrier = "https"
[web.timeouts]
long_poll_secs = 1
lane_open_wait_secs = 1
[[web.vhosts]]
host = "{HOST}"
public_addr = "203.0.113.10:443"
[web.vhosts.decoy]
mode = "static_directory"
directory = "{self.root}/decoy"
[[web.vhosts.profiles]]
user = "alice"
secret_mode = "dd"
[[web.vhosts.profiles]]
user = "bob"
secret_mode = "dd"
'''
  (self.root/'telemt.toml').write_text(self.config)
 def start(self):
  self.log=(self.root/'process.log').open('ab')
  self.proc=subprocess.Popen([str(BINARY),'run','--data-path',str(self.root/'data'),str(self.root/'telemt.toml')],cwd=self.root,stdout=self.log,stderr=self.log)
  def ready():
   if self.proc.poll() is not None:raise RuntimeError('Core exited: '+str(self.root))
   try:return self.api('/v1/health')[0]==200
   except OSError:return False
  if not wait(ready,5):raise RuntimeError('Core unavailable')
  return self
 def stop(self,kill=False):
  if self.proc and self.proc.poll() is None:
   (self.proc.kill if kill else self.proc.terminate)()
   try:self.proc.wait(8)
   except subprocess.TimeoutExpired:self.proc.kill();self.proc.wait()
  if hasattr(self,'log'):self.log.close()
 def close(self):
  for child in self.children:child.close()
  self.stop();self.dc.shutdown();self.dc.server_close()
 def api(self,path,method='GET',body=None):
  c=http.client.HTTPConnection('127.0.0.1',self.a,timeout=3)
  try:
   c.request(method,path,json.dumps(body) if body is not None else None,{'Content-Type':'application/json'});r=c.getresponse();data=r.read();return r.status,json.loads(data)
  finally:c.close()
 def user(self):return self.api('/v1/users/alice')[1]['data']
 def used(self):
  users=self.api('/v1/stats/users/quota')[1]['data']['users']
  return next((u['used_bytes'] for u in users if u['username']=='alice'),None)
 def native(self,ip='127.0.0.2',secret=SECRET):
  c=Native(self,ip,secret);self.children.append(c);return c
 def web(self,ip='198.51.100.1',secret=SECRET,source='127.0.0.1'):
  c=Web(self,ip,secret,source);self.children.append(c);return c
class Native:
 def __init__(self,core,ip,secret):
  self.s=socket.socket();self.s.settimeout(2);self.s.bind((ip,0));self.s.connect(('127.0.0.1',core.n))
  hello,self.enc,self.dec=client_crypto(secret);self.s.sendall(hello)
 def echo(self,data=b'test-data'*8):
  try:
   self.s.sendall(self.enc.update(data));out=bytearray()
   while len(out)<len(data):
    b=self.s.recv(len(data)-len(out))
    if not b:break
    out.extend(self.dec.update(b))
   return bytes(out)
  except OSError:return b''
 def close(self):
  try:self.s.shutdown(socket.SHUT_RDWR)
  except OSError:pass
  self.s.close()
def frame(t,sid=0,payload=b''):return bytes([t])+sid.to_bytes(3,'big')+len(payload).to_bytes(4,'big')+payload
def frames(body):
 out=[]
 while len(body)>=8:
  n=int.from_bytes(body[4:8],'big');out.append((body[0],int.from_bytes(body[1:4],'big'),body[8:8+n]));body=body[8+n:]
 return out
class Web:
 def __init__(self,core,ip,secret,source):
  self.core,self.ip,self.source=core,ip,source;self.seq=0;self.cursor=0;self.token='';self.closed=False
  ctx='tdesktop-web-proxy-bridge-v1\n'+HOST
  cap=base64.urlsafe_b64encode(hmac.new(b'\xdd'+secret,ctx.encode(),hashlib.sha256).digest()).decode().rstrip('=')
  status,heads,body=self.request('GET','/?bridge='+cap)
  boot=re.search(rb'let bootstrap="([A-Za-z0-9_-]{43})"',body)
  if not boot:raise RuntimeError('No bootstrap')
  status,heads,body=self.request('POST','/api/v1/session',frame(0x10,payload=b'\1'),{'Authorization':'Bearer '+boot[1].decode(),'Content-Type':'application/octet-stream'})
  self.token=heads.get('x-session-token','')
  if not self.token:raise RuntimeError('No session token')
  hello,self.enc,self.dec=client_crypto(secret)
  self.up(frame(1,1)+frame(2,1,hello))
 def request(self,method,path,body=None,headers=None):
  c=http.client.HTTPConnection('127.0.0.1',self.core.w,timeout=3,source_address=(self.source,0))
  h={'Host':HOST,'X-Forwarded-For':self.ip};h.update(headers or {})
  if self.token:h['Authorization']='Bearer '+self.token
  try:
   c.request(method,path,body,h);r=c.getresponse();return r.status,{k.lower():v for k,v in r.getheaders()},r.read()
  finally:c.close()
 def up(self,data):
  self.seq+=1;return self.request('POST','/api/v1/up',data,{'Content-Type':'application/octet-stream','X-Up-Seq':str(self.seq)})
 def echo(self,data=b'test-data'*8):
  if self.closed:return b''
  self.up(frame(2,1,self.enc.update(data)));out=bytearray();end=time.monotonic()+3
  while len(out)<len(data) and time.monotonic()<end:
   status,h,body=self.request('POST','/api/v1/down',b'',{'X-Down-Cursor':str(self.cursor)})
   self.cursor=int(h.get('x-down-cursor',self.cursor))
   for t,sid,payload in frames(body):
    if t==2 and sid==1:out.extend(self.dec.update(payload))
    elif t==3 and sid==1:self.closed=True
   if self.closed:break
  return bytes(out)
 def close(self):
  if self.token:
   try:self.request('DELETE','/api/v1/session')
   except OSError:pass
   self.token=''

if __name__=='__main__':
 c=Core('ip-active').start()
 try:
  n=c.native();check('native_echo',n.echo()==b'test-data'*8)
  w=c.web('127.0.0.2');check('same_ip_native_web_allowed',w.echo()==b'test-data'*8)
  check('same_ip_counts_once',c.user()['active_unique_ips']==1)
  blocked=c.native('127.0.0.3');check('native_second_ip_rejected',blocked.echo()==b'')
  wb=c.web('198.51.100.2');check('web_second_ip_rejected',wb.echo()==b'')
  bob=c.web('198.51.100.2',BOB);check('other_user_unaffected',bob.echo()==b'test-data'*8)
  n.close();check('ip_held_until_last_stream',c.web('198.51.100.2').echo()==b'')
  w.close();check('ip_slot_released',bool(wait(lambda:c.user()['active_unique_ips']==0)))
  other=c.web('2001:db8::5');check('ipv6_forwarded_ip_accepted',other.echo()==b'test-data'*8)
  check('ipv6_counted',c.user()['active_unique_ips_list']==['2001:db8::5'])
  other.close();wait(lambda:c.user()['active_unique_ips']==0)
  rejected=False
  try:c.web('198.51.100.99',source='127.0.0.4')
  except RuntimeError as e:rejected=str(e)=='No bootstrap'
  check('untrusted_forwarder_rejected',rejected and c.user()['active_unique_ips']==0)
  # Runtime update instead of process restart. This changes only the isolated fixture TOML.
  before=c.proc.pid
  status,reply=c.api('/v1/users/alice?reload=true','PATCH',{'max_unique_ips':2})
  check('ip_limit_api_patch_accepted',status in (200,202),status=status)
  time.sleep(.4)
  a=c.native('127.0.0.2');b=c.web('198.51.100.2')
  check('hot_reload_two_ips_admitted',a.echo()==b'test-data'*8 and b.echo()==b'test-data'*8)
  check('hot_reload_same_process',c.proc.pid==before and c.proc.poll() is None)
 finally:c.close()
 for policy in ['time_window','combined']:
  c=Core('ip-'+policy,policy=policy,window=2).start()
  try:
   a=c.native();check(policy+'/first',a.echo()==b'test-data'*8);a.close();wait(lambda:c.user()['active_unique_ips']==0)
   b=c.web();check(policy+'/recent_ip_blocks',b.echo()==b'');b.close();time.sleep(2.1)
   d=c.web();check(policy+'/window_expires',d.echo()==b'test-data'*8)
  finally:c.close()
 for transport in ['native','web']:
  c=Core('quota-'+transport,limit=0,quota=1024).start()
  try:
   s=getattr(c,transport)();check(transport+'/under_quota',s.echo()==b'test-data'*8)
   check(transport+'/counts_both_directions',c.used()==144,used=c.used())
   got=s.echo(b'x'*4096);wait(lambda:c.used()>=1024)
   check(transport+'/hard_quota_caps_traffic',c.used()==1024 and len(got)<4096,used=c.used(),received=len(got))
   check(transport+'/new_stream_denied',getattr(c,transport)().echo()==b'')
   other=c.web(secret=BOB);check(transport+'/other_user_quota_independent',other.echo()==b'test-data'*8)
   c.stop();check(transport+'/graceful_state_saved',json.loads((c.root/'quota.json').read_text())['users']['alice']['used_bytes']==1024)
   c.start();check(transport+'/graceful_restart_retains_quota',c.used()==1024 and getattr(c,transport)().echo()==b'')
   status,reply=c.api('/v1/users/alice/reset-quota','POST');check(transport+'/reset_api',status==200 and c.used()==0)
   s=getattr(c,transport)();check(transport+'/access_after_reset',s.echo()==b'test-data'*8)
   spent=c.used();c.stop(kill=True);c.start()
   check(transport+'/forced_kill_loses_uncheckpointed_usage',spent==144 and c.used()==0,before=spent,after=c.used())
  finally:c.close()
 c=Core('quota-zero',limit=0,quota=0).start()
 try:
  check('zero_quota_denies_native',c.native().echo()==b'')
  check('zero_quota_denies_web',c.web().echo()==b'')
 finally:c.close()
 print(json.dumps({'checks':len(results),'passed':sum(x['ok'] for x in results)}))
