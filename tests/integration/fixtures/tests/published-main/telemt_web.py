#!/usr/bin/env python3
import base64,hashlib,hmac,http.client,json,os,pathlib,re,socket,ssl,struct,subprocess,time,urllib.parse
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
os.umask(0o077);R=pathlib.Path('/opt/vpnbot-hosted-ci/stand');O=R/'results/telemt-web';O.mkdir(mode=0o700,exist_ok=True);results=[]
def check(n,v,detail=None):
 results.append({'name':n,'passed':bool(v),'detail':detail});(O/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if v else 'FAIL ')+n,flush=True)
def bot(*a):
 p=subprocess.run(['docker','exec','php-audit','php','/tmp/audit-driver.php',*a],capture_output=True,text=True,timeout=150);p.check_returncode();j=json.loads(p.stdout);check('bot-'+a[0]+'-'+'-'.join(a[1:]),not j['warnings']);return j['result']
class Front(http.client.HTTPSConnection):
 def connect(self):self.sock=self._context.wrap_socket(socket.create_connection(('10.10.0.10',443),timeout=self.timeout),server_hostname=self.host)
context=ssl.create_default_context(cafile=str(R/'bot/certs/cert_public'))
def req(host,path,method='GET',body=None,headers=None,timeout=45):
 c=Front(host,context=context,timeout=timeout);c.request(method,path,body,headers or {});r=c.getresponse();out=(r.status,{k.lower():v for k,v in r.getheaders()},r.read());c.close();return out
def bridge_req(host,path,label):
 # Settings restart the WEB listener asynchronously. A gateway response during
 # startup is not readiness; retain every probe and fail if it never recovers.
 deadline=time.monotonic()+30;attempts=[];last=None
 while True:
  remaining=deadline-time.monotonic()
  if remaining<=0:return last
  last=req(host,path,timeout=min(3,remaining))
  attempts.append({'status':last[0],'size':len(last[2]),'elapsed':round(30-(deadline-time.monotonic()),3)})
  (O/(label+'-readiness.json')).write_text(json.dumps(attempts,indent=2))
  if last[0] not in (502,503,504):return last
  time.sleep(min(.25,max(0,deadline-time.monotonic())))
def frame(t,i=0,b=b''):return bytes([t])+i.to_bytes(3,'big')+len(b).to_bytes(4,'big')+b
def inner(secret,secure):
 n=bytearray(os.urandom(64));n[0]=0x42;n[56:60]=bytes([0xdd if secure else 0xef])*4;n[60:62]=struct.pack('<h',2);rev=bytes(n[8:56][::-1]);enc=Cipher(algorithms.AES(hashlib.sha256(n[8:40]+secret).digest()),modes.CTR(bytes(n[40:56]))).encryptor();dec=Cipher(algorithms.AES(hashlib.sha256(rev[:32]+secret).digest()),modes.CTR(rev[32:])).decryptor();hdr=enc.update(bytes(n));pq=os.urandom(16);body=struct.pack('<I',0xbe7e8ef1)+pq;msg=bytes(8)+struct.pack('<QI',int(time.time()*2**32)&~3,len(body))+body;prefix=struct.pack('<I',len(msg)) if secure else bytes([len(msg)//4]);return bytes(n[:56])+hdr[56:]+enc.update(prefix+msg),dec,pq
for mode in ['dd','plain']:
 for carrier in ['https','https-lanes']:
  label=mode+'-'+carrier;bot('telemt-web-config',mode,carrier);time.sleep(8);bot('telemt-export');a=json.loads((R/'bot/logs/audit-telemt.json').read_text());q=urllib.parse.parse_qs(urllib.parse.urlparse(a['web']).query);host=q['server'][0];secret=bytes.fromhex(q['secret'][0]);cap=base64.urlsafe_b64encode(hmac.new(secret,b'tdesktop-web-proxy-bridge-v1\n'+host.encode(),hashlib.sha256).digest()).decode().rstrip('=')
  s,h,b=bridge_req(host,'/?bridge='+cap,label);m=re.search(rb'let bootstrap="([A-Za-z0-9_-]{43})"',b);check(label+'-trusted-tls-bridge',s==200 and m is not None,{'status':s,'size':len(b)})
  if not m:continue
  check(label+'-bridge-not-cached','no-store' in h.get('cache-control',''))
  _,_,bad=req(host,'/?bridge='+'Z'*43);check(label+'-wrong-capability-decoy',b'let bootstrap=' not in bad)
  _,bh,bb=req(host,'/api/v1/session','POST',frame(0x10,0,b'\1'),{'Authorization':'Bearer '+'Z'*43,'Content-Type':'application/octet-stream'});check(label+'-wrong-bootstrap-rejected','x-session-token' not in bh)
  s,h,b=req(host,'/api/v1/session','POST',frame(0x10,0,b'\1'),{'Authorization':'Bearer '+m[1].decode(),'Content-Type':'application/octet-stream'});token=h.get('x-session-token','');check(label+'-session',s==200 and b==frame(0x11) and len(token)==43 and h.get('x-carrier-mode')==carrier)
  if not token:continue
  data,dec,pq=inner(bytes.fromhex(a['secret']),mode=='dd');up={'Authorization':'Bearer '+token,'Content-Type':'application/octet-stream','X-Up-Seq':'1'};down={'Authorization':'Bearer '+token,'X-Down-Cursor':'0'}
  if carrier=='https-lanes':up['X-Lane-ID']='1';down['X-Lane-ID']='1'
  s,_,_=req(host,'/api/v1/up','POST',frame(1,1)+frame(2,1,data),up);check(label+'-uplink',s==204)
  received=bytearray()
  for _ in range(4):
   s,h,b=req(host,'/api/v1/down','POST',b'',down);down['X-Down-Cursor']=h.get('x-down-cursor',down['X-Down-Cursor']);off=0
   while off+8<=len(b):
    kind=b[off];length=int.from_bytes(b[off+4:off+8],'big');payload=b[off+8:off+8+length];off+=8+length
    if kind==2:received.extend(dec.update(payload))
   if len(received)>40:break
  skip=4 if mode=='dd' else 1;msg=received[skip:];check(label+'-telegram-res-pq',len(msg)>40 and msg[20:24]==struct.pack('<I',0x05162463) and msg[24:40]==pq,{'status':s,'bytes':len(received)})
  s,_,_=req(host,'/api/v1/session','DELETE',b'',{'Authorization':'Bearer '+token});check(label+'-session-close',s==204)
  _,h,_=req(host,'/api/v1/up','POST',frame(3,1),up);check(label+'-closed-token-rejected','x-up-ack' not in h)
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}));raise SystemExit(0 if all(x['passed'] for x in results) else 1)
