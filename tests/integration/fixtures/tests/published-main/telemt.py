#!/usr/bin/env python3
import hashlib,hmac,json,os,pathlib,socket,struct,subprocess,time
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
os.umask(0o077);R=pathlib.Path('/opt/vpnbot-hosted-ci/stand');O=R/'results/telemt';O.mkdir(mode=0o700,exist_ok=True);results=[]
def run(*a,timeout=120):return subprocess.run(a,capture_output=True,text=True,timeout=timeout)
def check(n,v,detail=None):
 results.append({'name':n,'passed':v,'detail':detail});(O/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if v else 'FAIL ')+n,flush=True)
def bot(*a):
 r=run('docker','exec','php-audit','php','/tmp/audit-driver.php',*a);r.check_returncode();j=json.loads(r.stdout);check('bot-'+a[0]+'-'+(a[1] if len(a)>1 else ''),not j['warnings']);
 if a[0] in ['telemt-mode','telemt-toggle','telemt-rotate']:
  deadline=time.monotonic()+20
  while time.monotonic()<deadline:
   try:
    with socket.create_connection(('10.10.0.20',443),timeout=.3):break
   except OSError:time.sleep(.25)
 return j['result']
def auth():bot('telemt-export');return json.loads((R/'bot/logs/audit-telemt.json').read_text())
def exact(s,n):
 b=b''
 while len(b)<n:
  d=s.recv(n-len(b))
  if not d:raise EOFError()
  b+=d
 return b

def tls_hello(secret,host):
 def ext(t,b):return struct.pack('!HH',t,len(b))+b
 h=host.encode();sn=b'\0'+struct.pack('!H',len(h))+h
 exts=ext(0,struct.pack('!H',len(sn))+sn)+ext(0x33,struct.pack('!HHH',36,29,32)+b'\x09'+bytes(31))+ext(0x2b,b'\x02\x03\x04')
 body=b'\x03\x03'+bytes(32)+b'\x20'+os.urandom(32)+b'\x00\x02\x13\x01\x01\x00'
 pad=600-(4+len(body)+2+len(exts)+4);exts+=ext(21,bytes(pad));body+=struct.pack('!H',len(exts))+exts
 hello=bytearray(b'\x16\x03\x01'+struct.pack('!H',4+len(body))+b'\x01'+len(body).to_bytes(3,'big')+body)
 d=bytearray(hmac.new(secret,hello,hashlib.sha256).digest());ts=struct.pack('<I',int(time.time()))
 for i in range(4):d[28+i]^=ts[i]
 hello[11:43]=d
 return bytes(hello),bytes(d)

def reqpq(a,timeout=7):
 secret=bytes.fromhex(a['secret']);is_tls=a['mode']=='tls';secure=a['mode']!='classic'
 try:
  with socket.create_connection(('10.10.0.20',443),timeout=timeout) as s:
   if is_tls:
    hello,digest=tls_hello(secret,a['sni']);s.sendall(hello);s.settimeout(.8);resp=bytearray()
    while True:
     try:
      b=s.recv(16384)
      if not b:raise EOFError()
      resp.extend(b)
     except socket.timeout:break
    if len(resp)<43:raise RuntimeError('no TLS reply')
    server_digest=bytes(resp[11:43]);resp[11:43]=bytes(32)
    if not hmac.compare_digest(server_digest,hmac.new(secret,digest+resp,hashlib.sha256).digest()):raise RuntimeError('TLS authenticator mismatch')
    s.sendall(b'\x14\x03\x03\x00\x01\x01')
   s.settimeout(timeout)
   nonce=bytearray(os.urandom(64));nonce[0]=0x42;nonce[56:60]=b'\xdd'*4 if secure else b'\xef'*4;nonce[60:62]=struct.pack('<h',2)
   reverse=bytes(nonce[8:56][::-1]);enc=Cipher(algorithms.AES(hashlib.sha256(nonce[8:40]+secret).digest()),modes.CTR(bytes(nonce[40:56]))).encryptor();dec=Cipher(algorithms.AES(hashlib.sha256(reverse[:32]+secret).digest()),modes.CTR(reverse[32:])).decryptor()
   encoded=enc.update(bytes(nonce));header=bytes(nonce[:56])+encoded[56:];pqnonce=os.urandom(16);body=struct.pack('<I',0xbe7e8ef1)+pqnonce;msg=bytes(8)+struct.pack('<QI',int(time.time()*2**32)&~3,len(body))+body
   frame=struct.pack('<I',len(msg))+msg if secure else bytes([len(msg)//4])+msg
   out=header+enc.update(frame)
   s.sendall(b'\x17\x03\x03'+struct.pack('!H',len(out))+out if is_tls else out)
   buf=bytearray()
   def read(n):
    while len(buf)<n:
     if is_tls:
      h=exact(s,5);d=exact(s,struct.unpack('!H',h[3:])[0]);
      if h[0]!=23:continue
     else:d=s.recv(4096)
     if not d:raise EOFError()
     buf.extend(dec.update(d))
    d=bytes(buf[:n]);del buf[:n];return d
   length=struct.unpack('<I',read(4))[0] if secure else read(1)[0]*4
   if length>8192:raise RuntimeError('invalid response size')
   response=read(length)
   return len(response)>40 and response[20:24]==struct.pack('<I',0x05162463) and response[24:40]==pqnonce,None
 except Exception as e:return False,type(e).__name__+':'+str(e)[:90]

for mode in ['classic','secure','tls']:
 bot('telemt-mode',mode);time.sleep(2);a=auth();ok,detail=reqpq(a);check(mode+'-telegram-req-pq',ok,detail)
 bad=dict(a,secret='f'*32);ok,detail=reqpq(bad,3);check(mode+'-wrong-secret-rejected',not ok)
 bot('telemt-toggle');ok,detail=reqpq(a,3);check(mode+'-disabled-rejected',not ok)
 bot('telemt-toggle');time.sleep(.5);ok,detail=reqpq(a);check(mode+'-enabled-works',ok,detail)
 bot('telemt-rotate');ok,_=reqpq(a,3);check(mode+'-old-secret-rejected',not ok);a=auth();ok,detail=reqpq(a);check(mode+'-new-secret-works',ok,detail)
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}))
raise SystemExit(0 if all(x['passed'] for x in results) else 1)
