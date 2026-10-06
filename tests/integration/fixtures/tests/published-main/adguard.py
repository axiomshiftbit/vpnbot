#!/usr/bin/env python3
import base64,http.client,json,os,pathlib,socket,ssl,struct,subprocess,time,urllib.parse
os.umask(0o077);R=pathlib.Path('/opt/vpnbot-hosted-ci/stand');O=R/'results/adguard';O.mkdir(mode=0o700,exist_ok=True);results=[]
def check(n,v,detail=None):
 results.append({'name':n,'passed':bool(v),'detail':detail});(O/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if v else 'FAIL ')+n,flush=True)
def bot(a):
 r=subprocess.run(['docker','exec','php-audit','php','/tmp/audit-driver.php',a],capture_output=True,text=True,timeout=120);r.check_returncode();j=json.loads(r.stdout);check('bot-'+a,not j['warnings'])
bot('ad-sync');bot('ad-export');time.sleep(2);a=json.loads((R/'bot/logs/audit-ad.json').read_text());context=ssl.create_default_context(cafile=str(R/'bot/certs/cert_public'))
class Front(http.client.HTTPSConnection):
 def connect(self):self.sock=self._context.wrap_socket(socket.create_connection(('10.10.0.10',443),timeout=15),server_hostname=self.host)
def req(path,method='GET',body=None,headers=None):
 c=Front(a['domain'],context=context,timeout=15);c.request(method,path,body,headers or {});r=c.getresponse();out=r.status,dict(r.getheaders()),r.read();c.close();return out
def query(name='example.com'):
 return os.urandom(2)+b'\1\0\0\1'+bytes(6)+b''.join(bytes([len(s)])+s.encode() for s in name.split('.'))+b'\0\0\1\0\1'
def valid(q,r):return len(r)>12 and r[:2]==q[:2] and r[2]&128 and r[3]&15==0 and int.from_bytes(r[6:8],'big')>0
def exact(s,n):
 b=b''
 while len(b)<n:
  x=s.recv(n-len(b))
  if not x:raise EOFError()
  b+=x
 return b
for transport in ['udp','tcp','tls']:
 q=query()
 try:
  if transport=='udp':
   with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:s.settimeout(8);s.sendto(q,('10.10.0.5',53));r=s.recv(4096)
  else:
   with socket.create_connection(('10.10.0.5',853 if transport=='tls' else 53),timeout=8) as raw:
    s=context.wrap_socket(raw,server_hostname=a['domain']) if transport=='tls' else raw;s.sendall(struct.pack('!H',len(q))+q);r=exact(s,int.from_bytes(exact(s,2),'big'))
  check('dns-'+transport,valid(q,r))
 except Exception as e:check('dns-'+transport,False,type(e).__name__)
path='/dns-query'+a['hash']+'/'+a['doh_id'];q=query();s,h,r=req(path,'POST',q,{'Content-Type':'application/dns-message'});check('doh-post',s==200 and valid(q,r),s)
s,h,r=req(path+'?dns='+base64.urlsafe_b64encode(q).decode().rstrip('='));check('doh-get',s==200 and valid(q,r),s)
prefix='/adguard'+a['hash'];cookie={'Cookie':'c='+a['hash']};auth={**cookie,'Authorization':'Basic '+base64.b64encode(('admin:'+a['password']).encode()).decode()}
s,_,_=req(prefix+'/control/status',headers=cookie);check('admin-cookie-alone-insufficient',s in [401,403],s)
s,_,_=req(prefix+'/control/status',headers={**cookie,'Authorization':'Basic '+base64.b64encode(b'admin:wrong-password').decode()});check('admin-wrong-password-rejected',s in [401,403],s)
s,_,b=req(prefix+'/control/status',headers=auth);check('admin-real-password',s==200 and 'version' in json.loads(b),s)
s,_,b=req(prefix+'/control/filtering/status',headers=auth);check('filtering-api',s==200);old=json.loads(b).get('user_rules',[])
try:
 rule='||vpnbot-audit-block.example^';body=json.dumps({'rules':old+[rule]}).encode();s,_,_=req(prefix+'/control/filtering/set_rules','POST',body,{**auth,'Content-Type':'application/json'});check('add-dns-filter',s==200)
 time.sleep(2);s,_,b=req(prefix+'/control/filtering/check_host?name=vpnbot-audit-block.example',headers=auth);j=json.loads(b);check('filter-matches',s==200 and j.get('reason','').startswith('Filtered'),j.get('reason'))
finally:req(prefix+'/control/filtering/set_rules','POST',json.dumps({'rules':old}).encode(),{**auth,'Content-Type':'application/json'})
subprocess.run(['docker','restart','adguard-audit'],capture_output=True,check=True);time.sleep(3);q=query();s,_,r=req(path,'POST',q,{'Content-Type':'application/dns-message'});check('doh-survives-container-restart',s==200 and valid(q,r))
s,_,_=req(prefix+'/control/status',headers=auth);check('admin-password-survives-restart',s==200)
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}));raise SystemExit(0 if all(x['passed'] for x in results) else 1)
