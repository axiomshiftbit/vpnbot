#!/usr/bin/env python3
import copy, json, os, pathlib, re, subprocess, sys, time, tomllib
from proxy_helpers import UDP as EXTERNAL_UDP
ROOT=pathlib.Path('/opt/vpnbot-hosted-ci/stand');OUT=ROOT/'results/proxies';OUT.mkdir(mode=0o700,exist_ok=True)
os.umask(0o077);C='vpnbot-audit-wgclient';results=[]
def run(*a,timeout=45): return subprocess.run(a,capture_output=True,text=True,timeout=timeout)
def exe(*a,**kw): return run('docker','exec',C,*a,**kw)
def bot(a):
 r=run('docker','exec','php-audit','php','/tmp/audit-driver.php',a,timeout=120);r.check_returncode();return json.loads(r.stdout)['result']
def check(n,a,e=True):
 ok=a==e;results.append(dict(name=n,passed=ok,actual=a,expected=e));(OUT/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if ok else 'FAIL ')+n,flush=True)
def save(n,r): (OUT/(n+'.log')).write_text(r.stdout+r.stderr)
def put(name,c):
 p=OUT/name;p.write_text(json.dumps(c,indent=2));run('docker','cp',str(p),C+':/tmp/audit-proxy.json').check_returncode()
def stop():
 exe('pkill','-x','sing-box');exe('pkill','-x','mihomo');time.sleep(.15)
def start(kind,label,config):
 stop();put(label+'.json',config)
 args=['sing-box','check','-c','/tmp/audit-proxy.json'] if kind=='sing-box' else ['mihomo','-t','-d','/tmp/audit-mihomo','-f','/tmp/audit-proxy.json']
 r=exe(*args);save(label+'-parse',r);check(label+'-parse',r.returncode,0)
 if r.returncode:return False
 cmd='sing-box run -c /tmp/audit-proxy.json' if kind=='sing-box' else 'mihomo -d /tmp/audit-mihomo -f /tmp/audit-proxy.json'
 run('docker','exec','-d','-e','SSL_CERT_FILE=/tmp/audit-proxy-ca.crt',C,'sh','-c',cmd+' >/tmp/audit-proxy.log 2>&1').check_returncode();time.sleep(.6)
 return True
def profile(kind,node):
 if kind=='sing-box':
  return {'log':{'level':'warn'},'inbounds':[{'type':'mixed','listen':'127.0.0.1','listen_port':1089}],'outbounds':[node]}
 node['name']='proxy';return {'mixed-port':1089,'bind-address':'127.0.0.1','log-level':'warning','mode':'rule','proxies':[node],'rules':['MATCH,proxy']}
def http(url,timeout=12): return exe('curl','-4','--socks5-hostname','127.0.0.1:1089','--noproxy','','-sS','--max-time',str(timeout),url,timeout=timeout+5)
# A single datagram to the isolated responder verifies UDP without depending on
# Internet packet delivery. External DNS additionally uses bounded DNS retries.
CONTROLLED_UDP=r'''import os,socket,struct
def read(s,n):
 b=b''
 while len(b)<n:
  c=s.recv(n-len(b))
  if not c:raise RuntimeError('eof')
  b+=c
 return b
with socket.create_connection(('127.0.0.1',1089),timeout=5) as s:
 s.sendall(b'\x05\x01\x00');assert read(s,2)==b'\x05\x00';s.sendall(b'\x05\x03\x00\x01'+bytes(6));h=read(s,4);assert h[1]==0;read(s,4 if h[3]==1 else 16 if h[3]==4 else read(s,1)[0]);p=struct.unpack('!H',read(s,2))[0]
 ident=os.urandom(2);q=ident+b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as u:
  u.settimeout(8);u.sendto(b'\x00\x00\x00\x01\x0b\x4d\x00\x02\x27\x45'+q,('127.0.0.1',p));r,_=u.recvfrom(4096);off=10 if r[3]==1 else 22 if r[3]==4 else 7+r[4];assert r[off:off+2]==ident and (r[off+3]&15)==0;print('dns-ok')
'''
TCP=r'''import socket,struct,sys
def read(s,n):
 b=b''
 while len(b)<n:
  c=s.recv(n-len(b))
  if not c:raise EOFError()
  b+=c
 return b
try:
 with socket.create_connection(('127.0.0.1',1089),timeout=3) as s:
  s.sendall(b'\x05\x01\x00');assert read(s,2)==b'\x05\x00';s.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x16');h=read(s,4)
  if h[1]!=0:print('blocked');sys.exit(0)
  read(s,4 if h[3]==1 else 16 if h[3]==4 else read(s,1)[0]);read(s,2);data=s.recv(128)
  if data:print('service-data-received');sys.exit(1)
except (OSError,EOFError):pass
print('blocked')
'''
run('docker','cp',str(ROOT/'bot/certs/cert_public'),C+':/tmp/audit-proxy-ca.crt').check_returncode()
cases=sys.argv[1:] or ['hysteria','naive','trusttunnel']
connected=[]
def default_route(pid):
 r=run('nsenter','-t',str(pid),'-n','ip','-j','route','show','default');r.check_returncode();return json.loads(r.stdout)
try:
 for protocol in cases:
  if protocol in ('hysteria','trusttunnel'):
   container={'hysteria':'hysteria-audit','trusttunnel':'trusttunnel-audit'}[protocol]
   meta=json.loads(run('docker','inspect',container).stdout)[0];pid=meta['State']['Pid'];before=default_route(pid)
   if 'vpnbot-protocol-test' not in meta['NetworkSettings']['Networks']:
    run('docker','network','connect','--gw-priority','-1','vpnbot-protocol-test',container).check_returncode();connected.append((container,pid,before))
   check(protocol+'-controlled-network-preserves-default',before==default_route(pid) and before[0]['gateway']=='10.10.0.1')
  if protocol=='hysteria':
   bot('hy-export');a=json.loads((ROOT/'bot/logs/audit-hy.json').read_text())
   n={'type':'hysteria2','server':'10.10.0.17','server_port':443,'password':a['password'],'tls':{'enabled':True,'server_name':'vpnbot.test','certificate_path':'/tmp/audit-proxy-ca.crt'}}
   if a['obfs']:n['obfs']={'type':'salamander','password':a['obfs']}
   nodes=[('sing-box',n)]
  elif protocol=='naive':
   bot('naive-export');a=json.loads((ROOT/'bot/logs/audit-naive.json').read_text())
   nodes=[('sing-box',{'type':'naive','server':'10.10.0.10','server_port':443,'username':a['user'],'password':a['password'],'tls':{'enabled':True,'server_name':a['host'],'certificate_path':'/tmp/audit-proxy-ca.crt'}})]
  elif protocol=='trusttunnel':
   bot('tt-export');a=tomllib.loads((ROOT/'bot/logs/audit-files/trusttunnel-audittt.toml').read_text())
   n={'type':'trusttunnel','server':'10.10.0.10','port':2443,'username':a['username'],'password':a['password'],'sni':a['hostname'],'udp':True}
   nodes=[('mihomo',n),('mihomo',{**n,'quic':True})]
  else:raise RuntimeError('unknown case')
  for kind,node in nodes:
   label=protocol+'-'+kind+('-quic' if node.get('quic') else '')
   if not start(kind,label,profile(kind,copy.deepcopy(node))):continue
   for scheme in ['http','https']:
    r=http(scheme+'://example.com/');save(label+'-'+scheme,r);check(label+'-'+scheme,r.returncode==0 and 'Example Domain' in r.stdout)
   if protocol!='naive':
    r=exe('python3','-c',CONTROLLED_UDP,timeout=15);save(label+'-controlled-udp',r);check(label+'-controlled-udp',r.returncode==0 and 'dns-ok' in r.stdout)
    r=exe('python3','-c',EXTERNAL_UDP,timeout=15);save(label+'-udp',r);check(label+'-udp-dns',r.returncode==0 and 'dns-ok' in r.stdout)
    with (OUT/'udp-probes.jsonl').open('a') as log:log.write(json.dumps({'label':label,'time':time.time(),'exit':r.returncode,'retries':r.stderr.count('dns-retry-'),'stderr':r.stderr})+'\n')
   for name,url in [('docker-api','http://10.10.0.8:2375/version'),('panel','http://10.10.0.7:8090/'),('adguard-admin','http://10.10.0.5:80/'),('loopback','telnet://127.0.0.1:22')]:
    if name=='loopback':
     r=exe('python3','-c',TCP,timeout=10);save(label+'-'+name,r);check(label+'-'+name+'-isolated',r.returncode==0 and 'blocked' in r.stdout)
    else:
     r=http(url,3);save(label+'-'+name,r);check(label+'-'+name+'-isolated',not r.stdout and r.returncode!=0)
   save(label+'-client',exe('cat','/tmp/audit-proxy.log'))
   bad=copy.deepcopy(node);bad['password']='wrong-audit-password';start(kind,label+'-bad-password',profile(kind,bad));r=http('https://example.com/',4);check(label+'-wrong-password-rejected',r.returncode!=0)
finally:
 stop()
 for container,pid,before in reversed(connected):
  run('docker','network','disconnect','vpnbot-protocol-test',container).check_returncode()
  check(container+'-controlled-network-cleanup',before==default_route(pid))
print(json.dumps({'passed':sum(r['passed'] for r in results),'total':len(results)}))
raise SystemExit(0 if all(r['passed'] for r in results) else 1)
