#!/usr/bin/env python3
import copy, json, os, pathlib, re, subprocess, sys, time, tomllib
ROOT=pathlib.Path('/opt/vpnbot-hosted-ci/stand');OUT=ROOT/'results/proxies';OUT.mkdir(mode=0o700,exist_ok=True)
os.umask(0o077);C='vpnbot-audit-wgclient';results=[]
def run(*a,timeout=45): return subprocess.run(a,capture_output=True,text=True,timeout=timeout)
def exe(*a,**kw):
 r=run('docker','exec',C,*a,**kw)
 if len(a)==3 and a[:2]==('python3','-c') and a[2]==globals().get('UDP'):
  with (OUT/'udp-probes.jsonl').open('a') as log:
   log.write(json.dumps({'time':time.time(),'exit':r.returncode,'retries':r.stderr.count('dns-retry-'),'stderr':r.stderr})+'\n')
 return r
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
UDP_ONE_SHOT=r'''import os,socket,struct
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
  u.settimeout(8);u.sendto(b'\x00\x00\x00\x01\x01\x01\x01\x01\x00\x35'+q,('127.0.0.1',p));r,_=u.recvfrom(4096);off=10 if r[3]==1 else 22 if r[3]==4 else 7+r[4];assert r[off:off+2]==ident and (r[off+3]&15)==0;print('dns-ok')
'''
UDP=r'''import os,socket,struct,sys,time
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
  packet=b'\x00\x00\x00\x01\x01\x01\x01\x01\x00\x35'+q
  deadline=time.monotonic()+8
  for attempt in range(3):
   remaining=deadline-time.monotonic()
   if remaining<=0:raise TimeoutError('DNS deadline exceeded')
   u.settimeout(min(2,remaining) if attempt<2 else remaining)
   u.sendto(packet,('127.0.0.1',p))
   try:
    r,_=u.recvfrom(4096)
    break
   except socket.timeout:
    if attempt==2:raise
    print('dns-retry-'+str(attempt+1),file=sys.stderr,flush=True)
  off=10 if r[3]==1 else 22 if r[3]==4 else 7+r[4]
  assert r[off:off+2]==ident and (r[off+3]&15)==0
  print('dns-ok')
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
