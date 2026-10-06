#!/usr/bin/env python3
from pathlib import Path
import json,os,socket,socketserver,struct,subprocess,threading,time,urllib.parse
os.umask(0o077)
B=Path('/opt/vpnbot-hosted-ci/stand/bot');T=Path('/opt/vpnbot-hosted-ci/stand')
O=Path(os.environ['VPNBOT_TEST_RESULTS']);O.mkdir(exist_ok=True)
address='11.77.0.2';installed=False;client=None;checks=[];echo_started=False
def check(name,ok):
 checks.append({'name':name,'ok':bool(ok)});(O/'naive-idle.json').write_text(json.dumps(checks))
 if not ok:raise RuntimeError(name)
 print('PASS '+name,flush=True)
def recv_exact(s,n):
 out=b''
 while len(out)<n:
  data=s.recv(n-len(out))
  if not data:raise RuntimeError('tunnel closed')
  out+=data
 return out
class Echo(socketserver.BaseRequestHandler):
 def handle(self):
  self.request.settimeout(100)
  while data:=self.request.recv(4096):self.request.sendall(data)
try:
 networks=json.loads(subprocess.check_output(['docker','inspect','--format','{{json .NetworkSettings.Networks}}','naive-audit']))
 if 'vpnbot-protocol-test' not in networks:
  subprocess.run(['docker','network','connect','vpnbot-protocol-test','naive-audit'],check=True);installed=True
 echo_script="import os,socketserver,pathlib\npathlib.Path('/tmp/naive-idle.pid').write_text(str(os.getpid()))\nclass Echo(socketserver.BaseRequestHandler):\n def handle(self):\n  self.request.settimeout(100)\n  while data:=self.request.recv(4096):self.request.sendall(data)\nsocketserver.ThreadingTCPServer.allow_reuse_address=True;s=socketserver.ThreadingTCPServer(('0.0.0.0',80),Echo);s.daemon_threads=True;s.serve_forever()\n"
 script=O/'naive_idle_echo.py';script.write_text(echo_script)
 subprocess.run(['docker','cp',str(script),'vpnbot-protocol-target:/tmp/naive_idle_echo.py'],check=True)
 subprocess.run(['docker','exec','-d','vpnbot-protocol-target','python3','/tmp/naive_idle_echo.py'],check=True);echo_started=True
 subprocess.run(['docker','exec','php-audit','php','/tmp/audit-driver.php','naive-export'],stdout=subprocess.DEVNULL,check=True)
 a=json.loads((B/'logs/audit-naive.json').read_text())
 with socket.socket() as reserve:reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
 cfg={'listen':'socks://127.0.0.1:'+str(port),'proxy':'https://'+urllib.parse.quote(a['user'],safe='')+':'+urllib.parse.quote(a['password'],safe='')+'@'+a['host']+':443','host-resolver-rules':'MAP '+a['host']+' 10.10.0.10'}
 conf=O/'naive-idle-config.json';conf.write_text(json.dumps(cfg))
 with (O/'naive-idle-client.log').open('wb') as log:
  client=subprocess.Popen([str(T/'bin/naive'),str(conf)],env=os.environ|{'SSL_CERT_FILE':str(B/'certs/cert_public')},stdout=log,stderr=log)
 time.sleep(1)
 with socket.create_connection(('127.0.0.1',port),timeout=15) as s:
  s.sendall(b'\x05\x01\x00');check('SOCKS-auth',recv_exact(s,2)==b'\x05\x00')
  s.sendall(b'\x05\x01\x00\x01'+socket.inet_aton(address)+struct.pack('!H',80))
  header=recv_exact(s,4);check('public-fixture-CONNECT',header[1]==0)
  recv_exact(s,6 if header[3]==1 else 18 if header[3]==4 else recv_exact(s,1)[0]+2)
  s.sendall(b'before-idle');check('before-idle',recv_exact(s,11)==b'before-idle')
  time.sleep(75)
  s.sendall(b'after-idle');check('after-75-seconds-idle',recv_exact(s,10)==b'after-idle')
 check('client-still-running',client.poll() is None)
finally:
 if client is not None:
  client.terminate();client.wait(timeout=10)
 if echo_started:
  cleanup="import pathlib,os,signal;f=pathlib.Path('/tmp/naive-idle.pid');pid=int(f.read_text());assert b'naive_idle_echo.py' in pathlib.Path('/proc',str(pid),'cmdline').read_bytes();os.kill(pid,signal.SIGTERM);f.unlink()"
  subprocess.run(['docker','exec','vpnbot-protocol-target','python3','-c',cleanup],check=True)
 if installed:subprocess.run(['docker','network','disconnect','vpnbot-protocol-test','naive-audit'],check=True)
 (O/'naive-idle-config.json').unlink(missing_ok=True)
