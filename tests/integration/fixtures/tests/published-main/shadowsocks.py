#!/usr/bin/env python3
import base64, copy, json, os, pathlib, subprocess, sys, time, urllib.parse
import proxy_helpers as h
h.C='vpnbot-audit-ssclient';h.OUT=h.ROOT/'results/shadowsocks';h.OUT.mkdir(mode=0o700,exist_ok=True)
run=h.run;exe=h.exe;check=h.check;save=h.save

def bot(*args):
 r=run('docker','exec','php-audit','php','/tmp/audit-driver.php',*args,timeout=150);r.check_returncode();v=json.loads(r.stdout);check('bot-'+args[0]+'-'+(args[1] if len(args)>1 else ''),v['warnings']==[]);return v['result']
def stop():
 for proc in ['sslocal','v2ray-plugin','ck-client','simple-tls']:exe('pkill','-x',proc)
 time.sleep(.3)
def config(mode):
 bot('ss-export');a=json.loads((h.ROOT/'bot/logs/audit-ss.json').read_text());u=urllib.parse.urlsplit(a['link']);userinfo=base64.urlsafe_b64decode(u.username+'='*((-len(u.username))%4)).decode();method,password=userinfo.split(':',1)
 c={'server':('10.10.0.10' if u.port==443 else '10.10.0.2') if mode=='v2ray' else '10.10.0.6','server_port':u.port,'method':method,'password':password,'local_address':'127.0.0.1','local_port':1089,'mode':'tcp_and_udp'}
 opts=urllib.parse.parse_qs(u.query).get('plugin',[])
 if opts:
  plugin,options=opts[0].split(';',1);c.update(plugin=plugin,plugin_opts=options)
  if plugin=='simple-tls':c['plugin_opts']=options.replace(';no-verify','')+';ca=/tmp/audit-proxy-ca.crt'
 return c

def start(c,label):
 stop();h.put(label+'.json',c);run('docker','exec','-d','-e','SSL_CERT_FILE=/tmp/audit-proxy-ca.crt',h.C,'sh','-c','sslocal -c /tmp/audit-proxy.json >/tmp/audit-proxy.log 2>&1').check_returncode();time.sleep(1)
 check(label+'-client-started',exe('pgrep','-x','sslocal').returncode==0)

bundle=h.OUT/'ca.crt';bundle.write_bytes((h.ROOT/'bot/certs/cert_public').read_bytes()+(h.ROOT/'bot/certs/self_public').read_bytes());run('docker','cp',str(bundle),h.C+':/tmp/audit-proxy-ca.crt').check_returncode()
try:
 for mode in sys.argv[1:] or ['plain','v2ray','cloak','simple-tls']:
  bot('ss-mode',mode);c=config(mode);start(c,mode)
  for scheme in ['http','https']:
   r=h.http(scheme+'://example.com/');save(mode+'-'+scheme,r);check(mode+'-'+scheme,r.returncode==0 and 'Example Domain' in r.stdout)
  if mode=='plain':
   r=exe('python3','-c',h.UDP,timeout=15);save(mode+'-udp',r);check(mode+'-udp-dns',r.returncode==0)
  for name,url in [('docker-api','http://10.10.0.8:2375/version'),('panel','http://10.10.0.7:8090/'),('adguard-admin','http://10.10.0.5:80/')]:
   r=h.http(url,3);save(mode+'-'+name,r);check(mode+'-'+name+'-isolated',not r.stdout and r.returncode!=0)
  r=exe('python3','-c',h.TCP,timeout=10);check(mode+'-loopback-isolated',r.returncode==0 and 'blocked' in r.stdout)
  save(mode+'-client',exe('cat','/tmp/audit-proxy.log'))
  bad=copy.deepcopy(c);bad['password']='audit-invalid-password';start(bad,mode+'-bad');r=h.http('http://example.com/',3);check(mode+'-wrong-password-rejected',r.returncode!=0)
  start(c,mode+'-old');bot('ss-rotate');r=h.http('https://example.com/',3);check(mode+'-old-password-rejected',r.returncode!=0)
  c=config(mode);start(c,mode+'-rotated');r=h.http('https://example.com/');check(mode+'-new-password-works',r.returncode==0 and 'Example Domain' in r.stdout)
finally:stop()
print(json.dumps({'passed':sum(r['passed'] for r in h.results),'total':len(h.results)}))
raise SystemExit(0 if all(r['passed'] for r in h.results) else 1)
