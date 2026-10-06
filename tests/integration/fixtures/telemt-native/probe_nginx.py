from pathlib import Path
import sys,os,re,json,subprocess,ssl,http.client,time
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE/'support'))
import probe_limits as p
import probe_relay as relay
p.ROOT=HERE/'nginx-cases';p.ROOT.mkdir(exist_ok=True);p.BINARY=Path(os.environ['TELEMT_BINARY'])
NGINX=os.environ['NGINX_BINARY'];SOURCE=Path(os.environ['SOURCE_DIR']);checks=[]
def check(name,ok):
 checks.append({'name':name,'ok':bool(ok)});(HERE/'nginx-results.json').write_text(json.dumps(checks,indent=2));print(name,'OK' if ok else 'FAIL',flush=True)
 if not ok:raise AssertionError(name)
for template in ['nginx_default.conf','nginx.conf']:
 c=p.Core(template,limit=1,quota=1000000);r=c.root/'front';r.mkdir(exist_ok=True);front=p.port();proc=None
 cert=r/'cert.pem';key=r/'fixture.key'
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN='+p.HOST,'-addext','subjectAltName=DNS:'+p.HOST,'-keyout',str(key),'-out',str(cert)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
 c.tlscontext=ssl.create_default_context(cafile=str(cert));c.front=front
 block=re.search(r'#-tgweb\n(.*?)#-tgweb',(SOURCE/'config'/template).read_text(),re.S).group(1);block=re.sub(r'^    # ?', '', block, flags=re.M)
 block=block.replace('10.10.0.20:8080','127.0.0.1:'+str(c.w)).replace('listen 10.10.0.2:443 ssl proxy_protocol;','listen 127.0.0.1:'+str(front)+' ssl;').replace('listen 10.10.1.2:443 ssl;','').replace('server_name tgweb;','server_name '+p.HOST+';').replace('/certs/cert_public',str(cert)).replace('/certs/cert_private',str(key))
 config=f'error_log {r}/error.log; pid {r}/nginx.pid; events {{ worker_connections 128; }} http {{ access_log {r}/access.log; map $http_upgrade $connection_upgrade {{default upgrade; "" "";}}\n'
 for name in ['client_body','proxy','fastcgi','uwsgi','scgi']:config+=f'{name}_temp_path {r}/{name};\n'
 (r/'nginx.conf').write_text(config+block+'\n}')
 marker='SYNTHETIC_BRIDGE_QUOTA_AUDIT_ONLY'
 def request(method='GET',body=None):
  client=relay.TLSConn(p.HOST,front,timeout=5,context=c.tlscontext)
  try:client.request(method,'/?bridge='+marker,body,{'Host':p.HOST});response=client.getresponse();response.read();return response.status
  finally:client.close()
 def leaked():return any(marker in f.read_text(errors='replace') for f in r.glob('*.log'))
 log=(r/'stderr.log').open('wb')
 try:
  proc=subprocess.Popen([NGINX,'-e',str(r/'startup.log'),'-p',str(r)+'/', '-c',str(r/'nginx.conf'),'-g','daemon off; master_process off;'],stdout=log,stderr=log)
  for _ in range(50):
   try:status=request();break
   except OSError:time.sleep(.05)
  else:raise RuntimeError('NGINX did not start')
  check(template+'/unavailable_upstream_502',status==502);check(template+'/502_does_not_log_capability',not leaked())
  c.start();check(template+'/backend_recovery_no_nginx_reload',request()==200)
  w=relay.TLSWeb(c,'198.51.100.250',p.SECRET,'127.0.0.2');c.children.append(w)
  check(template+'/real_https_web_data',w.echo()==b'test-data'*8)
  check(template+'/xff_forgery_overwritten',c.user()['active_unique_ips_list']==['127.0.0.2'])
  blocked=relay.TLSWeb(c,'127.0.0.2',p.SECRET,'127.0.0.3');c.children.append(blocked)
  check(template+'/real_source_ip_limit',blocked.echo()==b'')
  check(template+'/large_request_413',request('POST',b'x'*(4*1024*1024+1))==413)
  check(template+'/413_does_not_log_capability',not leaked())
  for child in c.children:child.close()
  c.children=[];c.stop();check(template+'/stopped_core_502',request()==502)
  check(template+'/second_502_keeps_capability_private',not leaked())
  c.start();check(template+'/second_recovery',request()==200)
 finally:
  c.close()
  if proc and proc.poll() is None:proc.terminate();proc.wait(5)
  log.close()
print('TOTAL',len(checks))
