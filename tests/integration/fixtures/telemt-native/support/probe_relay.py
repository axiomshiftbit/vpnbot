from pathlib import Path
import http.client, json, os, socket, ssl, subprocess, time
import probe_limits as p
ROOT=p.ROOT
NGINX=Path(os.environ['NGINX_BINARY'])
ORIGIN='web.audit.example';RELAY='relay.audit.example'
results=[]
def check(name,ok,**detail):
 results.append(dict(name=name,ok=bool(ok),**detail));(ROOT/'relay-results.json').write_text(json.dumps(results,indent=2))
 print(name+': '+('OK' if ok else 'FAIL')+((' '+json.dumps(detail)) if detail else ''),flush=True)
 if not ok:raise AssertionError(name)
class TLSConn(http.client.HTTPSConnection):
 def connect(self):
  sock=socket.create_connection(('127.0.0.1',self.port),self.timeout,self.source_address)
  self.sock=self._context.wrap_socket(sock,server_hostname=self.host)
class TLSWeb(p.Web):
 def request(self,method,path,body=None,headers=None):
  c=TLSConn(p.HOST,self.core.front,timeout=3,source_address=(self.source,0),context=self.core.tlscontext)
  h={'Host':p.HOST,'X-Forwarded-For':self.ip};h.update(headers or {})
  if self.token:h['Authorization']='Bearer '+self.token
  try:
   c.request(method,path,body,h);r=c.getresponse();return r.status,{k.lower():v for k,v in r.getheaders()},r.read()
  finally:c.close()
class Front:
 def __init__(self,core,trust=False):
  self.core=core;self.root=core.root/'front';self.root.mkdir(exist_ok=True)
  self.origin,self.relay=p.port(),p.port();self.proc=None
  cert=self.root/'cert.pem';key=self.root/'key.pem'
  subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN='+ORIGIN,'-addext','subjectAltName=DNS:'+ORIGIN+',DNS:'+RELAY,'-keyout',str(key),'-out',str(cert)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
  core.tlscontext=ssl.create_default_context(cafile=str(cert));core.front=self.origin
  tls=f'ssl_certificate {cert}; ssl_certificate_key {key};'
  context=f'error_log {self.root}/error.log; pid {self.root}/nginx.pid;\nevents {{worker_connections 128;}}\nhttp {{\naccess_log off;\n'
  for name in ['client_body','proxy','fastcgi','uwsgi','scgi']:context+=f'{name}_temp_path {self.root}/{name};\n'
  context+='map $http_upgrade $connection_upgrade { default upgrade; "" ""; }\n'
  location='proxy_http_version 1.1; proxy_set_header Host $host; proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection $connection_upgrade; proxy_request_buffering off; proxy_buffering off; proxy_read_timeout 10s;'
  realip='set_real_ip_from 127.0.0.1; real_ip_header X-Forwarded-For;' if trust else ''
  context+=f'server {{listen 127.0.0.1:{self.origin} ssl; server_name {ORIGIN} {RELAY}; {tls} {realip} location / {{proxy_pass http://127.0.0.1:{core.w}; {location}}}}}\n'
  context+=f'server {{listen 127.0.0.1:{self.relay} ssl; server_name {RELAY}; {tls} location / {{proxy_pass https://127.0.0.1:{self.origin}; proxy_ssl_server_name on; proxy_ssl_name {ORIGIN}; proxy_ssl_verify on; proxy_ssl_trusted_certificate {cert}; {location}}}}}\n}}'
  (self.root/'nginx.conf').write_text(context)
 def start(self):
  self.log=(self.root/'process.log').open('wb')
  self.proc=subprocess.Popen([str(NGINX),'-e',str(self.root/'startup.log'),'-p',str(self.root)+'/', '-c',str(self.root/'nginx.conf'),'-g','daemon off; master_process off;'],stdout=self.log,stderr=self.log)
  def ready():
   if self.proc.poll() is not None:raise RuntimeError('Nginx exited')
   try:
    c=TLSConn(ORIGIN,self.origin,timeout=1,context=self.core.tlscontext);c.request('GET','/');r=c.getresponse();r.read();c.close();return r.status==200
   except OSError:return False
  if not p.wait(ready):raise RuntimeError('Nginx unavailable')
  return self
 def close(self):
  if self.proc and self.proc.poll() is None:self.proc.terminate();self.proc.wait(5)
  if hasattr(self,'log'):self.log.close()
def web(core,ip='127.0.0.2'):
 w=TLSWeb(core,'198.51.100.99',p.SECRET,ip);core.children.append(w);return w
if __name__=='__main__':
 for variant,extra,trust in [('existing',False,False),('relay-no-client-ip',True,False),('relay-trusted-client-ip',True,True)]:
  p.HOST=ORIGIN;c=p.Core(variant,limit=1,quota=1000000)
  if extra:
   section=c.config[c.config.index('[[web.vhosts]]'):].replace('host = "'+ORIGIN+'"','host = "'+RELAY+'"').replace('203.0.113.10:443','203.0.113.20:443')
   c.config+='\n'+section;(c.root/'telemt.toml').write_text(c.config)
  c.start();front=None
  try:
   front=Front(c,trust).start()
   if not extra:
    direct=web(c);check('direct_real_https_echo',direct.echo()==b'test-data'*8);direct.close();p.wait(lambda:c.user()['active_unique_ips']==0)
    p.HOST=RELAY;c.front=front.relay;rejected=False
    try:web(c)
    except RuntimeError as e:rejected=str(e)=='No bootstrap'
    check('changing_link_domain_alone_fails',rejected)
   else:
    p.HOST=RELAY;c.front=front.relay;a=web(c);check(variant+'/tls_chain_echo',a.echo()==b'test-data'*8)
    seen=c.user()['active_unique_ips_list'];check(variant+'/observed_source',seen==(['127.0.0.2'] if trust else ['127.0.0.1']),observed=seen)
    b=web(c,'127.0.0.3');received=b.echo()
    check(variant+'/second_ip_limit',received==(b'' if trust else b'test-data'*8))
    if trust:check('client_cannot_spoof_xff',seen!=['198.51.100.99'])
  finally:
   c.close()
   if front:front.close()
 print(json.dumps({'checks':len(results),'passed':sum(x['ok'] for x in results)}))
