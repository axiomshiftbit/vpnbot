from pathlib import Path
import sys,os,json,subprocess,time,concurrent.futures,importlib.util
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'support'))
import probe_limits as p
p.ROOT=HERE/'settings';p.ROOT.mkdir(exist_ok=True)
SOURCE=Path(os.environ['SOURCE_DIR']);BINARY=Path(os.environ['TELEMT_BINARY']);p.BINARY=BINARY
spec=importlib.util.spec_from_file_location('state',SOURCE/'scripts/telemt_state.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
results=[]
def check(name,ok,**details):
 results.append({'name':name,'ok':bool(ok),**details});(HERE/'settings-results.json').write_text(json.dumps(results,indent=2));print(name, 'OK' if ok else 'FAIL',flush=True)
 if not ok:raise AssertionError(name)
c=p.Core('native',limit=0,quota=None)
cfg={'source':str(SOURCE),'binary':str(BINARY),'n':c.n,'w':c.w,'a':c.a,'dc':c.dc.server_address[1]}
(c.root/'fixture.json').write_text(json.dumps(cfg));(c.root/'pac.json').write_text(json.dumps({'domain':'audit.example','tw_domain':'web','letsencrypt':'letsencrypt','telemt_web':1,'telemt_web_negotiation':'off','telemt_web_carrier':'https','telemt_domain':'localhost','telemt_mode':'secure','telemt_beobachten':1,'telemt_users':{'alice':p.SECRET.hex(),'bob':p.BOB.hex()}}))
s=m.TelemtState(c.root,'http://127.0.0.1:'+str(c.a))
def call(action,**kw):
 r=subprocess.run(['docker','exec','-i','vpnbot-telemt-php85','php','-d','error_reporting=32767',str(HERE/'native_bot.php'),str(SOURCE),str(c.root)],input=json.dumps({'action':action,**kw}),text=True,capture_output=True,timeout=80)
 try:out=json.loads(r.stdout)
 except Exception:raise RuntimeError('PHP harness failure: '+r.stderr[:600])
 if not out['ok']:raise RuntimeError(out['error'])
 if action=='service' and (c.root/'service-enabled').read_text().strip()=='1' and not s.processes():
  s.prepare();subprocess.run(['python3',str(HERE/'native_runner.py'),str(c.root),'start'],check=True,capture_output=True)
 return out

def ready():
 try:return c.api('/v1/health')[0]==200
 except OSError:return False

def close_clients():
 for child in c.children:child.close()
 c.children=[]

def saved():return s.read()['users']['alice']['used_bytes']
class Client(p.Web):
 def request(self,method,path,body=None,headers=None):
  headers=dict(headers or {})
  if path=='/api/v1/session':headers['X-Telemt-Up-Window']='4'
  if path in ['/api/v1/up','/api/v1/down']:method=self.core.method
  if path=='/api/v1/up' and self.core.conveyor:headers['X-Telemt-Up-Confirmed']=str(self.seq-1)
  reply=super().request(method,path,body,headers)
  if path.startswith('/?bridge='):self.page=reply[2]
  if path=='/api/v1/session':self.window=reply[1].get('x-telemt-up-window')
  return reply
try:
 call('start');check('settings_generated_configuration_starts',p.wait(ready,10))
 call('reply',field='quota',value='1');call('reply',field='ips',value='2')
 for method,conveyor in [('post',True),('put',True),('put',False),('post',False),('post',True)]:
  before=c.used()
  call('http',setting='method',value=method);call('http',setting='conveyor',value='on' if conveyor else 'off')
  label=method+'-'+str(conveyor);check(label+'/usage_preserved_by_callbacks',c.used()==before)
  access=s.settings();check(label+'/limits_preserved',access['user_data_quota']['alice']==1073741824 and access['user_max_unique_ips']['alice']==2)
  c.method=method.upper();c.conveyor=conveyor;w=Client(c,'198.51.100.2',p.SECRET,'127.0.0.1');c.children.append(w)
  check(label+'/rendered_method',("const carrierMethod='"+method.upper()+"'").encode() in w.page)
  check(label+'/runtime_window',w.window==('4' if conveyor else '1'))
  check(label+'/native_and_web_data',w.echo()==b'test-data'*8 and c.native().echo()==b'test-data'*8)
  check(label+'/combined_accounting',c.used()==before+288)
  pid=s.processes();call('http',setting='method',value=method);call('http',setting='conveyor',value='on' if conveyor else 'off')
  check(label+'/repeated_callback_keeps_process',s.processes()==pid)
  check(label+'/existing_web_stream_survives_noop',w.echo()==b'test-data'*8)
  close_clients()
 call('http',setting='method',value='put');call('http',setting='conveyor',value='off');used=c.used();call('backup')
 backup=json.loads((c.root/'backup.json').read_text());check('backup_saves_both_http_settings',backup['pac']['telemt_web_carrier_method']=='put' and backup['pac']['telemt_web_conveyor']==0)
 # Штатный restore сохраняет telemt_* PAC вместе с persistent quota state.
 call('http',setting='method',value='post');call('http',setting='conveyor',value='on');call('restore');call('start')
 pac=json.loads((c.root/'pac.json').read_text());check('restore_keeps_http_settings_and_usage',pac['telemt_web_carrier_method']=='put' and pac['telemt_web_conveyor']==0 and c.used()==used)
 call('web-toggle');pid=s.processes();check('web_disabled_native_remains_ready',p.wait(ready))
 call('http',setting='method',value='post');call('http',setting='conveyor',value='on')
 check('web_off_settings_do_not_restart_native',s.processes()==pid)
 call('web-toggle');check('web_reenable_keeps_saved_options_and_usage',p.wait(ready) and c.used()==used)
 c.method='POST';c.conveyor=True;w=Client(c,'198.51.100.2',p.SECRET,'127.0.0.1');c.children.append(w)
 check('web_reenabled_conveyor_works',w.window=='4' and w.echo()==b'test-data'*8)
finally:
 close_clients()
 if s.processes():s.stop()
 c.close()
print('TOTAL',len(results),flush=True)
