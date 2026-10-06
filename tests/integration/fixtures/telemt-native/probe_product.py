from pathlib import Path
import sys,os,json,subprocess,time,concurrent.futures,importlib.util
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'support'))
import probe_limits as p
p.ROOT=HERE/'product';p.ROOT.mkdir(exist_ok=True)
SOURCE=Path(os.environ['SOURCE_DIR']);BINARY=Path(os.environ['TELEMT_BINARY']);p.BINARY=BINARY
spec=importlib.util.spec_from_file_location('state',SOURCE/'scripts/telemt_state.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
results=[]
def check(name,ok,**details):
 results.append({'name':name,'ok':bool(ok),**details});(HERE/'product-results.json').write_text(json.dumps(results,indent=2));print(name, 'OK' if ok else 'FAIL',flush=True)
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
  s.prepare();subprocess.run(['docker','exec','vpnbot-telemt-php85','python3',str(HERE/'native_runner.py'),str(c.root),'start'],check=True,capture_output=True)
 return out

def ready():
 try:return c.api('/v1/health')[0]==200
 except OSError:return False

def close_clients():
 for child in c.children:child.close()
 c.children=[]

def saved():return s.read()['users']['alice']['used_bytes']
try:
 call('start');check('generated_bot_configuration_starts',p.wait(ready,10))
 check('read_only_control_api',c.api('/v1/users/alice/reset-quota','POST',{})[0] in [403,405])
 check('default_no_quota',c.used() is None)
 call('reply',field='ips',value='1');check('ui_ip_limit_applied',s.settings()['user_max_unique_ips']['alice']==1)
 n=c.native();check('native_first_ip',n.echo()==b'test-data'*8)
 w=c.web('127.0.0.2');check('web_shares_native_ip_slot',w.echo()==b'test-data'*8)
 check('native_extra_ip_blocked',c.native('127.0.0.3').echo()==b'')
 check('web_extra_ip_blocked',c.web('198.51.100.3').echo()==b'')
 check('another_user_unaffected_by_ip_limit',c.native('127.0.0.3',p.BOB).echo()==b'test-data'*8)
 close_clients();time.sleep(.2);check('closed_ip_slot_reusable',c.native('127.0.0.3').echo()==b'test-data'*8)
 close_clients();call('reply',field='ips',value='2')
 call('reply',field='quota',value='0,000001');check('ui_fractional_gib_exact_bytes',s.settings()['user_data_quota']['alice']==1074)
 check('first_enable_zero_usage',c.used()==0)
 n=c.native();w=c.web('198.51.100.1')
 check('native_traffic_with_quota',n.echo()==b'test-data'*8);check('web_traffic_with_quota',w.echo()==b'test-data'*8)
 check('combined_upload_download_quota',c.used()==288)
 screen=call('click',op='limits')['screen']['text'];check('live_menu_reports_two_ips','активных IP: 2' in screen)
 before=c.used();s.checkpoint();check('periodic_checkpoint_exact',saved()==before)
 pid=next(iter(s.processes()));os.kill(pid,9);p.wait(lambda:not s.processes())
 s.prepare();call('start');check('crash_restores_checkpoint',p.wait(ready) and c.used()==before)
 close_clients()
 n=c.native();check('resumed_native_traffic',n.echo()==b'test-data'*8);before=c.used()
 call('set',field='quota',value=100)
 check('lowering_quota_preserves_counter',c.used()==before)
 check('lowering_quota_closes_old_stream',n.echo()==b'')
 check('lowering_quota_blocks_new_native',c.native().echo()==b'')
 check('lowering_quota_blocks_new_web',c.web().echo()==b'')
 check('other_user_survives_exhaustion',c.native('127.0.0.3',p.BOB).echo()==b'test-data'*8)
 call('set',field='quota',value=10000);check('raising_quota_preserves_counter',c.used()==before)
 close_clients();check('raising_quota_reopens_access',c.native().echo()==b'test-data'*8)
 used=c.used();call('click',op='toggle');check('disable_preserves_counter',c.used()==used)
 check('disabled_native_rejected',c.native().echo()==b'')
 call('click',op='toggle');check('reenable_preserves_counter',c.used()==used)
 check('reenable_connects',c.native().echo()==b'test-data'*8)
 close_clients();used=c.used();call('backup');check('backup_exact_live_usage',json.loads((c.root/'backup.json').read_text())['telemt_quota']['users']['alice']['used_bytes']==used)
 call('reset');check('confirmed_reset_reopens_quota',c.used()==0 and c.native().echo()==b'test-data'*8)
 call('restore');check('restore_preserves_backed_up_usage',c.used()==used)
 close_clients();used=c.used();old=p.SECRET;call('click',op='regen-confirm')
 check('rotation_preserves_counter',c.used()==used)
 check('old_secret_rejected',c.native(secret=old).echo()==b'')
 new=bytes.fromhex(json.loads((c.root/'pac.json').read_text())['telemt_users']['alice'])
 check('rotated_native_works',c.native(secret=new).echo()==b'test-data'*8)
 check('rotated_web_works',c.web(secret=new).echo()==b'test-data'*8)
 close_clients();used=c.used();call('service');check('container_disable_stops_core',not s.processes())
 check('container_disable_saves_usage',saved()==used)
 call('service');check('container_enable_preserves_usage',p.wait(ready) and c.used()==used)
 call('reply',field='quota',value='0');check('quota_off_is_unlimited_not_zero',c.used() is None and 'user_data_quota' not in s.settings())
 check('unlimited_native_works',c.native(secret=new).echo()==b'test-data'*8)
 close_clients();call('reply',field='quota',value='1');check('re_enable_starts_new_period',c.used()==0)
 call('set',field='quota',value=1000);call('reply',field='ips',value='0');check('ip_off_omits_native_table','user_max_unique_ips' not in s.settings())
 check('consume_before_concurrent_test',c.native(secret=new).echo()==b'test-data'*8)
 close_clients();call('reset')
 clients=[c.native('127.0.0.'+str(j+2),new) for j in range(8)]
 with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:echoes=list(pool.map(lambda x:x.echo(b'x'*256),clients))
 check('parallel_streams_cannot_exceed_quota',c.used()<=1000,used=c.used())
 check('parallel_limit_blocks_some_streams',sum(x==b'x'*256 for x in echoes)<8)
 close_clients();call('set',field='quota',value=100000)
 # Пересекающиеся callbacks используют один flock: оба изменения обязаны сохраниться.
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
  fs=[pool.submit(call,'set',field='ips',value=3),pool.submit(call,'set',field='quota',value=200000)]
  [f.result() for f in fs]
 access=s.settings();check('concurrent_callbacks_keep_both_changes',access['user_data_quota']['alice']==200000 and access['user_max_unique_ips']['alice']==3)
 call('click',op='delete-confirm');check('delete_removes_quota_state','alice' not in s.read()['users'])
 call('add');check('same_name_recreated_without_old_limits','alice' not in s.settings().get('user_data_quota',{}) and s.read()['users']['alice']['used_bytes']==0)
 # Конфиг может быть валиден, а persistent state утрачен: запуск обязан отказать.
 call('reply',field='quota',value='1');s.stop();state=s.read();s.path.unlink()
 try:s.prepare();blocked=False
 except ValueError:blocked=True
 check('missing_persistence_fails_closed',blocked and not s.processes())
 s.write(state);s.prepare();call('start');check('state_recovery_restarts_core',p.wait(ready))
 s.stop();s.path.write_text('{broken')
 try:s.prepare();blocked=False
 except ValueError:blocked=True
 check('corrupt_persistence_fails_closed',blocked and not s.processes())
 s.write(state)
finally:
 close_clients()
 if s.processes():s.stop()
 c.close()
print('TOTAL',len(results),flush=True)
