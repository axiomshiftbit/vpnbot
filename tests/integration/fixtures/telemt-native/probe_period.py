"""Периодический сброс квоты TeleMT 3.5.15+ на настоящем ядре через меню бота.

Таблица [access.user_quota_periods] принимается ядром, расписание видно в
API, календарь ядра остаётся в файле расхода после записей расхода ботом,
штатного перезапуска и ручного сброса; смена и выключение периода. Ядро
старше 3.5.15 таблицу не получает, а бот отказывает в включении периода.
"""
from pathlib import Path
import sys,os,json,subprocess,time,hashlib,importlib.util,calendar
from datetime import datetime,timedelta,timezone
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'support'))
import probe_limits as p
p.ROOT=HERE/'period';p.ROOT.mkdir(exist_ok=True)
SOURCE=Path(os.environ['SOURCE_DIR']);BINARY=Path(os.environ['TELEMT_BINARY']);p.BINARY=BINARY
VERSION=os.environ.get('TELEMT_VERSION','0')
spec=importlib.util.spec_from_file_location('state',SOURCE/'scripts/telemt_state.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
results=[]
def check(name,ok,**details):
 results.append({'name':name,'ok':bool(ok),**details});(HERE/'period-results.json').write_text(json.dumps(results,indent=2,ensure_ascii=False));print(name,'OK' if ok else 'FAIL '+json.dumps(details,ensure_ascii=False),flush=True)
 if not ok:raise AssertionError(name)
c=p.Core('native',limit=0,quota=None)
(c.root/'activity.json').unlink(missing_ok=True);(c.root/'data/telemt.limit.json').unlink(missing_ok=True)
cfg={'source':str(SOURCE),'binary':str(BINARY),'n':c.n,'w':c.w,'a':c.a,'dc':c.dc.server_address[1]}
(c.root/'fixture.json').write_text(json.dumps(cfg));(c.root/'pac.json').write_text(json.dumps({'domain':'audit.example','tw_domain':'web','letsencrypt':'letsencrypt','telemt_web':0,'telemt_domain':'localhost','telemt_mode':'secure','telemt_beobachten':0,'telemt_users':{'alice':p.SECRET.hex(),'bob':p.BOB.hex()}}))
s=m.TelemtState(c.root,'http://127.0.0.1:'+str(c.a))
KEY=hashlib.sha256(p.SECRET.hex().encode()).hexdigest()[:8]
def call(action,**kw):
 r=subprocess.run(['docker','exec','-i','vpnbot-telemt-php85','php','-d','error_reporting=32767',str(HERE/'native_bot.php'),str(SOURCE),str(c.root)],input=json.dumps({'action':action,**kw}),text=True,capture_output=True,timeout=80)
 try:out=json.loads(r.stdout)
 except Exception:raise RuntimeError('PHP harness failure: '+(r.stderr or r.stdout)[:600])
 if not out['ok']:raise RuntimeError(out['error'])
 return out
def ready():
 try:return c.api('/v1/health')[0]==200
 except OSError:return False
def row():
 try:return next((u for u in c.api('/v1/stats/users/quota')[1]['data']['users'] if u['username']=='alice'),None)
 except (OSError,KeyError,TypeError,ValueError):return None
def state_row():return s.read()['users'].get('alice',{})
def toml():return (c.root/'generated.toml').read_text()
def boundary(period):
 now=datetime.now(timezone.utc);day=now.replace(hour=0,minute=0,second=0,microsecond=0)
 if period=='daily':nxt=day+timedelta(days=1)
 elif period=='weekly':nxt=day+timedelta(days=7-day.weekday())
 else:nxt=(day.replace(day=1)+timedelta(days=32)).replace(day=1)
 return calendar.timegm(nxt.timetuple())
def works(ip='127.0.0.2'):return c.native(ip,p.SECRET).echo()==b'test-data'*8
old=tuple(int(x) for x in VERSION.split('.')[:3] if x.isdigit())<(3,5,15)
try:
 call('start');check('core_starts',p.wait(ready,10))
 call('reply',field='quota',value='1');check('quota_set',s.settings()['user_data_quota']['alice']==1073741824)
 screen=call('click',op='limits')['screen']
 labels=[r[0]['text'] for r in screen['buttons']]
 check('period_button_with_quota',any('Период сброса квоты' in l for l in labels),labels=labels)
 if old:
  screen=call('click',op='period-monthly-'+KEY)['screen']
  check('old_core_refuses_period','3.5.15' in screen['text'] and 'user_quota_periods' not in toml(),version=VERSION)
  check('old_core_keeps_running',ready())
 else:
  check('traffic_before_period',works())
  used=c.used()
  screen=call('click',op='period')['screen']
  cbs=[r[0]['callback_data'] for r in screen['buttons'][:4]]
  check('chooser_has_four_options',[x.rsplit(' ',1)[-1] for x in cbs]==['period-%s-%s'%(o,KEY) for o in ('off','daily','weekly','monthly')],cbs=cbs)
  call('click',op='period-monthly-'+KEY)
  check('toml_has_period_table','[access.user_quota_periods]\n"alice" = "monthly"' in toml())
  check('core_accepts_period_table',p.wait(ready,10))
  check('schedule_active_monthly',p.wait(lambda:(row() or {}).get('quota_schedule_state')=='active',20) and row()['quota_period']=='monthly' and row()['active_quota_period']=='monthly',row=row())
  check('next_reset_first_of_next_month',row()['quota_next_reset_epoch_secs']==boundary('monthly'),got=row()['quota_next_reset_epoch_secs'],want=boundary('monthly'))
  check('enabling_period_keeps_usage',c.used()==used,used=c.used(),before=used)
  check('traffic_with_period',works())
  check('core_writes_calendar',p.wait(lambda:state_row().get('quota_period')=='monthly' and state_row().get('period_cursor_epoch_secs',0)>0,20),state=state_row())
  cursor=state_row()['period_cursor_epoch_secs']
  native_before=(c.root/'data/telemt.limit.json').read_bytes()
  s.checkpoint()
  check('bot_checkpoint_does_not_overwrite_core',native_before==(c.root/'data/telemt.limit.json').read_bytes())
  check('bot_checkpoint_keeps_calendar',state_row().get('quota_period')=='monthly' and state_row()['period_cursor_epoch_secs']==cursor and state_row()['used_bytes']==c.used(),state=state_row())
  screen=call('click',op='limits')['screen']
  want=datetime.fromtimestamp(boundary('monthly'),timezone.utc).strftime('%Y-%m-%d %H:%M')
  check('menu_shows_next_reset','ежемесячно' in screen['text'] and want+' UTC' in screen['text'],text=screen['text'][:600])
  before=c.used()
  call('start');check('graceful_restart_with_period',p.wait(ready,10))
  check('restart_keeps_usage_and_calendar',c.used()==before and state_row().get('quota_period')=='monthly' and state_row()['period_cursor_epoch_secs']>=cursor
        and p.wait(lambda:(row() or {}).get('quota_schedule_state')=='active',20),used=c.used(),state=state_row(),row=row())
  call('backup');saved_used=c.used();saved_cursor=state_row()['period_cursor_epoch_secs']
  check('traffic_changes_usage_after_backup',works() and c.used()>saved_used)
  call('click',op='period-daily-'+KEY)
  check('changed_period_before_restore',p.wait(lambda:(row() or {}).get('active_quota_period')=='daily',20))
  call('restore');check('backup_restore_starts_real_core',p.wait(ready,10))
  check('backup_restore_exact_usage',c.used()==saved_used)
  check('backup_restore_calendar',state_row().get('quota_period')=='monthly' and state_row()['period_cursor_epoch_secs']==saved_cursor
        and p.wait(lambda:(row() or {}).get('active_quota_period')=='monthly',20) and row()['quota_next_reset_epoch_secs']==boundary('monthly'))
  check('traffic_works_after_backup_restore',works())
  call('restore');check('repeat_restore_exact_usage',p.wait(ready,10) and c.used()==saved_used)
  t0=int(time.time())
  call('reset');check('reset_restarts_core',p.wait(ready,10))
  check('manual_reset_keeps_period',c.used()==0 and state_row().get('quota_period')=='monthly' and state_row()['period_cursor_epoch_secs']>=t0,state=state_row())
  check('manual_reset_keeps_cadence',p.wait(lambda:(row() or {}).get('quota_schedule_state')=='active',20) and row()['quota_next_reset_epoch_secs']==boundary('monthly'),row=row())
  call('click',op='period-daily-'+KEY);check('period_change_restarts',p.wait(ready,10))
  check('daily_next_midnight',p.wait(lambda:(row() or {}).get('active_quota_period')=='daily',20) and row()['quota_next_reset_epoch_secs']==boundary('daily'),row=row())
  call('click',op='period-off-'+KEY);check('period_off_restarts',p.wait(ready,10))
  check('period_off_removes_table','user_quota_periods' not in toml() and 'period' not in call('click',op='limits')['limits'].get('alice',{}))
  check('period_off_schedule_disabled',p.wait(lambda:(row() or {}).get('quota_period') is None and (row() or {}).get('quota_schedule_state')=='disabled',20),row=row())
  check('quota_still_enforced_after_period_off',s.settings()['user_data_quota']['alice']==1073741824 and works())
finally:
 try:s.stop()
 except Exception:pass
 c.close()
