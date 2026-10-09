"""Учёт подключений TeleMT на настоящем ядре: «онлайн», трафик, журнал адресов.

Бот сам генерирует telemt.toml и опрашивает управляющий API ядра; клиенты —
настоящие соединения MTProxy и WEB с разных адресов.
"""
from pathlib import Path
import sys,os,json,subprocess,time,importlib.util
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'support'))
import probe_limits as p
p.ROOT=HERE/'activity';p.ROOT.mkdir(exist_ok=True)
SOURCE=Path(os.environ['SOURCE_DIR']);BINARY=Path(os.environ['TELEMT_BINARY']);p.BINARY=BINARY
spec=importlib.util.spec_from_file_location('state',SOURCE/'scripts/telemt_state.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
results=[]
def check(name,ok,**details):
 results.append({'name':name,'ok':bool(ok),**details});(HERE/'activity-results.json').write_text(json.dumps(results,indent=2));print(name,'OK' if ok else 'FAIL '+json.dumps(details,ensure_ascii=False),flush=True)
 if not ok:raise AssertionError(name)
c=p.Core('native',limit=0,quota=None)
(c.root/'activity.json').unlink(missing_ok=True)
cfg={'source':str(SOURCE),'binary':str(BINARY),'n':c.n,'w':c.w,'a':c.a,'dc':c.dc.server_address[1]}
# Без beobachten и без лимитов: раньше API ядра в этом случае был выключен.
(c.root/'fixture.json').write_text(json.dumps(cfg));(c.root/'pac.json').write_text(json.dumps({'domain':'audit.example','tw_domain':'web','letsencrypt':'letsencrypt','telemt_web':1,'telemt_web_negotiation':'off','telemt_web_carrier':'https','telemt_domain':'localhost','telemt_mode':'secure','telemt_beobachten':0,'telemt_users':{'alice':p.SECRET.hex(),'bob':p.BOB.hex()}}))
s=m.TelemtState(c.root,'http://127.0.0.1:'+str(c.a))
def call(action,**kw):
 r=subprocess.run(['docker','exec','-i','vpnbot-telemt-php85','php','-d','error_reporting=32767',str(HERE/'native_bot.php'),str(SOURCE),str(c.root)],input=json.dumps({'action':action,**kw}),text=True,capture_output=True,timeout=80)
 try:out=json.loads(r.stdout)
 except Exception:raise RuntimeError('PHP harness failure: '+(r.stderr or r.stdout)[:600])
 if not out['ok']:raise RuntimeError(out['error'])
 return out
def ready():
 try:return c.api('/v1/health')[0]==200
 except OSError:return False
def core_user(name='alice'):return next(u for u in c.api('/v1/users')[1]['data'] if u['username']==name)
def close_clients():
 for child in c.children:child.close()
 c.children=[]
def track(name='alice'):
 out=call('track');check_tracked.append(out['tracked']);return out['activity']['users'].get(name)
check_tracked=[]
try:
 call('start');check('generated_bot_configuration_starts',p.wait(ready,10))
 toml=(c.root/'generated.toml').read_text()
 check('api_enabled_without_limits_and_diagnostics','[server.api]\nenabled = true' in toml and 'read_only = true' in toml and '[access.user_max_unique_ips]' not in toml)
 check('control_api_stays_read_only',c.api('/v1/users/alice/reset-quota','POST',{})[0] in [403,405])
 a=track();check('idle_user_tracked_offline',a['conns']==0 and a['online']==[] and not a['ips'] and a['bytes']==0 and a['last']==0,user=a)
 screen=call('card')['screen']['text'];check('card_reports_offline','оффлайн' in screen and 'был в сети' not in screen)

 n1=c.native('127.0.0.2');n2=c.native('127.0.0.3');nb=c.native('127.0.0.4',p.BOB)
 check('clients_pass_traffic',n1.echo(b'x'*5000)==b'x'*5000 and n2.echo(b'y'*100)==b'y'*100 and nb.echo(b'z'*300)==b'z'*300)
 check('core_reports_connections',p.wait(lambda:core_user()['current_connections']==2 and core_user()['total_octets']==10200,5),core=core_user())
 # Кнопки «обновить» сами снимают состояние с ядра: отдельного опроса до них не было.
 out=call('click',op='refresh');check('card_refresh_button_shows_online','онлайн' in out['screen']['text'] and '<code>127.0.0.2</code>' in out['screen']['text'] and out['activity']['users']['alice']['conns']==2,screen=out['screen']['text'][:300])
 nb.close();check('bob_disconnected',p.wait(lambda:core_user('bob')['current_connections']==0,5))
 out=call('users-refresh');check('list_refresh_button_updates_status','онлайн: 1' in out['screen']['text'] and not any('bob' in row[0]['text'] and '👤' in row[0]['text'] for row in out['screen']['buttons']),text=out['screen']['text'][:200])
 nb=c.native('127.0.0.4',p.BOB);check('bob_reconnected',nb.echo(b'')==b'' and p.wait(lambda:core_user('bob')['current_connections']==1,5))
 a=track()
 check('online_connections_and_addresses',a['conns']==2 and sorted(a['online'])==['127.0.0.2','127.0.0.3'],user=a)
 check('traffic_counts_both_directions',a['bytes']==10200,bytes=a['bytes'])
 check('journal_has_first_sighting',sorted(a['ips'])==['127.0.0.2','127.0.0.3'] and all(r['count']==1 and r['first']==r['last'] for r in a['ips'].values()),ips=a['ips'])
 b=track('bob');check('users_are_separate',b['conns']==1 and b['online']==['127.0.0.4'] and b['bytes']==600 and list(b['ips'])==['127.0.0.4'],user=b)
 a=track();check('repeated_poll_does_not_double_count',a['bytes']==10200 and all(r['count']==1 for r in a['ips'].values()),user=a)
 screen=call('card')['screen']['text'];check('card_reports_online','онлайн' in screen and '<code>127.0.0.2</code>' in screen and '<code>127.0.0.3</code>' in screen and 'подключения: 2' in screen,screen=screen[:400])
 out=call('users')['screen'];labels=[row[0]['text'] for row in out['buttons']]
 check('user_list_marks_online','онлайн: 2' in out['text'] and any('alice' in l and '👤2' in l for l in labels) and any('bob' in l and '👤1' in l for l in labels),labels=labels,text=out['text'][:200])
 screen=call('click',op='log')['screen']['text'];check('journal_view_lists_addresses','127.0.0.2' in screen and '127.0.0.3' in screen and '127.0.0.4' not in screen,screen=screen[:500])

 n1.close();n2.close()
 check('core_sees_disconnect',p.wait(lambda:core_user()['current_connections']==0,5))
 a=track();check('disconnected_user_is_offline',a['conns']==0 and a['online']==[] and a['last']>0 and len(a['ips'])==2,user=a)
 screen=call('card')['screen']['text'];check('card_reports_last_seen','оффлайн' in screen and 'был в сети' in screen)

 # Подключение, открытое и закрытое между двумя опросами, ядро ещё 30 с держит
 # в списке «недавних» — в журнал оно обязано попасть.
 short=c.native('127.0.0.5');check('short_session_traffic',short.echo(b'q'*40)==b'q'*40);short.close()
 check('short_session_closed',p.wait(lambda:'127.0.0.5' not in core_user()['active_unique_ips_list'],5))
 a=track();check('short_session_reaches_journal','127.0.0.5' in a['ips'] and a['conns']==0 and a['bytes']==10280,user=a)

 # WEB-транспорт: адрес клиента приходит заголовком от доверенного прокси.
 w=c.web('198.51.100.7');check('web_client_traffic',w.echo()==b'test-data'*8)
 a=track();check('web_client_address_in_journal','198.51.100.7' in a['ips'] and '198.51.100.7' in a['online'],user=a)
 before=a['bytes'];check('web_traffic_counted',before>10280,bytes=before)
 close_clients()

 # Перезапуск ядра обнуляет его счётчик; накопленное ботом остаётся.
 started=c.api('/v1/system/info')[1]['data']['process_started_at_epoch_secs'];time.sleep(3.1)
 call('start');check('core_restarted',p.wait(ready,10) and c.api('/v1/system/info')[1]['data']['process_started_at_epoch_secs']>started+2 and core_user()['total_octets']==0)
 a=track();check('restart_keeps_accumulated_traffic',a['bytes']==before and a['conns']==0 and len(a['ips'])==4,user=a)
 n=c.native('127.0.0.2');check('traffic_after_restart',n.echo(b'r'*1000)==b'r'*1000)
 check('core_counts_new_traffic',p.wait(lambda:core_user()['total_octets']==2000,5))
 a=track();check('traffic_continues_after_restart',a['bytes']==before+2000 and a['conns']==1,user=a)
 check('same_address_within_five_minutes_is_one_connection',a['ips']['127.0.0.2']['count']==1 and a['ips']['127.0.0.2']['last']>=a['ips']['127.0.0.2']['first'],rec=a['ips']['127.0.0.2'])
 check('every_poll_reached_the_core',all(check_tracked),polls=check_tracked)

 out=call('click',op='logclear');a=out['activity']['users']['alice']
 check('journal_cleared_traffic_kept',not a['ips'] and a['bytes']==before+2000 and 'подключений пока не зафиксировано' in out['screen']['text'],user=a)
 close_clients()
 out=call('click',op='delete-confirm');check('deleted_user_forgotten','alice' not in out['activity']['users'] and 'bob' in out['activity']['users'],users=list(out['activity']['users']))
 call('add');check('core_restarted_after_user_change',p.wait(ready,10))
 a=track();check('recreated_user_starts_clean',a['bytes']==0 and not a['ips'] and a['last']==0,user=a)
 state=(c.root/'activity.json')
 check('journal_file_is_private',oct(state.stat().st_mode&0o777)=='0o600' and p.SECRET.hex() not in state.read_text() and p.BOB.hex() not in state.read_text())
finally:
 close_clients()
 if s.processes():s.stop()
 c.close()
print('TOTAL',len(results),flush=True)
