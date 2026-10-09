"""Квота и Limit IP TeleMT на настоящем ядре: граничные случаи через меню бота.

Квота не превышается ни на байт и не обнуляется перезапуском и правкой других
пользователей; адрес пропавшего без закрытия клиента освобождается за
ограниченное время.
"""
from pathlib import Path
import sys,os,json,subprocess,time,shutil,importlib.util
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'support'))
import probe_limits as p
p.ROOT=HERE/'edges';p.ROOT.mkdir(exist_ok=True)
SOURCE=Path(os.environ['SOURCE_DIR']);BINARY=Path(os.environ['TELEMT_BINARY']);p.BINARY=BINARY
spec=importlib.util.spec_from_file_location('state',SOURCE/'scripts/telemt_state.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
results=[]
def check(name,ok,**details):
 results.append({'name':name,'ok':bool(ok),**details});(HERE/'edges-results.json').write_text(json.dumps(results,indent=2));print(name,'OK' if ok else 'FAIL '+json.dumps(details,ensure_ascii=False),flush=True)
 if not ok:raise AssertionError(name)
c=p.Core('native',limit=0,quota=None)
(c.root/'activity.json').unlink(missing_ok=True)
cfg={'source':str(SOURCE),'binary':str(BINARY),'n':c.n,'w':c.w,'a':c.a,'dc':c.dc.server_address[1]}
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
def close_clients():
 for child in c.children:child.close()
 c.children=[]
def works(ip,secret=p.SECRET):return c.native(ip,secret).echo()==b'test-data'*8
def drain(chunk):
 """Гонит эхо одним соединением до отказа ядра; возвращает наибольший учтённый расход."""
 n=c.native('127.0.0.2');peak=0
 for _ in range(400):
  ok=n.echo(b'x'*chunk)==b'x'*chunk;peak=max(peak,c.used() or 0)
  if not ok:break
 return peak
# Адрес только для этого сценария: правила отбрасывания пакетов не заденут соседей.
GONE='127.0.0.71';MARK='vpnbot-telemt-edges'
RULES=[['INPUT','-s',GONE],['INPUT','-d',GONE],['OUTPUT','-s',GONE],['OUTPUT','-d',GONE]]
def blackhole(on):
 for chain,flag,ip in RULES:
  args=['iptables','-I' if on else '-D',chain,flag,ip,'-m','comment','--comment',MARK,'-j','DROP']
  while subprocess.run(args,capture_output=True).returncode==0 and not on:pass
try:
 blackhole(False)
 call('start');check('generated_bot_configuration_starts',p.wait(ready,10))

 # ── квота: точная граница ───────────────────────────────────────────────
 call('reply',field='quota',value='0,0001');quota=s.settings()['user_data_quota']['alice']
 check('ui_quota_exact_bytes',quota==107374,quota=quota)
 peak=drain(20000)
 check('quota_never_exceeded_by_fast_stream',peak==quota and c.used()==quota,peak=peak,used=c.used())
 check('exhausted_native_rejected',not works('127.0.0.3'))
 check('exhausted_web_rejected',c.web('198.51.100.5').echo()==b'')
 check('other_user_unaffected',works('127.0.0.4',p.BOB))
 close_clients()
 screen=call('click',op='limits')['screen']['text'];check('limits_menu_reports_exhaustion','Квота исчерпана' in screen,screen=screen[:300])
 call('track');screen=call('card')['screen']['text'];check('card_reports_quota_and_exhaustion','Квота трафика:' in screen and 'Квота исчерпана' in screen,screen=screen[:500])
 labels=[row[0]['text'] for row in call('users')['screen']['buttons']]
 check('user_list_marks_exhausted_quota',any('alice' in l and l.endswith('⛔') for l in labels) and not any('bob' in l and '⛔' in l for l in labels),labels=labels)

 # ── квота не обнуляется перезапуском и правкой других пользователей ─────
 call('start');check('core_restarted',p.wait(ready,10))
 check('graceful_restart_keeps_exhaustion',c.used()==quota and not works('127.0.0.3'),used=c.used())
 close_clients()
 call('click',name='bob',op='delete-confirm');check('core_restarted_after_delete',p.wait(ready,10))
 check('deleting_another_user_keeps_usage',c.used()==quota and not works('127.0.0.3') and 'bob' not in s.read()['users'],used=c.used())
 call('add',name='carol');check('core_restarted_after_add',p.wait(ready,10))
 check('adding_a_user_keeps_usage',c.used()==quota and not works('127.0.0.3'),used=c.used())
 carol=s.settings()['users']['carol']
 check('new_user_is_unlimited',works('127.0.0.5',bytes.fromhex(carol)) and 'carol' not in s.settings().get('user_data_quota',{}))
 close_clients()

 # ── повышение квоты и медленный добор мелкими порциями ──────────────────
 call('reply',field='quota',value='0,0002');quota2=s.settings()['user_data_quota']['alice']
 check('raised_quota_keeps_usage_and_reopens',quota2==214748 and c.used()==quota and works('127.0.0.3'),quota=quota2,used=c.used())
 close_clients()
 peak=drain(500)
 check('quota_never_exceeded_by_small_chunks',peak==quota2 and c.used()==quota2,peak=peak,used=c.used())
 check('exhausted_again_rejected',not works('127.0.0.3'))
 close_clients()
 call('reset');check('core_restarted_after_reset',p.wait(ready,10))
 check('confirmed_reset_starts_from_zero',c.used()==0 and works('127.0.0.3'),used=c.used())
 close_clients()
 call('track');labels=[row[0]['text'] for row in call('users')['screen']['buttons']]
 check('exhaustion_mark_cleared_after_reset',not any('⛔' in l for l in labels),labels=labels)

 # ── Limit IP: живое и пропавшее соединение ──────────────────────────────
 call('reply',field='ips',value='1');check('ui_ip_limit_applied',p.wait(ready,10) and s.settings()['user_max_unique_ips']['alice']==1)
 held=c.native(GONE);check('first_address_admitted',held.echo()==b'test-data'*8)
 check('second_address_rejected',not works('127.0.0.3'))
 time.sleep(12);check('idle_open_connection_keeps_its_slot',not works('127.0.0.3') and c.user()['active_unique_ips_list']==[GONE],user=c.user()['active_unique_ips_list'])
 check('same_address_shares_the_slot',c.native(GONE).echo()==b'test-data'*8)
 check('packet_filter_available',shutil.which('iptables') is not None)
 # Клиент исчез без FIN: пакеты в обе стороны теряются, как при смене сети.
 blackhole(True);started=time.monotonic();admitted=None;early=None
 while time.monotonic()-started<200:
  ok=works('127.0.0.3')
  if early is None and time.monotonic()-started>=15:early=ok
  if ok:admitted=time.monotonic()-started;break
  time.sleep(5)
 blackhole(False)
 check('vanished_client_holds_slot_at_first',early is False,early=early,admitted=admitted)
 check('vanished_client_slot_released_in_bounded_time',admitted is not None and admitted<=180,seconds=admitted)
 check('released_slot_belongs_to_new_address',c.user()['active_unique_ips_list']==['127.0.0.3'],user=c.user()['active_unique_ips_list'])
 close_clients()
 call('reply',field='ips',value='0');check('ip_limit_removed',p.wait(ready,10) and 'alice' not in s.settings().get('user_max_unique_ips',{}))
 check('two_addresses_after_limit_removed',works('127.0.0.2') and works('127.0.0.3'))
finally:
 blackhole(False)
 close_clients()
 if s.processes():s.stop()
 c.close()
print('TOTAL',len(results),flush=True)
