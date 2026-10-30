#!/usr/bin/env python3
import base64,http.client,json,os,pathlib,socket,ssl,struct,subprocess,time,urllib.parse
os.umask(0o077);R=pathlib.Path('/opt/vpnbot-hosted-ci/stand');O=R/'results/adguard';O.mkdir(mode=0o700,exist_ok=True);results=[]
def check(n,v,detail=None):
 results.append({'name':n,'passed':bool(v),'detail':detail});(O/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if v else 'FAIL ')+n,flush=True)
def bot(a):
 r=subprocess.run(['docker','exec','php-audit','php','/tmp/audit-driver.php',a],capture_output=True,text=True,timeout=120);r.check_returncode();j=json.loads(r.stdout);check('bot-'+a,not j['warnings'])
bot('ad-sync');bot('ad-export');time.sleep(2);a=json.loads((R/'bot/logs/audit-ad.json').read_text());context=ssl.create_default_context(cafile=str(R/'bot/certs/cert_public'))
class Front(http.client.HTTPSConnection):
 def connect(self):self.sock=self._context.wrap_socket(socket.create_connection(('10.10.0.10',443),timeout=15),server_hostname=self.host)
def req(path,method='GET',body=None,headers=None):
 c=Front(a['domain'],context=context,timeout=15);c.request(method,path,body,headers or {});r=c.getresponse();out=r.status,dict(r.getheaders()),r.read();c.close();return out
def query(name='example.com'):
 return os.urandom(2)+b'\1\0\0\1'+bytes(6)+b''.join(bytes([len(s)])+s.encode() for s in name.split('.'))+b'\0\0\1\0\1'
def valid(q,r):return len(r)>12 and r[:2]==q[:2] and r[2]&128 and r[3]&15==0 and int.from_bytes(r[6:8],'big')>0
def exact(s,n):
 b=b''
 while len(b)<n:
  x=s.recv(n-len(b))
  if not x:raise EOFError()
  b+=x
 return b
for transport in ['udp','tcp','tls']:
 q=query()
 try:
  if transport=='udp':
   with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:s.settimeout(8);s.sendto(q,('10.10.0.5',53));r=s.recv(4096)
  else:
   with socket.create_connection(('10.10.0.5',853 if transport=='tls' else 53),timeout=8) as raw:
    s=context.wrap_socket(raw,server_hostname=a['domain']) if transport=='tls' else raw;s.sendall(struct.pack('!H',len(q))+q);r=exact(s,int.from_bytes(exact(s,2),'big'))
  check('dns-'+transport,valid(q,r))
 except Exception as e:check('dns-'+transport,False,type(e).__name__)
path='/dns-query'+a['hash']+'/'+a['doh_id'];q=query();s,h,r=req(path,'POST',q,{'Content-Type':'application/dns-message'});check('doh-post',s==200 and valid(q,r),s)
s,h,r=req(path+'?dns='+base64.urlsafe_b64encode(q).decode().rstrip('='));check('doh-get',s==200 and valid(q,r),s)
prefix='/adguard'+a['hash']
# Общедоступный хэш подписки больше не даёт пропуск в панель, даже с паролем.
basic={'Authorization':'Basic '+base64.b64encode(('admin:'+a['password']).encode()).decode()}
for label,headers in [('anonymous',{}),('public-hash',{'Cookie':'c='+a['hash']}),
                      ('public-hash-with-password',{'Cookie':'c='+a['hash'],**basic}),
                      ('forged',{'Cookie':'adg='+a['gate'][:-1]+('0' if a['gate'][-1]!='0' else '1')}),
                      ('expired',{'Cookie':'adg='+a['expired_gate']}),('wrong-kind',{'Cookie':'adg='+a['link_gate']})]:
 s,_,_=req(prefix+'/control/status',headers=headers);check('gate-rejects-'+label,s in (302,401,403),s)
cookie={'Cookie':'adg='+a['gate']};auth={**cookie,**basic}
s,_,_=req(prefix+'/control/status',headers=cookie);check('admin-cookie-alone-insufficient',s in [401,403],s)
s,_,_=req(prefix+'/control/status',headers={**cookie,'Authorization':'Basic '+base64.b64encode(b'admin:wrong-password').decode()});check('admin-wrong-password-rejected',s in [401,403],s)
s,_,b=req(prefix+'/control/status',headers=auth);check('admin-real-password',s==200 and 'version' in json.loads(b),s)
s,h,_=req(prefix+'/login.html',headers=cookie);check('panel-pages-are-not-cached',s==200 and 'no-cache' in {k.lower():v for k,v in h.items()}.get('cache-control',''),h.get('Cache-Control'))
check('security-headers-kept',{k.lower():v for k,v in h.items()}.get('x-content-type-options')=='nosniff')
s,_,b=req(prefix+'/control/filtering/status',headers=auth);check('filtering-api',s==200);old=json.loads(b).get('user_rules',[])
try:
 rule='||vpnbot-audit-block.example^';body=json.dumps({'rules':old+[rule]}).encode();s,_,_=req(prefix+'/control/filtering/set_rules','POST',body,{**auth,'Content-Type':'application/json'});check('add-dns-filter',s==200)
 time.sleep(2);s,_,b=req(prefix+'/control/filtering/check_host?name=vpnbot-audit-block.example',headers=auth);j=json.loads(b);check('filter-matches',s==200 and j.get('reason','').startswith('Filtered'),j.get('reason'))
finally:req(prefix+'/control/filtering/set_rules','POST',json.dumps({'rules':old}).encode(),{**auth,'Content-Type':'application/json'})
# Меню AdGuard на живом AdGuardHome: настройки через его API без перезапуска,
# апстримы с пробой, клиенты, список разрешённых. Всё возвращается в исходное.
def botx(*args):
 r=subprocess.run(['docker','exec','php-audit','php','/tmp/audit-driver.php',*args],capture_output=True,text=True,timeout=240)
 if r.returncode not in (0,91):raise RuntimeError('bot '+args[0]+' failed')
 j=json.loads(r.stdout)
 if j['warnings']:check('bot-'+'-'.join(args[:2])+'-no-PHP-warnings',False)
 return j['result']
def said(state,text):return any(text in m for m in state['messages'])
def days(config):return 0 if not config or not config.get('enabled') else round(config.get('interval',0)/86400000)
def answer(name):
 q=query(name)
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as u:
  u.settimeout(8);u.sendto(q,('10.10.0.5',53));r=u.recv(4096)
 return '.'.join(map(str,r[-4:])) if valid(q,r) else ''
s0=botx('ad-state');check('settings-api-reachable-with-the-bot-password',s0['api'],s0['api_error'])
user=s0['users'][0]
check('config-with-password-hash-is-private',s0['mode_bits']==0o600,oct(s0['mode_bits']))
try:
 for limit in (300,1100,0):check('rate-limit-%d-applied'%limit,botx('ad-set','rate',str(limit))['ratelimit']==limit)
 st=botx('ad-set','rate','250');check('rate-limit-outside-the-list-refused',st['ratelimit']==0 and said(st,'bad value'))
 check('upstream-mode-parallel',botx('ad-set','mode','parallel')['mode']=='parallel')
 check('upstream-mode-back',botx('ad-set','mode','lb')['mode'] in ('','load_balance'))
 st=botx('ad-set','qlog','7');check('query-log-seven-days',days(st['querylog'])==7)
 st=botx('ad-set','anon','on');check('client-ip-hidden-and-retention-kept',st['querylog']['anonymize_client_ip'] is True and days(st['querylog'])==7)
 check('query-log-off',days(botx('ad-set','qlog','0')['querylog'])==0)
 check('statistics-thirty-days',days(botx('ad-set','stats','30')['stats'])==30)
 check('protection-paused',botx('ad-set','protection','10')['protection'] is False)
 check('protection-back-on',botx('ad-set','protection','on')['protection'] is True)
 check('safe-search-on',botx('ad-set','safesearch','on')['safesearch'] is True)
 check('safe-search-off',botx('ad-set','safesearch','off')['safesearch'] is False)
 check('dns-answers-after-the-settings',answer('example.com')!='')
 # Апстримы: неотвечающий отклоняется, для отдельного домена — работает.
 st=botx('ad-upstream','tls://192.0.2.1');check('dead-upstream-refused',st['upstreams']==s0['upstreams'] and len(st['messages'])>0)
 own='[/public.test/]10.10.0.242'
 st=botx('ad-upstream',own);check('domain-upstream-added',own in st['upstreams'] and st['api'])
 time.sleep(1);check('domain-goes-to-its-own-upstream',answer('public.test')=='11.77.0.2',answer('public.test'))
 st=botx('ad-delupstream',own);check('domain-upstream-removed',st['upstreams']==s0['upstreams'])
 # Клиенты: правка из панели переживает переименование пользователя.
 st=botx('ad-clients',user);client=dict(st['clients'][user]);client.update(filtering_enabled=True,use_global_settings=False);client.pop('uid',None)
 code,_,_=req(prefix+'/control/clients/update','POST',json.dumps({'name':user,'data':client}).encode(),{**auth,'Content-Type':'application/json'});check('panel-edit-accepted',code==200,code)
 st=botx('ad-clients','audit-renamed');renamed=st['clients'].get('audit-renamed',{})
 check('rename-keeps-the-panel-settings',renamed.get('filtering_enabled') is True and renamed.get('use_global_settings') is False and user not in st['clients'])
 check('client-keeps-its-doh-id',renamed.get('ids')==[st['doh_ids'][0]])
 st=botx('ad-clients',user);client=dict(st['clients'][user]);client.update(filtering_enabled=False,use_global_settings=True);client.pop('uid',None)
 req(prefix+'/control/clients/update','POST',json.dumps({'name':user,'data':client}).encode(),{**auth,'Content-Type':'application/json'})
 # Список разрешённых и ClientID.
 st=botx('ad-fill','fill');check('allowed-list-filled',st['api'] and '10.10.0.0/24' in st['allowed'] and all(i in st['allowed'] for i in st['doh_ids']))
 check('dns-answers-for-an-allowed-network',answer('example.com')!='')
 st=botx('ad-key','My Key!');check('bad-client-id-refused',st['key']==s0['key'] and 'My Key!' not in st['allowed'] and st['api'])
 st=botx('ad-key','audit-key');check('client-id-enters-the-allowed-list',st['key']=='audit-key' and 'audit-key' in st['allowed'])
 st=botx('ad-key',s0['key'] or '-');check('client-id-restored',st['key']==s0['key'] and 'audit-key' not in st['allowed'])
 st=botx('ad-menu');check('menu-and-screens-render',len(st['menu'])<4096 and '/adgSettings' in st['menu_buttons'] and '/adgStats' in st['menu_buttons'] and st['api'])
finally:
 botx('ad-clients',user);botx('ad-set','rate',str(s0['ratelimit']));botx('ad-set','mode','lb' if s0['mode'] in ('','load_balance') else s0['mode'].replace('fastest_addr','fastest'))
 botx('ad-set','qlog',str(days(s0['querylog'])) if days(s0['querylog']) in (0,1,7,30,90) else '90')
 botx('ad-set','anon','on' if (s0['querylog'] or {}).get('anonymize_client_ip') else 'off')
 botx('ad-set','stats',str(days(s0['stats'])) if days(s0['stats']) in (0,1,7,30,90) else '1')
 botx('ad-set','safesearch','on' if s0['safesearch'] else 'off');botx('ad-set','protection','on' if s0['protection'] else 'off')
 end=botx('ad-fill','fill' if s0['allowed'] else 'clear')
 check('adguard-settings-restored',end['ratelimit']==s0['ratelimit'] and end['upstreams']==s0['upstreams'] and end['users']==s0['users'] and bool(end['allowed'])==bool(s0['allowed']))
subprocess.run(['docker','restart','adguard-audit'],capture_output=True,check=True);time.sleep(3);q=query();s,_,r=req(path,'POST',q,{'Content-Type':'application/dns-message'});check('doh-survives-container-restart',s==200 and valid(q,r))
s,_,_=req(prefix+'/control/status',headers=auth);check('admin-password-survives-restart',s==200)
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}));raise SystemExit(0 if all(x['passed'] for x in results) else 1)
