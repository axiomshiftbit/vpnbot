#!/usr/bin/env python3
"""Узлы выхода на живых контейнерах: настоящий бот и Xray стенда, узел — второй
Xray с входом VLESS REALITY во внутренней сети, клиент — настоящий клиент Xray
с профилем пользователя. Каким путём ушёл запрос, видно по адресу источника на
цели: через узел — адрес узла, напрямую — адрес Xray бота. Проба бота идёт
через узел к цели (узел разрешает имена сайтов пробы в её адрес); внешние
сервисы не используются."""
import json,os,pathlib,subprocess,time,urllib.parse
os.umask(0o077);R=pathlib.Path('/opt/vpnbot-hosted-ci/stand');O=R/'results/exit-nodes';O.mkdir(mode=0o700,exist_ok=True);results=[]
TARGET='vpnbot-protocol-target';NET='vpnbot-protocol-test'
# Имя с префиксом vpnbot-ci-retain-: оставшийся после сбоя контейнер убирает cleanup.
EXIT='vpnbot-ci-retain-exit-node';EXIT_IP='11.77.0.4';TARGET_IP='11.77.0.2'
SOCKS=15520;SNI='exit.vpnbot.test'
DOMAINS=['video.exit.test','cdn.video.exit.test','full.exit.test','kw-match.exit.test','rx-7.exit.test','srs.exit.test','mrs.exit.test','direct.exit.test']
PROBE=['www.gstatic.com','www.cloudflare.com','www.youtube.com']
BUNDLE='/etc/ssl/certs/ca-certificates.crt'
def run(*a,timeout=60):return subprocess.run(list(map(str,a)),capture_output=True,text=True,timeout=timeout)
def check(n,v):results.append({'name':n,'passed':bool(v)});(O/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if v else 'FAIL ')+n,flush=True)
calls=0
def bot(*a):
 global calls;calls+=1
 r=run('docker','exec','php-audit','php','/tmp/audit-driver.php','exit',*a,timeout=240)
 if r.returncode not in (0,91):raise RuntimeError('bot exit '+a[0]+' failed: '+r.stderr[-300:])
 j=json.loads(r.stdout)
 # Ссылки узлов содержат ключи: в результаты кладём состояние без них.
 safe={k:v for k,v in j['result'].items() if k not in ('nodes','outbounds','messages')}
 (O/('bot-%02d-%s.json'%(calls,a[0]))).write_text(json.dumps(safe,ensure_ascii=False,indent=1))
 if j['warnings']:check('exit-'+a[0]+'-no-PHP-warnings',False)
 return j['result']
def said(state,text):return any(text in m for m in state['messages'])
def xray_alive():return run('docker','exec','xray-audit','sh','-c','pgrep -f "[x]ray run" >/dev/null').returncode==0
def fetch(host,limit=10):
 r=run('curl','--socks5-hostname','127.0.0.1:%d'%SOCKS,'--noproxy','','-s','--max-time',limit,'http://%s:8455/'%host,timeout=limit+20)
 return r.stdout.strip().removeprefix('src=') if r.stdout.startswith('src=') else ''
# Каждое изменение перезапускает Xray бота: запрос в эту секунду остаётся без
# ответа. Путь судим только по ответу, пустой — повторяем.
def source(host,limit=10):
 for attempt in range(3):
  src=fetch(host,limit)
  if src:return src
  time.sleep(2)
 return ''
def via(host,limit=10):return source(host,limit)==EXIT_IP
def direct(host,limit=10):
 src=source(host,limit);return src not in ('',EXIT_IP)
def wait(cond,seconds):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  if cond():return True
  time.sleep(2)
 return cond()
def node_rules(state,nid):return [r for r in state['rules'] if r['ruleTag'].startswith('vpnbot:exit:'+nid+':')]
connected=[];hosts_added=False;bundle_saved=False;nid='';trust='';client=None
try:
 # ── Цель и узел ─────────────────────────────────────────────────────────
 names=','.join('DNS:'+n for n in PROBE+[SNI])
 run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-keyout',O/'key.pem','-out',O/'ca.pem','-subj','/CN=exit-target','-addext','subjectAltName='+names+',IP:'+TARGET_IP).check_returncode()
 (O/'ca.pem').chmod(0o644)
 for local,remote in ((O/'ca.pem','/tmp/exit-cert.pem'),(O/'key.pem','/tmp/exit-key.pem'),(pathlib.Path('/opt/vpnbot-hosted-ci/exit-nodes/exit_target.py'),'/tmp/exit-target.py')):
  run('docker','cp',local,TARGET+':'+remote).check_returncode()
 run('docker','exec',TARGET,'sh','-c','pkill -f "[e]xit-target.py"; rm -f /tmp/exit-target.log')
 run('docker','exec','-d',TARGET,'python3','/tmp/exit-target.py','/tmp/exit-cert.pem','/tmp/exit-key.pem').check_returncode()
 xr=json.loads(run('docker','inspect','--format','{{json .Config.Image}}','xray-audit').stdout)
 keys=dict(l.split(': ',1) for l in run('docker','run','--rm','--network','none','--entrypoint','xray',xr,'x25519').stdout.splitlines() if ': ' in l)
 private,public=keys['PrivateKey'],keys['Password (PublicKey)']
 uid=run('docker','run','--rm','--network','none','--entrypoint','xray',xr,'uuid').stdout.strip();sid=os.urandom(4).hex()
 server={'log':{'loglevel':'warning'},'inbounds':[{'listen':EXIT_IP,'port':443,'protocol':'vless','settings':{'clients':[{'id':uid,'flow':'xtls-rprx-vision','email':'main'}],'decryption':'none'},
  'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'dest':TARGET_IP+':8456','serverNames':[SNI],'privateKey':private,'shortIds':[sid]}}}],
  'outbounds':[{'protocol':'freedom','tag':'direct'}]}
 (O/'exit-server.json').write_text(json.dumps(server))
 run('docker','rm','-f',EXIT)
 hosts=sum((['--add-host','%s:%s'%(n,TARGET_IP)] for n in DOMAINS+PROBE),[])
 run('docker','create','--name',EXIT,'--network',NET,'--ip',EXIT_IP,*hosts,'--entrypoint','xray',xr,'run','-c','/exit.json').check_returncode()
 run('docker','cp',O/'exit-server.json',EXIT+':/exit.json').check_returncode()
 (O/'exit-server.json').unlink()
 run('docker','start',EXIT).check_returncode()
 if run('docker','network','connect','--gw-priority','-1',NET,'xray-audit').returncode==0:connected.append('xray-audit')
 check('exit-network-attached',connected==['xray-audit'])
 # Прямой путь Xray бота: те же имена — в адрес цели; проба бота доверяет CA цели.
 run('docker','exec','xray-audit','sh','-c','cp /etc/hosts /tmp/hosts.exit-ci && for n in %s; do echo "%s $n" >> /etc/hosts; done'%(' '.join(DOMAINS),TARGET_IP)).check_returncode();hosts_added=True
 run('docker','exec','xray-audit','cp',BUNDLE,'/tmp/ca-bundle.exit-ci').check_returncode();bundle_saved=True
 run('docker','cp',O/'ca.pem','xray-audit:/tmp/exit-ca.pem').check_returncode()
 run('docker','exec','xray-audit','sh','-c','cat /tmp/exit-ca.pem >> '+BUNDLE).check_returncode()
 time.sleep(1.5)
 check('exit-node-running',run('docker','inspect','--format','{{.State.Running}}',EXIT).stdout.strip()=='true')
 link='vless://%s@%s:443?'%(uid,EXIT_IP)+urllib.parse.urlencode({'type':'tcp','security':'reality','pbk':public,'sni':SNI,'fp':'chrome','sid':sid,'flow':'xtls-rprx-vision'})+'#'+urllib.parse.quote('ci exit')

 # ── Клиент: настоящий профиль первого пользователя ──────────────────────
 before=bot('reset');check('clean-before-the-test',before['nodes']=={} and before['rules']==[] and before['outbounds']==[] and before['burst'] is None)
 email=before['clients'][0]['email']
 run('docker','exec','php-audit','php','/tmp/audit-driver.php','export',timeout=120).check_returncode()
 # Клиент на самой VM, как в наборе транспортов nginx: выход proxy из
 # профиля бота, сервер — nginx стенда на 127.0.0.1:443, CA — сертификат
 # сервера (ядро 26.10.10+ читает SSL_CERT_FILE только с useSystemCa).
 node=next(o for o in json.loads((R/'bot/logs/audit-profiles/xray.json').read_text())['outbounds'] if o.get('protocol') in ('vless','trojan'))
 node['tag']='proxy';node['settings']['vnext' if node['protocol']=='vless' else 'servers'][0]['address']='127.0.0.1'
 if isinstance(node.get('streamSettings',{}).get('tlsSettings'),dict):node['streamSettings']['tlsSettings']['useSystemCa']=True
 (O/'client.json').write_text(json.dumps({'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':SOCKS,'protocol':'socks'}],'outbounds':[node]}))
 client=subprocess.Popen(['/opt/vpnbot-hosted-ci/tests/xray','run','-c',str(O/'client.json')],stdout=(O/'client.log').open('w'),stderr=subprocess.STDOUT,
  env=dict(os.environ,SSL_CERT_FILE=str(R/'bot/certs/cert_public')))
 time.sleep(2);(O/'client.json').unlink()
 check('client-running',client.poll() is None)
 check('client-goes-direct-without-nodes',direct('video.exit.test'))

 # ── «Профиль для узла» на этом сервере ──────────────────────────────────
 s=bot('relay','ci-main')
 relay=[c for c in s['clients'] if c['email']=='node-ci-main']
 check('relay-profile-created',len(relay)==1 and relay[0]['relay'] and said(s,'Профиль создан') and said(s,'vless://'))
 check('relay-profile-has-the-transport-flow',relay and (s['transport']!='Reality' or relay[0]['flow']=='xtls-rprx-vision'))
 own=next((m.split('<pre><code>')[1].split('</code></pre>')[0] for m in s['messages'] if '<pre><code>' in m),'')
 s=bot('add',own.replace('&amp;','&'))
 check('own-relay-link-rejected-as-a-loop',s['nodes']=={} and (said(s,'этого же сервера') or said(s,'не публичный')))
 s=bot('state');check('relay-profile-not-offered-to-nodes',all(c['exit'] is None for c in s['clients'] if c['relay']))

 # ── Добавление узла ─────────────────────────────────────────────────────
 s=bot('add',link.replace('security=reality','security=none'));check('link-without-protection-rejected',s['nodes']=={} and said(s,'REALITY или TLS'))
 s=bot('add',link)
 check('node-added',len(s['nodes'])==1 and said(s,'Узел добавлен'))
 nid=next(iter(s['nodes']));node=s['nodes'][nid]
 check('node-name-from-the-link',node['name']=='ci exit')
 check('node-off-for-users-by-default',all(c['exit'] is None for c in s['clients']))
 check('outbound-and-probe-inbound-written',[o['tag'] for o in s['outbounds']]==['vpnbot-exit-'+nid] and s['inbounds'] and s['inbounds'][0]['listen']=='127.0.0.1' and s['inbounds'][0]['port']==10870)
 check('no-user-rules-without-users-and-routes',[r['ruleTag'] for r in node_rules(s,nid)]==['vpnbot:exit:'+nid+':probe'] and s['burst'] is None)
 st=s['status'].get(nid,{})
 check('probe-on-add-sees-the-node',st.get('ok') is True and st.get('http')==204 and st.get('ip')==EXIT_IP and st.get('loc')=='FI' and st.get('gl')=='FI')
 check('xray-running-after-add',xray_alive())
 s=bot('add',link);check('duplicate-node-rejected',len(s['nodes'])==1 and said(s,'Такой узел уже есть'))
 log=run('docker','exec',TARGET,'cat','/tmp/exit-target.log').stdout
 check('probe-went-through-the-node',' www.gstatic.com /generate_204 '+EXIT_IP in log and ' www.youtube.com / '+EXIT_IP in log)

 # ── Маршруты и пользователи ─────────────────────────────────────────────
 s=bot('routes',nid,'domain:video.exit.test|full:full.exit.test|keyword:kw-match|regexp:^rx-[0-9]+\\.exit\\.test$|domain:|domain:video.exit.test')
 check('routes-saved-with-bad-entries-skipped',set(s['nodes'][nid]['routes'])=={'domain:video.exit.test','full:full.exit.test','keyword:kw-match','regexp:^rx-[0-9]+\\.exit\\.test$'} and said(s,'Добавлено: 4') and said(s,'пропущено'))
 check('routes-alone-change-nothing-for-users',direct('video.exit.test'))
 s=bot('all',nid,'on')
 check('enabled-for-all-regular-users',all((c['exit']==[nid])!=c['relay'] for c in s['clients']))
 rules={r['ruleTag'].split(':')[-1]:r for r in node_rules(s,nid)}
 check('user-rules-written',set(rules)=={'probe','quic-domain','domain'} and rules['domain']['balancerTag']=='vpnbot-exit-'+nid and email in rules['domain']['user'] and 'node-ci-main' not in rules['domain']['user'])
 check('quic-to-node-domains-blocked',rules['quic-domain']['network']=='udp' and rules['quic-domain']['port']=='443' and rules['quic-domain']['outboundTag']=='block')
 check('balancer-falls-back-to-direct',s['balancers']==[{'tag':'vpnbot-exit-'+nid,'selector':['vpnbot-exit-'+nid],'strategy':{'type':'random'},'fallbackTag':'direct'}])
 check('burst-observatory-watches-only-the-remote-node',s['burst'] and s['burst']['subjectSelector']==['vpnbot-exit-'+nid] and s['burst']['pingConfig']['destination']=='https://www.gstatic.com/generate_204')
 order=s['order'];first_exit=min(i for i,t in enumerate(order) if t.startswith('vpnbot:exit:'+nid+':quic') or t=='vpnbot:exit:'+nid+':domain')
 check('blocking-rules-stay-above-the-node',all(i<first_exit for i,t in enumerate(order) if t.startswith('vpnbot:routes:block:') or t.endswith(':bittorrent')))
 check('xray-running-after-routes',xray_alive())
 for host,name in (('video.exit.test','domain'),('cdn.video.exit.test','domain-subdomain'),('full.exit.test','full'),('kw-match.exit.test','keyword'),('rx-7.exit.test','regexp')):
  check('through-the-node-'+name,wait(lambda:via(host),20))
 check('other-domain-direct',direct('direct.exit.test'))
 check('other-ip-direct',direct(TARGET_IP))
 # Один пользователь — выключить и включить в его карточке.
 s=bot('user',nid,'0');check('user-switched-off',s['clients'][0]['exit'] is None and not any(email in r.get('user',[]) for r in node_rules(s,nid)))
 check('switched-off-user-goes-direct',wait(lambda:direct('video.exit.test'),20))
 s=bot('user',nid,'0');check('user-switched-on',s['clients'][0]['exit']==[nid])
 check('switched-on-user-through-the-node',wait(lambda:via('video.exit.test'),20))
 # IP-маршрут и QUIC: правило по адресу и его QUIC-блок, «пропускать QUIC».
 s=bot('routes',nid,TARGET_IP+'/32')
 rules={r['ruleTag'].split(':')[-1]:r for r in node_rules(s,nid)}
 check('ip-route-written',rules.get('ip',{}).get('ip') in ([TARGET_IP],[TARGET_IP+'/32']) and 'quic-ip' in rules)
 check('through-the-node-by-ip',wait(lambda:via(TARGET_IP),20))
 s=bot('quic',nid);check('quic-pass-removes-the-block',not any(t.endswith((':quic-domain',':quic-ip')) for t in (r['ruleTag'] for r in node_rules(s,nid))))
 s=bot('quic',nid);check('quic-block-restored',any(r['ruleTag'].endswith(':quic-domain') for r in node_rules(s,nid)))
 s=bot('route-off',nid,TARGET_IP+'/32');check('ip-route-switched-off',not any(r['ruleTag'].endswith(':ip') for r in node_rules(s,nid)))
 check('ip-direct-again',wait(lambda:direct(TARGET_IP),20))

 # ── Наборы правил .srs и .mrs ───────────────────────────────────────────
 cmd=('rm -rf /tmp/exit-sets && mkdir -p /tmp/exit-sets && cd /tmp/exit-sets && '
  'printf \'{"version":3,"rules":[{"domain":["srs.exit.test"],"ip_cidr":["11.77.0.3/32"]}]}\' > s.json && sing-box rule-set compile -o ci.srs s.json && '
  'printf "+.mrs.exit.test\\n" > m.txt && mihomo convert-ruleset domain text m.txt ci.mrs && rm s.json m.txt && ls')
 r=run('docker','exec','php-audit','sh','-c',cmd);check('rule-sets-compiled',r.stdout.split()==['ci.mrs','ci.srs'])
 for name in ('ci.srs','ci.mrs'):
  run('docker','cp','php-audit:/tmp/exit-sets/'+name,O/name).check_returncode()
 run('docker','exec','php-audit','rm','-rf','/tmp/exit-sets')
 run('docker','exec',TARGET,'sh','-c','rm -rf /tmp/exit-sets && mkdir -p /tmp/exit-sets').check_returncode()
 for name in ('ci.srs','ci.mrs'):run('docker','cp',O/name,TARGET+':/tmp/exit-sets/'+name).check_returncode()
 run('docker','cp','/opt/vpnbot-hosted-ci/dat/dat_server.py',TARGET+':/tmp/exit-sets-server.py').check_returncode()
 run('docker','exec','-d',TARGET,'python3','/tmp/exit-sets-server.py','/tmp/exit-sets','0.0.0.0','8457','/tmp/exit-cert.pem','/tmp/exit-key.pem').check_returncode()
 trust='/etc/ssl/certs/'+run('openssl','x509','-hash','-noout','-in',O/'ca.pem').stdout.strip()+'.0'
 run('docker','cp',O/'ca.pem','php-audit:'+trust).check_returncode()
 if run('docker','network','connect','--gw-priority','-1',NET,'php-audit').returncode==0:connected.append('php-audit')
 time.sleep(1)
 srs='https://%s:8457/ci.srs'%TARGET_IP;mrs='https://%s:8457/ci.mrs'%TARGET_IP
 s=bot('sets',nid,srs+'|domain '+mrs+'|http://%s:8457/plain.srs'%TARGET_IP)
 check('rule-sets-added-insecure-link-refused',set(s['nodes'][nid]['rulesets'])=={srs,mrs} and said(s,'Добавлено: 2') and said(s,'не подошло'))
 entries=sorted(e for c in s['sets'] for e in c.get('entries',[]))
 check('rule-sets-unpacked',entries==['11.77.0.3/32','domain:mrs.exit.test','full:srs.exit.test'] and all(c['error']=='' for c in s['sets']))
 check('through-the-node-srs',wait(lambda:via('srs.exit.test'),20))
 check('through-the-node-mrs',wait(lambda:via('mrs.exit.test'),20))
 s=bot('set-del',nid,mrs);check('rule-set-deleted',list(s['nodes'][nid]['rulesets'])==[srs] and len(s['sets'])==1)
 check('deleted-set-domain-direct',wait(lambda:direct('mrs.exit.test'),20))
 # «Обновить»: набор изменился у источника — новые записи без перезапуска бота.
 run('docker','exec','php-audit','sh','-c','mkdir -p /tmp/exit-sets && cd /tmp/exit-sets && printf \'{"version":3,"rules":[{"domain_suffix":["video2.exit.test"]}]}\' > s.json && sing-box rule-set compile -o ci.srs s.json').check_returncode()
 run('docker','cp','php-audit:/tmp/exit-sets/ci.srs',O/'ci.srs').check_returncode();run('docker','exec','php-audit','rm','-rf','/tmp/exit-sets')
 run('docker','cp',O/'ci.srs',TARGET+':/tmp/exit-sets/ci.srs').check_returncode()
 s=bot('refresh',nid);entries=[e for c in s['sets'] for e in c.get('entries',[])]
 check('refresh-picks-up-the-new-set',entries==['domain:video2.exit.test'] and said(s,'наборы правил изменились'))
 check('srs-domain-direct-after-refresh',wait(lambda:direct('srs.exit.test'),20))

 # ── Отказ узла: трафик напрямую, уведомление, возврат ───────────────────
 bot('cron')
 run('docker','stop','-t','1',EXIT).check_returncode()
 # burstObservatory: узел «мёртв», когда отказали все пробы окна (10 с × 3).
 check('node-down-traffic-goes-direct',wait(lambda:direct('video.exit.test',6),120))
 s=bot('check',nid);check('check-reports-the-dead-node',s['status'][nid]['ok'] is False and s['status'][nid].get('error')=='tcp' and said(s,'недоступен по TCP'))
 check('xray-running-with-a-dead-node',xray_alive())
 run('docker','start',EXIT).check_returncode()
 check('node-back-traffic-through-it',wait(lambda:via('video.exit.test'),120))
 s=bot('cron');check('cron-reports-the-recovery',s['status'][nid]['ok'] is True and (s['admins']==0 or said(s,'снова работает')))

 # ── Выключение узла, «новым пользователям», удаление ────────────────────
 s=bot('toggle',nid);check('disabled-node-leaves-the-config',s['outbounds']==[] and s['rules']==[] and s['balancers']==[] and s['burst'] is None)
 check('disabled-node-traffic-direct',wait(lambda:direct('video.exit.test'),20))
 s=bot('toggle',nid);check('enabled-node-back-in-the-config',len(s['outbounds'])==1 and node_rules(s,nid))
 check('enabled-node-traffic-through-it',wait(lambda:via('video.exit.test'),20))
 s=bot('auto',nid);check('auto-flag-set',s['nodes'][nid]['auto']==1)
 s=bot('adduser','ci-exit-new');new=[c for c in s['clients'] if c['email']=='ci-exit-new']
 check('new-user-gets-the-auto-node',new and new[0]['exit']==[nid] and 'ci-exit-new' in next(r for r in node_rules(s,nid) if r['ruleTag'].endswith(':domain'))['user'])
 s=bot('deluser','ci-exit-new');check('deleted-user-leaves-the-rules',not any('ci-exit-new' in r.get('user',[]) for r in s['rules']))
 # ── Куда пойдёт домен (временный Xray в xray-audit), сервисы, экспорт ──
 s=bot('where',nid,'video.exit.test '+email);check('where-shows-the-node-for-a-node-user',said(s,'через узел <b>') and said(s,'запись <code>domain:video.exit.test</code>'))
 s=bot('where',nid,'direct.exit.test '+email);check('where-shows-no-node-for-other-domains',not said(s,'через узел <b>') and (said(s,'ни одно правило не подошло') or said(s,'напрямую')))
 s=bot('where',nid,'video.exit.test');check('where-without-user-shows-both',said(s,'пользователь без узлов') and said(s,'пользователи узла'))
 s=bot('preset',nid,'discord');check('service-preset-added',all(e in s['nodes'][nid]['routes'] for e in ('domain:discord.com','domain:discord.gg')))
 s=bot('preset',nid,'discord');check('service-preset-removed',not any(e.startswith('domain:discord') for e in s['nodes'][nid]['routes']) and 'domain:video.exit.test' in s['nodes'][nid]['routes'])
 s=bot('roundtrip',nid);check('export-import-roundtrip',said(s,'"same":true'))
 menus=bot('menus',nid);check('menus-open',len(menus['messages'])>=10 and all(cb in menus['buttons'] for cb in ('/exitCreate','/exitAdd','/exitRelayAdd','/exitSettings '+nid,'/exitDiag '+nid)))
 check('menus-hide-the-node-keys',not any(public in m or uid in m for m in menus['messages']))
 s=bot('delete',nid);check('node-deleted',s['nodes']=={} and s['outbounds']==[] and s['inbounds']==[] and s['rules']==[] and s['balancers']==[] and s['burst'] is None)
 check('deleted-node-cleared-from-users',all(c['exit'] is None for c in s['clients']) and s['sets']==[])
 check('after-delete-direct',wait(lambda:direct('video.exit.test'),20))
 s=bot('relay-del','node-ci-main')
 check('relay-profile-deleted',not any(c['email']=='node-ci-main' for c in s['clients']) and said(s,'Удалить профиль для узла <b>node-ci-main</b>') and said(s,'Профиль удалён'))
 check('relay-delete-keeps-regular-users',email in [c['email'] for c in s['clients']])
 check('xray-running-at-the-end-of-the-flow',xray_alive())
finally:
 if client:client.terminate();client.wait(10)
 try:
  after=bot('reset');check('stand-restored',after['nodes']=={} and after['rules']==[] and not any(c['relay'] for c in after['clients']))
 except Exception:check('stand-restored',False)
 run('docker','exec',TARGET,'sh','-c','pkill -f "[e]xit-target.py"; pkill -f "[e]xit-sets-server.py"; rm -rf /tmp/exit-sets /tmp/exit-target.log /tmp/exit-key.pem')
 if hosts_added:run('docker','exec','xray-audit','sh','-c','cat /tmp/hosts.exit-ci > /etc/hosts && rm -f /tmp/hosts.exit-ci')
 if bundle_saved:run('docker','exec','xray-audit','sh','-c','cat /tmp/ca-bundle.exit-ci > %s && rm -f /tmp/ca-bundle.exit-ci /tmp/exit-ca.pem'%BUNDLE)
 if trust:run('docker','exec','php-audit','rm','-f',trust)
 run('docker','rm','-f',EXIT)
 for name in connected:run('docker','network','disconnect',NET,name)
 for path in (O/'ca.pem',O/'key.pem',O/'ci.srs',O/'ci.mrs',O/'client.json',O/'exit-server.json'):path.unlink(missing_ok=True)
 check('xray-running-at-the-end',xray_alive())
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}))
raise SystemExit(0 if all(x['passed'] for x in results) else 1)
