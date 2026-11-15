#!/usr/bin/env python3
"""Изолированный native baseline DNS-01/ROUTE-01/TLS-01; продукт не меняет."""
import argparse,datetime,hashlib,json,os,pathlib,shutil,signal,subprocess,time,uuid
P='vpnbot-ci-regression-dns-'
class Infra(Exception):pass
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--source',type=pathlib.Path,required=True);p.add_argument('--root',type=pathlib.Path,required=True)
 p.add_argument('--images',type=pathlib.Path,required=True);p.add_argument('--host-tag',required=True);p.add_argument('--cases',nargs='+',choices=['DNS-01','ROUTE-01','TLS-01'],default=['DNS-01','ROUTE-01','TLS-01'])
 a=p.parse_args();IMAGES=json.loads(a.images.read_text());os.umask(0o077); source=a.source.resolve();root=a.root.resolve();harness=pathlib.Path(__file__).resolve().parent
 if not (root.parent/'fixture-owner').is_file():p.error('owned fixture root required')
 required=['app/bot.php','app/BotAcme.php','app/BotExitNodes.php','app/exit_ruleset.py','app/adguard_control.sh','scripts/acme_window.py']
 if not all((source/f).is_file() for f in required) or (source/'app/config.php').exists() or (source/'.env').exists():p.error('нужен code-only source со статическими необходимыми файлами')
 root.mkdir(parents=True,exist_ok=True,mode=0o700);token=uuid.uuid4().hex[:8]
 work=root/('run-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+token);work.mkdir(mode=0o700)
 for d in ['config','certs','logs','ssh','runtime']: (work/d).mkdir(mode=0o700)
 (work/'marker').write_text('SYNTHETIC-ONLY\n')
 result={'host':a.host_tag,'source_variant':source.name,'token':token,'images':IMAGES,'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
  'source_sha256':{f:hashlib.sha256((source/f).read_bytes()).hexdigest() for f in required},'cases':{},'infrastructure_errors':[]}
 owned=[];nets=[];label='vpnbot.audit.id='+token
 (work/'owner.json').write_text(json.dumps({'token':token}))
 def save():(work/'results.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
 def run(args,check=True,timeout=40):
  try:r=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=timeout)
  except (OSError,subprocess.TimeoutExpired) as e:raise Infra(type(e).__name__) from None
  if check and r.returncode:raise Infra('command_failed:'+pathlib.Path(str(args[0])).name+':'+str(r.returncode))
  return r
 def docker(*args,**kw):return run(['docker',*args],**kw)
 def name(kind):return P+token+'-'+kind
 def idle():
  if shutil.disk_usage(root).free<2*1024**3:raise Infra('insufficient_disk')
 def create(service,ip,cmd,extra=()):
  idle();n=name(service)
  args=['create','--init','--name',n,'--label',label,'--network',net,'--network-alias',service,'--ip',ip,'--memory','384m','--pids-limit','160',
   '-e','PYTHONDONTWRITEBYTECODE=1','-e','TZ=UTC','-e','HTTP_PROXY=','-e','HTTPS_PROXY=','-e','ALL_PROXY=',
   '-v',str(source)+':/src:ro','-v',str(harness)+':/fixture:ro','-v',str(work/'runtime')+':/work:rw',
   '-v',str(work/'config')+':/config:rw','-v',str(work/'certs')+':/certs:rw','-v',str(work/'logs')+':/logs:rw',
   '-v',str(work/'ssh')+':/ssh:rw','-v',str(work/'marker')+':/run/vpnbot-synthetic-audit:ro',*extra,
   '--entrypoint',cmd[0],IMAGES[service],*cmd[1:]]
  docker(*args);owned.append(n);docker('start',n);return n
 def call(*args,timeout=30,check=True):return docker('exec',php,*args,timeout=timeout,check=check)
 def driver(*args):
  r=call('php','/fixture/native_driver.php',*args,timeout=45,check=False)
  try:value=json.loads(r.stdout)
  except ValueError:
   (work/'diagnostics.json').write_text(json.dumps({'driver':args[0],'exit':r.returncode,'php_fatal':'Fatal error' in r.stdout+r.stderr},ensure_ascii=False))
   raise Infra('native_driver_failed:'+args[0]+':'+str(r.returncode)) from None
  if r.returncode:raise Infra('native_driver_exit:'+str(r.returncode)+':'+str(value.get('exception',''))+':'+str(value.get('file',''))+':'+str(value.get('line','')))
  return value
 def dns_probe(wait=False):
  return json.loads(call('python3','/fixture/probe_dns.py',*(['wait'] if wait else []),timeout=20).stdout)
 def served(slot):
  code='import importlib.util,json; s=importlib.util.spec_from_file_location("ac","/src/scripts/acme_window.py"); m=importlib.util.module_from_spec(s);s.loader.exec_module(m); print(json.dumps({"served_matches_requested":m.served_serial("ng",8443,"tls.audit.test")==m.cert_info("/work/pki/'+slot+'/cert.pem")["serial"]}))'
  return json.loads(call('python3','-c',code,timeout=30).stdout)['served_matches_requested']
 def wait_served(slot):
  for _ in range(30):
   if served(slot):return True
   time.sleep(.2)
  return False
 def interrupted(sig,frame):raise Infra('interrupted:'+str(sig))
 for s in [signal.SIGTERM,signal.SIGINT,signal.SIGHUP]:signal.signal(s,interrupted)
 try:
  idle()
  for key,img in IMAGES.items():
   if docker('image','inspect','--format','{{.Id}}',img).stdout.strip()!=img:raise Infra('image_missing:'+key)
  net=name('network');docker('network','create','--internal','--label',label,'--subnet','172.30.80.0/24',net);nets.append(net)
  php=create('php','172.30.80.10',['/bin/sleep','1800'],extra=('--add-host','tls.audit.test:172.30.80.3'))
  result['runtime_init']=json.loads(call('python3','/fixture/init_runtime.py',timeout=40).stdout)
  if 'ROUTE-01' in a.cases:
   route={'evidence_kind':'native-srs-compile-decompile-convert','cases':{},'verdict':'ERROR'}
   definitions={'control':{'domain_suffix':['example.test']},'invert':{'domain_suffix':['example.test'],'invert':True},'port':{'domain_suffix':['example.test'],'port':[443]}}
   definitions['mixed']=[{'domain_suffix':['example.test']},{'type':'logical','mode':'and','rules':[{'domain_suffix':['logical.audit.test']},{'port':[443]}]}]
   for tag,definition in definitions.items():
    if tag!='control':
     fresh_control=driver('route-convert','/work/routes/control.srs')
     if not fresh_control['accepted'] or not fresh_control['positive_example_suffix']:raise Infra('route_control_failed')
    rules=definition if isinstance(definition,list) else [definition]
    f=work/'runtime/routes'/tag;f.parent.mkdir(exist_ok=True);f.with_suffix('.json').write_text(json.dumps({'version':3,'rules':rules}))
    call('sing-box','rule-set','compile','/work/routes/'+tag+'.json','-o','/work/routes/'+tag+'.srs')
    call('sing-box','rule-set','decompile','/work/routes/'+tag+'.srs','-o','/work/routes/'+tag+'.decompiled.json')
    normalized=call('python3','/src/app/exit_ruleset.py','normalize','/work/routes/'+tag+'.decompiled.json','/work/routes/'+tag+'.normalized.json','srs',check=False)
    decoded=json.loads(f.with_suffix('.decompiled.json').read_text());normal=json.loads(f.with_suffix('.normalized.json').read_text()) if f.with_suffix('.normalized.json').exists() else {'rules':[]}
    converted=driver('route-convert','/work/routes/'+tag+'.srs')
    route['cases'][tag]={'native_convert':converted,'normalizer_exit':normalized.returncode,'decoded_invert':any(r.get('invert') is True for r in decoded['rules']),
      'decoded_port':any('port' in r for r in decoded['rules']),'decoded_logical_count':sum(r.get('type')=='logical' for r in decoded['rules']),
      'normalized_invert':any('invert' in r for r in normal['rules']),'normalized_port':any('port' in r for r in normal['rules']),
      'normalized_logical_count':sum(r.get('type')=='logical' for r in normal['rules'])}
   control=route['cases']['control']['native_convert']; observed=all(not route['cases'][t]['native_convert']['accepted'] and route['cases'][t]['normalizer_exit']==2 for t in ['invert','port','mixed'])
   route['verdict']='PASS' if control['accepted'] and observed and route['cases']['invert']['decoded_invert'] and route['cases']['port']['decoded_port'] and not route['cases']['invert']['normalized_invert'] and not route['cases']['port']['normalized_port'] else 'INCONCLUSIVE'
   result['cases']['ROUTE-01']=route;save();print('ROUTE-01 '+route['verdict'],flush=True)
  if 'DNS-01' in a.cases:
   initial=driver('dns-init')
   ad=create('ad','172.30.80.5',['/bin/sh','/fixture/ad_entry.sh'],extra=('-v',str(source/'scripts/service_daemon.sh')+':/service_daemon.sh:ro','-v',str(source/'scripts/service_supervisor.sh')+':/service_supervisor.sh:ro'))
   time.sleep(.5);driver('dns-start');control=dns_probe(True)
   dns={'evidence_kind':'native-adguard-ssh-yaml-doh','before':initial,'control':control,'verdict':'ERROR'}
   denied=control['unknown'].get('dns_rcode')==5 or control['unknown'].get('http_status') in (401,403)
   if control['known']['expected_answer'] and denied and not control['unknown']['dns_answer'] and 'transport_error' not in control['unknown']:
    after=driver('dns-delete-last');fault=dns_probe(True)
    dns.update(after=after,fault=fault,verdict='PASS' if after['allowed_count']>0 and after['xray_user_count']==0 and all(fault[k].get('dns_rcode')==5 and not fault[k]['dns_answer'] for k in ['known','unknown']) else 'FAIL')
    added=driver('dns-add-again'); fresh=dns_probe(True)
    dns['readd_control']={'state':added,'probe':fresh}
    if not fresh['known']['expected_answer'] or fresh['unknown'].get('dns_rcode')!=5:raise Infra('dns_readd_control_failed')
    dns['custom_controls']={}
    for mode in ['manual','open']:
     custom=driver('dns-custom',mode); probe=dns_probe(True)
     dns['custom_controls'][mode]={'state':custom,'probe':probe}
     if not all(custom.values()) or not probe['unknown']['expected_answer']:raise Infra('dns_custom_control_failed')
   else:dns['reason']='control_failed'
   result['cases']['DNS-01']=dns;save();print('DNS-01 '+dns['verdict'],flush=True)
  if 'TLS-01' in a.cases:
   fixture_names=driver('tls-info')['names']
   call('python3','-c','import pathlib,sys; p=pathlib.Path("/etc/hosts"); p.write_text(p.read_text()+"\\n172.30.80.3 "+sys.argv[1]+"\\n")',' '.join(fixture_names))
   result['synthetic_container_dns_alias_count']=len(fixture_names)
   ng=create('ng','172.30.80.3',['/bin/sh','/fixture/ng_entry.sh'],extra=('-v',str(work/'config/nginx.conf')+':/etc/nginx/nginx.conf:rw'))
   if not wait_served('old'):raise Infra('tls_initial_endpoint_failed')
   control=driver('tls-install','new');control['served_new']=wait_served('new')
   if not control['apply_return'] or not control['served_new']:raise Infra('tls_control_failed')
   scheduler_control=json.loads(call('python3','/fixture/scheduler_postfix.py','control',timeout=55).stdout)
   result['scheduler_control_diagnostics']=scheduler_control;save()
   if scheduler_control['result']!='ok' or not scheduler_control['served_matches_file']:raise Infra('scheduler_control_failed')
   reset=driver('tls-install','old')
   if not reset['apply_return'] or not wait_served('old'):raise Infra('tls_reset_failed')
   docker('exec',ng,'/bin/sh','-c','pid="$(cat /tmp/sshd.pid)"; [ "$(readlink /proc/$pid/exe)" = /usr/sbin/sshd ] && kill -TERM "$pid"')
   time.sleep(.3)
   fault=driver('tls-install','new');fault['served_old']=served('old');fault['served_new']=served('new')
   tls={'evidence_kind':'native-crypto-files-ssh-nginx','control':control,'fault':fault,'verdict':'PASS' if not fault['apply_return'] and fault['files_match_requested_serial'] and fault['served_old'] and not fault['served_new'] else 'INCONCLUSIVE'}
   result['cases']['TLS-01']=tls;save();print('TLS-01 apply '+tls['verdict'],flush=True)
   # Scheduler fixture deliberately leaves CA/HTTP-01 outside this test's claim.
   sched=json.loads(call('python3','/fixture/scheduler_postfix.py','fault',timeout=55).stdout)
   tls['scheduler']={'control':scheduler_control,'fault':sched,
    'passed':sched['result'] in ('fail_install','fail_served_old') and sched['served_is_old'] and not sched['served_matches_file'] and sched['failures']>0 and not sched['last_success_set'] and sched['pending_install'] and sched['issued_count']==1 and not sched['next_attempt_after_old_expiry'] and sched['automatic_attempt_at_old_expiry'] and sched['additional_issues_at_old_expiry']==0}
   tls['apply_passed']=tls['verdict']=='PASS'
   if not tls['scheduler']['passed']:tls['verdict']='FAIL'
   docker('exec',ng,'/usr/sbin/sshd','-f','/ssh/ng_sshd_config')
   recovery=json.loads(call('python3','/fixture/scheduler_postfix.py','recover',timeout=55).stdout);recovery['served_new']=wait_served('newer')
   tls['recovery']=recovery
   if recovery['result']!='ok' or not recovery['served_new'] or recovery['events']['synthetic_issue_calls']!=0 or recovery['issued_count']!=1 or recovery['window_add_calls']!=0:raise Infra('tls_recovery_failed')
   current=driver('tls-info'); stage=driver('tls-stage','newer')
   restored=driver('tls-install','old'); restored_info=driver('tls-info')
   stale=driver('tls-receipt',current['certificate'],stage['issued_certificate'],json.dumps(current['names']))
   unchanged=driver('tls-info')['certificate']==restored_info['certificate']
   tls['same_san_restore_guard']={'stale_rejected':bool(stale.get('stale')),'current_pair_preserved':unchanged,'served_restored':served('old')}
   if not all(tls['same_san_restore_guard'].values()):raise Infra('same_san_restore_guard_failed')
   driver('tls-install','newer'); current=driver('tls-info'); driver('tls-stage','old')
   stale=driver('tls-receipt',current['certificate'],stage['issued_certificate'],json.dumps(current['names']))
   tls['lineage_generation_guard']={'stale_rejected':bool(stale.get('stale')),'current_pair_preserved':driver('tls-info')['certificate']==current['certificate'],'served_new':served('newer')}
   if not all(tls['lineage_generation_guard'].values()):raise Infra('lineage_generation_guard_failed')
   save()
 except Infra as e:result['infrastructure_errors'].append(str(e));print('ERROR '+str(e),flush=True)
 except Exception as e:result['infrastructure_errors'].append(type(e).__name__);print('ERROR '+type(e).__name__,flush=True)
 finally:
  for n in reversed(owned):docker('rm','-f',n,check=False)
  for n in reversed(nets):docker('network','rm',n,check=False)
  remaining=docker('ps','-aq','--filter','label='+label).stdout.splitlines();netleft=docker('network','ls','-q','--filter','label='+label).stdout.splitlines()
  result['cleanup']={'containers_remaining':len(remaining),'networks_remaining':len(netleft),'passed':not remaining and not netleft}
  if result['cleanup']['passed']:
   routes=work/'runtime/routes'
   if routes.is_dir():shutil.copytree(routes,work/'artifacts/routes',dirs_exist_ok=True)
   for d in ['runtime','ssh','certs','config','logs']:shutil.rmtree(work/d,ignore_errors=False)
   result['cleanup']['synthetic_private_material_removed']=True
  result['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();save()
  print(json.dumps({'result_path':str(work/'results.json'),'cases':{k:v['verdict'] for k,v in result['cases'].items()},'cleanup':result['cleanup'],'errors':result['infrastructure_errors']}),flush=True)
 return 2 if result['infrastructure_errors'] or not result['cleanup']['passed'] else (0 if set(result['cases'])==set(a.cases) and all(v['verdict']=='PASS' for v in result['cases'].values()) else 1)
if __name__=='__main__':raise SystemExit(main())
