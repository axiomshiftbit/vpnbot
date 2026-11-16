import pathlib,subprocess,json,sys,time
ROOT=pathlib.Path(__file__).resolve().parent; NAME='vpnbot-masque-lifecycle-test';IMAGE=sys.argv[1];CLIENT_XRAY=sys.argv[2]
RESULTS={}
def run(args,**kw):return subprocess.run(args,check=True,capture_output=True,text=True,**kw).stdout
def check(name,v):
 RESULTS[name]=bool(v);(ROOT/'results/lifecycle.json').write_text(json.dumps(RESULTS,indent=2));print(name,'PASS' if v else 'FAIL',flush=True)
 if not v:raise RuntimeError(name)
def wait(fn):
 for _ in range(100):
  if fn():return True
  time.sleep(.1)
 return False
def status():
 try:return json.loads((ROOT/'lifecycle-state/status.json').read_text())
 except (OSError,ValueError):return {}
def save(s):
 p=ROOT/'lifecycle-config/desired.json';t=p.with_suffix('.tmp');t.write_text(json.dumps(s));t.replace(p)
def create():
 args=['docker','run','-d','--name',NAME,'--label','vpnbot.hosted-ci=true','--network','none','--memory','160m','--pids-limit','128','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--init','--log-driver','json-file','--entrypoint','python3','-e','PROTOCOL_DESIRED=/config/desired.json']
 for src,dst in [(str(ROOT),'/lab'),(str(ROOT/'lifecycle-state'),'/state'),(str(ROOT/'lifecycle-config'),'/config:ro'),(str(ROOT/'certs'),'/certs:ro'),(str(ROOT/'xray-masque'),'/usr/local/bin/xray:ro'),(str(ROOT/'source/scripts/masque_service.py'),'/masque_service.py:ro'),(str(ROOT/'source/scripts/protocol_service.py'),'/protocol_service.py:ro'),(CLIENT_XRAY,'/client-xray:ro')]:args+=['-v',src+':'+dst]
 run(args+[IMAGE,'/masque_service.py','/state'])
 info=json.loads(run(['docker','inspect',NAME]))[0];pid=str(info['State']['Pid']);run(['nsenter','-t',pid,'-n','ip','addr','add','198.51.100.23/32','dev','lo']);return info
for n in ['lifecycle-state','lifecycle-config']:(ROOT/n).mkdir(mode=0o700,exist_ok=True)
# A clean protocol store writes its empty usage ledger before its first desired state.
ledger=ROOT/'lifecycle-state/usage.json'
if not ledger.exists():ledger.write_text(json.dumps({'users':{}}));ledger.chmod(0o600)
s=json.loads((ROOT/'desired.json').read_text());save(s)
try:
 info=create();check('real_entrypoint_running',wait(lambda:status().get('phase')=='running'))
 probe="""exec(open('/lab/native_matrix.py').read().split('\\ntry:\\n for host')[0]);echo('198.51.100.23',18080);c=client();ok=tcp();stop(c);raise SystemExit(0 if ok else 1)"""
 check('entrypoint_native_traffic',subprocess.run(['docker','exec',NAME,'python3','-c',probe],capture_output=True).returncode==0)
 check('poll_persists_usage',wait(lambda: (ROOT/'lifecycle-state/usage.json').exists() and any(u.get('upload',0)>0 for u in json.loads((ROOT/'lifecycle-state/usage.json').read_text())['users'].values())))
 usage=json.loads((ROOT/'lifecycle-state/usage.json').read_text());run(['docker','stop','-t','15',NAME]);run(['docker','rm',NAME]);check('removed_only_fixture',subprocess.run(['docker','inspect',NAME],capture_output=True).returncode!=0)
 info=create();check('cold_recreate_running',wait(lambda:status().get('phase')=='running'))
 now=json.loads((ROOT/'lifecycle-state/usage.json').read_text());check('cold_recreate_keeps_usage',all(now['users'][uid]['upload']>=u['upload'] for uid,u in usage['users'].items()));check('cold_recreate_native_traffic',subprocess.run(['docker','exec',NAME,'python3','-c',probe],capture_output=True).returncode==0)
 s['enabled']=False;s['revision']+=1;save(s);check('disable_removes_child',wait(lambda:status().get('phase')=='disabled' and not status().get('running')))
 run(['docker','restart','-t','15',NAME]);check('restart_does_not_reenable',wait(lambda:status().get('phase')=='disabled' and not status().get('running')))
 s['enabled']=True;s['revision']+=1;save(s);check('reenable_after_restart',wait(lambda:status().get('phase')=='running'))
 inspection=json.loads(run(['docker','inspect',NAME]))[0];check('no_oom_no_extra_privileges',not inspection['State']['OOMKilled'] and inspection['HostConfig']['ReadonlyRootfs'] and inspection['HostConfig']['CapDrop']==['ALL'])
 print('LIFECYCLE COMPLETED',len(RESULTS),flush=True)
finally:
 (ROOT/'lifecycle-container.log').write_bytes(subprocess.run(['docker','logs',NAME],capture_output=True).stdout+subprocess.run(['docker','logs',NAME],capture_output=True).stderr)
 subprocess.run(['docker','stop','-t','15',NAME],capture_output=True);subprocess.run(['docker','rm',NAME],capture_output=True)
