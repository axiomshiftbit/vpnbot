from pathlib import Path
import os,sys,json,subprocess,socket,time,re,hashlib,fcntl,importlib.util
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE/'support'))
import probe_limits as p
p.ROOT=HERE/'container-cases';p.ROOT.mkdir(exist_ok=True)
SOURCE=Path(os.environ['SOURCE_DIR']);IMAGE=os.environ['TELEMT_IMAGE'];NAME='vpnbot-telemt-php85-fixture';results=[]
spec=importlib.util.spec_from_file_location('state',SOURCE/'scripts/telemt_state.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def check(name,ok,**extra):
 results.append({'name':name,'ok':bool(ok),**extra});(HERE/'container-results.json').write_text(json.dumps(results,indent=2));print(name,'OK' if ok else 'FAIL',flush=True)
 if not ok:raise AssertionError(name)
def docker(*args,timeout=70):return subprocess.run(['docker',*args],text=True,capture_output=True,timeout=timeout,check=True).stdout
with socket.socket() as guard:guard.bind(('127.0.0.1',9091))
c=p.Core('state',limit=2,quota=10000);c.a=9091
config='show_link = ["alice", "bob"]\n'+re.sub(r'quota_state_path = "[^"]+"','quota_state_path = "/telemt/data/telemt.limit.json"',c.config)
config=re.sub(r'listen = "127.0.0.1:\d+"','listen = "127.0.0.1:9091"',config)
config=config.replace('read_only = false','read_only = true').replace(str(c.root)+'/decoy','/telemt/decoy')
(c.root/'telemt.toml').write_text(config);(c.root/'data').mkdir(exist_ok=True)
statepath=c.root/'data/telemt.limit.json';statepath.write_text(json.dumps({'last_reset_epoch_secs':0,'users':{'alice':{'used_bytes':0,'last_reset_epoch_secs':0},'bob':{'used_bytes':0,'last_reset_epoch_secs':0}}}))
(c.root/'service-enabled').write_text('1\n');(c.root/'ssh').mkdir(exist_ok=True);(c.root/'ssh/key.pub').write_text('')
(c.root/'sshd_config').write_text(f'Port {p.port()}\nListenAddress 127.0.0.1\nHostKey /etc/ssh/ssh_host_ed25519_key\nPidFile /tmp/sshd.pid\nLogLevel ERROR\nPasswordAuthentication no\n')
for owned in [c.root, *c.root.rglob("*")]:os.chown(owned,os.getuid(),os.getgid())
def create():
 return docker('run','-d','--name',NAME,'--label','vpnbot.hosted-ci=true','--init','--network','host','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','256m','--pids-limit','128','--stop-timeout','45',
 '-v',str(c.root)+':/telemt','-v',str(c.root)+':/logs','-v',str(c.root/'ssh')+':/ssh:ro','-v',str(c.root/'sshd_config')+':/etc/ssh/sshd_config:ro',
 '-v',str(SOURCE/'scripts/start_telemt.sh')+':/start_telemt.sh:ro','-v',str(SOURCE/'scripts/telemt_state.py')+':/telemt_state.py:ro',IMAGE,'/bin/sh','/start_telemt.sh')
def alive():
 try:return c.api('/v1/health')[0]==200
 except OSError:return False

def saved():return m.TelemtState(c.root).read()['users']['alice']['used_bytes']
def clients_close():
 for child in c.children:child.close()
 c.children=[]
try:
 create();check('new_image_supervisor_starts_core',p.wait(alive,15))
 check('actual_image_core_hash',docker('exec',NAME,'sha256sum','/usr/local/bin/telemt').split()[0]==hashlib.sha256(Path(os.environ['TELEMT_BINARY']).read_bytes()).hexdigest())
 check('actual_image_helper_present',docker('exec',NAME,'python3','/telemt_state.py','version').strip()=='TELEMT_STATE_OK')
 n=c.native();w=c.web('198.51.100.1');check('container_native_and_web_traffic',n.echo()==b'test-data'*8 and w.echo()==b'test-data'*8)
 check('container_ip_limit_shared',c.native('127.0.0.3').echo()==b'')
 used=c.used();check('supervisor_periodic_checkpoint',p.wait(lambda:saved()==used,5))
 inode=statepath.stat().st_ino;time.sleep(2.2);check('idle_checkpoint_does_not_rewrite_file',statepath.stat().st_ino==inode)
 check('snapshot_private_mode',statepath.stat().st_mode&0o777==0o600)
 with (c.root/'.lock.telemt').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX);before=saved();n.echo();used=c.used();time.sleep(1.5)
  check('watcher_respects_php_shared_lock',saved()==before)
 check('watcher_resumes_after_php_unlock',p.wait(lambda:saved()==used,5))
 old_watcher=docker('exec',NAME,'pgrep','-f','^python3 /telemt_state.py watch$').strip()
 docker('exec',NAME,'pkill','-KILL','-f','^python3 /telemt_state.py watch$')
 def watcher_restarted():
  try:return docker('exec',NAME,'pgrep','-f','^python3 /telemt_state.py watch$').strip()!=old_watcher
  except subprocess.CalledProcessError:return False
 check('supervisor_recovers_checkpoint_worker',p.wait(watcher_restarted,6))
 n.echo();used=c.used();check('restarted_worker_saves_traffic',p.wait(lambda:saved()==used,5))
 clients_close();pid=docker('exec',NAME,'pgrep','-x','telemt').strip();docker('exec',NAME,'pkill','-KILL','-x','telemt')
 def restarted():
  try:return alive() and docker('exec',NAME,'pgrep','-x','telemt').strip()!=pid
  except subprocess.CalledProcessError:return False
 check('supervisor_recovers_core_after_sigkill',p.wait(restarted,10));check('core_crash_keeps_checkpoint',c.used()==used)
 n=c.native();w=c.web('198.51.100.1');n.echo();w.echo();used=c.used()
 begin=time.monotonic();docker('stop','--time','45',NAME);elapsed=time.monotonic()-begin
 check('docker_stop_graceful_under_deadline',elapsed<40,seconds=round(elapsed,3))
 inspect=json.loads(docker('inspect',NAME))[0];check('docker_stop_not_killed',inspect['State']['ExitCode']!=137)
 check('docker_stop_saves_exact_active_usage',saved()==used)
 clients_close();docker('start',NAME);check('docker_start_restores_quota',p.wait(alive,12) and c.used()==used)
 n=c.native();n.echo();used=c.used();(c.root/'service-enabled').write_text('0\n')
 check('saved_service_disable_stops_core',p.wait(lambda:not alive(),10));check('service_disable_saves_exact_usage',saved()==used)
 clients_close();(c.root/'service-enabled').write_text('1\n');check('saved_service_enable_restores_quota',p.wait(alive,12) and c.used()==used)
 docker('stop','--time','45',NAME);docker('rm',NAME);create();check('container_recreation_keeps_bind_mount_usage',p.wait(alive,12) and c.used()==used)
 docker('stop','--time','45',NAME);state=statepath.read_text();statepath.write_text('{broken');docker('start',NAME);time.sleep(3)
 check('supervisor_refuses_corrupt_quota_state',not alive())
 statepath.write_text(state);check('supervisor_recovers_after_restore',p.wait(alive,12) and c.used()==used)
 docker('stop','--time','45',NAME);state=statepath.read_text();statepath.unlink();docker('start',NAME);time.sleep(3)
 check('supervisor_refuses_missing_quota_state',not alive())
 statepath.write_text(state);check('restore_after_missing_state',p.wait(alive,12) and c.used()==used)
 time.sleep(5)
 stats=docker('stats','--no-stream','--format','{{.CPUPerc}}|{{.MemUsage}}',NAME).strip();check('container_resource_sample',True,sample=stats)
 os.chmod(c.root/'data',0o500);docker('stop','--time','45',NAME)
 exitcode=json.loads(docker('inspect',NAME))[0]['State']['ExitCode']
 check('docker_stop_reports_failed_final_write',exitcode not in [0,137],exitcode=exitcode)
 os.chmod(c.root/'data',0o700)
finally:
 os.chmod(c.root/'data',0o700)
 clients_close()
 try:docker('stop','--time','45',NAME)
 except subprocess.CalledProcessError:pass
 try:docker('rm',NAME)
 except subprocess.CalledProcessError:pass
 c.close()
print('TOTAL',len(results))
