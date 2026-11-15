#!/usr/bin/env python3
"""Disposable real WG/AWG old-client payload through public backup importer.

No host network/firewall changes, only two isolated container namespaces.
Other protocols/Nginx and SSH transport are outside this narrow entry's scope.
"""
import argparse,hashlib,json,os,pathlib,re,shutil,subprocess,tempfile,uuid

def main():
 p=argparse.ArgumentParser();p.add_argument('--source',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--php-image',required=True);p.add_argument('--wg-image',required=True);p.add_argument('--hosted-ci',action='store_true');a=p.parse_args()
 os.umask(0o077);a.out.mkdir(parents=True,exist_ok=True);tag=uuid.uuid4().hex[:10];owned=[];backends={};network='vpnbot-backup-native-'+tag;rows=[];error=None;made_network=False
 def run(cmd,timeout=40,input=None):return subprocess.run(list(map(str,cmd)),capture_output=True,timeout=timeout,input=input)
 def check(ok,name):
  rows.append({'name':name,'passed':bool(ok)})
  if not ok:raise RuntimeError(name)
 def execute(name,*cmd,timeout=40):return run(['docker','exec',name,*cmd],timeout)
 try:
  if a.hosted_ci:
   workers={int(pid) for pid in run(['pgrep','-x','Runner.Worker']).stdout.split()}
   ancestors=set();pid=os.getpid()
   while pid>1:
    ancestors.add(pid);pid=int(pathlib.Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[1])
   check(workers.issubset(ancestors),'no_foreign_runner')
   check(pathlib.Path('/opt/vpnbot-hosted-ci/owner').read_text()=='vpnbot-hosted-ci\n','owned_hosted_ci_fixture')
   check(run(['docker','exec','php-audit','php','-r','exit(getenv("TELEGRAM_API")==="tg-audit:8443"?0:1);']).returncode==0,'synthetic_telegram_only')
  else:check(run(['pgrep','-x','Runner.Worker']).returncode!=0,'runner_idle')
  for image in [a.php_image,a.wg_image]:check(run(['docker','image','inspect',image]).returncode==0,'cached_image_'+image)
  with tempfile.TemporaryDirectory(prefix='payload-',dir=a.out.resolve())as temp:
   scratch=pathlib.Path(temp);source=scratch/'source';binary=scratch/'bin';binary.mkdir()
   for f in (a.source/'app').glob('*.php'):
    if f.name in ['config.php','debug.php']or f.is_symlink():continue
    dest=source/'app'/f.name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(f,dest)
   source_hash={str(f.relative_to(source)):hashlib.sha256(f.read_bytes()).hexdigest()for f in source.rglob('*.php')}
   extract='vpnbot-backup-extract-'+tag;owned.append(extract)
   check(run(['docker','create','--name',extract,'--network','none','--entrypoint','/bin/true',a.wg_image]).returncode==0,'extract_container')
   for path in ['/usr/bin/wg','/usr/bin/awg','/usr/bin/amneziawg-go','/usr/bin/wg-quick','/usr/bin/awg-quick','/bin/bash','/sbin/ip','/usr/lib/libelf.so.1','/usr/lib/libmnl.so.0','/usr/lib/libcap.so.2','/usr/lib/libz.so.1','/usr/lib/libzstd.so.1','/usr/lib/libreadline.so.8','/usr/lib/libncursesw.so.6']:
    check(run(['docker','cp','-L',extract+':'+path,binary/pathlib.Path(path).name]).returncode==0,'native_binary_'+pathlib.Path(path).name)
   run(['docker','rm','-f',extract]);check(run(['docker','network','create','--internal',network]).returncode==0,'isolated_network');made_network=True
   for mode in ['wg','awg']:
    server='vpnbot-backup-server-'+mode+'-'+tag;client='vpnbot-backup-client-'+mode+'-'+tag
    for name in [server,client]:
     owned.append(name)
     cmd=['docker','run','-d','--init','--name',name,'--network',network,'--read-only','--cap-drop','ALL','--cap-add','NET_ADMIN','--device','/dev/net/tun','--security-opt','no-new-privileges','--memory','384m','--cpus','1','--pids-limit','96']
     for target in ['/tmp','/config','/logs','/run','/etc/wireguard','/etc/amnezia']:
      cmd+=['--tmpfs',target+':rw,exec,size=24m,mode=1777']
     for src,dst in [(source,'/source'),(binary,'/audit-bin'),(pathlib.Path(__file__).with_name('wg-driver.php').resolve(),'/driver.php')]:cmd+=['--mount','type=bind,src='+str(src)+',dst='+dst+',readonly']
     cmd+=['--env','VPNBOT_NATIVE_BACKUP_FIXTURE=isolated','--env','PATH=/audit-bin:/usr/sbin:/usr/bin:/sbin:/bin','--env','LD_LIBRARY_PATH=/audit-bin','--entrypoint','/bin/sh',a.php_image,'-ec','ln -s /etc/wireguard /etc/amnezia/amneziawg; ln -s /config/wg0.conf /etc/wireguard/wg0.conf; exec sleep infinity']
     check(run(cmd).returncode==0,mode+'-'+('server'if name==server else'client')+'-start')
     wrapper='#!/bin/sh\nif [ "$1" = up ] && [ -f /config/fail-up ]; then exit 42; fi\nexec /audit-bin/bash /audit-bin/'+mode+'-quick "$@"\n'
     f=scratch/(mode+'-quick');f.write_text(wrapper);f.chmod(0o755);check(run(['docker','exec','-i',name,'sh','-c','cat >/tmp/'+mode+'-quick; chmod 700 /tmp/'+mode+'-quick'],input=f.read_bytes()).returncode==0,mode+'-wrapper')
    def bot(action):
     r=execute(server,'php','-d','display_errors=0','/driver.php',action,mode,timeout=70)
     try:data=json.loads(r.stdout)
     except ValueError:data={}
     check(r.returncode==0 and data.get('ok'),mode+'-'+action+'-importer')
     if action=='init':backends[mode]=data.get('backend')
     for k,v in data.get('checks',{}).items():check(v,mode+'-'+action+'-'+k)
    def down():execute(client,'/tmp/'+mode+'-quick','down','/etc/wireguard/audit.conf')
    def connect(label,expected):
     down();up=execute(client,'/tmp/'+mode+'-quick','up','/etc/wireguard/audit.conf');check(up.returncode==0,mode+'-'+label+'-client-interface')
     check(execute(client,'ip','route','replace','10.77.0.1/32','dev','audit').returncode==0,mode+'-'+label+'-client-route')
     r=execute(client,'curl','--noproxy','*','--interface','audit','-sS','--max-time','4','http://10.77.0.1:18080/index.html',timeout=8)
     if expected and not (r.returncode==0 and r.stdout==b'VPNBOT-BACKUP-PAYLOAD\n'):
      hs=execute(client,'sh','-c',mode+" show audit latest-handshakes | awk '{print $2}'");target=execute(server,'curl','--noproxy','*','-sS','--max-time','2','http://10.77.0.1:18080/index.html')
      raise RuntimeError('payload exit='+str(r.returncode)+' bytes='+str(len(r.stdout))+' target_exit='+str(target.returncode)+' target_bytes='+str(len(target.stdout))+' hs='+hs.stdout.decode().strip())
     check((r.returncode==0 and r.stdout==b'VPNBOT-BACKUP-PAYLOAD\n')==expected,mode+'-'+label+'-unchanged-profile-payload')
    try:
     bot('init');ip=run(['docker','inspect','--format','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',server]).stdout.decode().strip()
     f=scratch/'client.conf';exported=execute(server,'cat','/config/client.conf');check(exported.returncode==0,mode+'-profile-before-backup');f.write_bytes(exported.stdout)
     body=re.sub(r'^Endpoint\s*=.*$', 'Endpoint = '+ip+':51820', f.read_text(), flags=re.M);body=re.sub(r'^DNS\s*=.*\n','',body,flags=re.M);f.write_text(body);profile_hash=hashlib.sha256(f.read_bytes()).hexdigest()
     check(run(['docker','exec','-i',client,'sh','-c','umask 077; cat >/etc/wireguard/audit.conf'],input=f.read_bytes()).returncode==0,mode+'-old-profile-installed')
     check(execute(server,'sh','-ec',"mkdir /tmp/http; printf 'VPNBOT-BACKUP-PAYLOAD\\n' >/tmp/http/index.html; php -S 0.0.0.0:18080 -t /tmp/http >/tmp/http.log 2>&1 &").returncode==0,mode+'-payload-target')
     connect('before',True);bot('fresh');connect('fresh-denied',False);bot('restore');connect('restored',True)
     check(execute(server,'touch','/config/fail-up').returncode==0,mode+'-native-exit-fault');bot('restore-failure')
     check(execute(server,'rm','/config/fail-up').returncode==0,mode+'-remove-fault');bot('restore');connect('retry',True)
     check(hashlib.sha256(f.read_bytes()).hexdigest()==profile_hash,mode+'-profile-not-regenerated')
    finally:
     down()
     for name in [client,server]:run(['docker','rm','-f',name])
 except Exception as e:error=type(e).__name__+':'+str(e)[:120]
 finally:
  for name in owned:run(['docker','rm','-f',name])
  if made_network:run(['docker','network','rm',network])
  cleanup=all(run(['docker','inspect','--format','{{.Id}}',name]).returncode!=0 for name in owned) and (not made_network or run(['docker','network','inspect',network]).returncode!=0)
  report={'checks':rows,'error':error,'source_sha256':locals().get('source_hash',{}),'driver_sha256':hashlib.sha256(pathlib.Path(__file__).with_name('wg-driver.php').read_bytes()).hexdigest(),'bounds':'Real wg/awg-quick, kernel/userspace tunnel, unchanged old client profile and HTTP payload; SSH replaced by local execution; no other protocol runtime','backends':backends,'cleanup_confirmed':cleanup}
  (a.out/'results.json').write_text(json.dumps(report,indent=2)+'\n')
 passed=error is None and cleanup and all(x['passed']for x in rows)
 print(json.dumps({'passed':passed,'checks':len(rows),'error':error}));return 0 if passed else 1
if __name__=='__main__':raise SystemExit(main())
