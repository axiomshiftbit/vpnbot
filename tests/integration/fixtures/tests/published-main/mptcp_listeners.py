#!/usr/bin/env python3
"""Ни один слушатель TCP в контейнерах стенда не принимает MPTCP.

CVE-2026-98432: через слушающий сокет IPv4 MPTCP ядро Linux даёт удалённый
root, а Go 1.24+ слушает MPTCP по умолчанию. Бот выключает его переменной
GODEBUG=multipathtcp=0 (.env, окружение модулей, SetEnv в sshd_config для
процессов, запущенных по SSH). Проба в сетевом пространстве каждого
контейнера находит всех слушателей в /proc/net/tcp{,6}, подключается к
каждому клиентом MPTCP и спрашивает у ядра TCP_IS_MPTCP: 1 — сервер принял
MPTCP. Встроенный DNS Docker (127.0.0.11) держит сам dockerd хоста, наружу он
не виден и в проверку не входит. Положительный контроль: проба распознаёт
собственного слушателя MPTCP."""
import json,os,pathlib,subprocess
os.umask(0o077);R=pathlib.Path('/opt/vpnbot-hosted-ci/stand');O=R/'results/mptcp';O.mkdir(mode=0o700,parents=True,exist_ok=True);results=[]
def run(*a,timeout=120):return subprocess.run(list(map(str,a)),capture_output=True,text=True,timeout=timeout)
def check(n,v,**d):
 results.append({'name':n,'passed':bool(v),**d});(O/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if v else 'FAIL ')+n+('' if v else ' '+json.dumps(d)),flush=True)
PROBE=r'''
import json,socket,sys
IS_MPTCP=43
def listeners():
 out=set()
 for path,fam in (('/proc/net/tcp',socket.AF_INET),('/proc/net/tcp6',socket.AF_INET6)):
  try:lines=open(path).read().splitlines()[1:]
  except OSError:continue
  for line in lines:
   f=line.split()
   if f[3]!='0A':continue
   addr,port=f[1].split(':');raw=bytes.fromhex(addr)
   raw=b''.join(raw[i:i+4][::-1] for i in range(0,len(raw),4))
   out.add((fam,socket.inet_ntop(fam,raw),int(port,16)))
 return sorted(out)
def probe(fam,host,port):
 s=socket.socket(fam,socket.SOCK_STREAM,262);s.settimeout(3)
 try:s.connect((host,port));return s.getsockopt(socket.IPPROTO_TCP,IS_MPTCP)
 except OSError as e:return 'error:'+type(e).__name__
 finally:s.close()
if sys.argv[1:]==['control']:
 l=socket.socket(socket.AF_INET,socket.SOCK_STREAM,262);l.bind(('127.0.0.1',0));l.listen(1)
 print(json.dumps(probe(socket.AF_INET,'127.0.0.1',l.getsockname()[1])));sys.exit()
rows=[]
for fam,ip,port in listeners():
 if ip.startswith('127.0.0.11'):continue
 host={'0.0.0.0':'127.0.0.1','::':'::1'}.get(ip,ip)
 rows.append([ip,port,probe(fam,host,port)])
print(json.dumps(rows))
'''
image=json.loads(run('docker','inspect','--format','{{json .Config.Image}}','xray-audit').stdout or '""')
check('probe-image-found',image!='')
control=run('docker','run','--rm','--network','none','--entrypoint','python3',image,'-c',PROBE,'control')
check('probe-detects-mptcp-listener',control.stdout.strip()=='1',out=control.stdout.strip()[:80],err=control.stderr[-200:])
names=sorted(n for n in run('docker','ps','--format','{{.Names}}').stdout.split() if n.endswith('-audit'))
check('stand-containers-found',len(names)>=10,count=len(names))
probed=0
for name in names:
 r=run('docker','run','--rm','--network','container:'+name,'--entrypoint','python3',image,'-c',PROBE)
 try:rows=json.loads(r.stdout)
 except ValueError:rows=None
 if rows is None:
  check(name+'-probed',False,err=(r.stderr or r.stdout)[-200:]);continue
 probed+=len(rows)
 mptcp=[f'{ip}:{port}' for ip,port,state in rows if state==1]
 check(name+'-no-mptcp-listeners',not mptcp,mptcp=mptcp,listeners=len(rows))
check('listeners-probed',probed>=20,probed=probed)
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}))
raise SystemExit(0 if all(x['passed'] for x in results) else 1)
