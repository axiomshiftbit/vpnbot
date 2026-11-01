#!/usr/bin/env python3
"""Полный backup/restore нового состояния на синтетическом bootstrap-стенде.

SQLite создаётся заново; старые профили Xray/Mihomo проверяются до изменения
UUID, после его изменения и после двух восстановлений. В finally возвращается
исходная полная копия и состояние cron. Частные файлы остаются на стенде.
"""
import pathlib,subprocess,json,os,time,socket,sys
ROOT=pathlib.Path('/opt/vpnbot-hosted-ci');out=pathlib.Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True,mode=0o700)
os.umask(0o077)
source=pathlib.Path('/opt/vpnbot-hosted-ci/stand/tests/mux_final_vps.py')
code=source.read_text().split("\ntry:\n bot('xray-core'")[0].replace("RUN=BASE.parent/'results/sing-mux-final-fix'",'RUN=pathlib.Path('+repr(str(out/'clients'))+')')
ns={'__file__':str(source)};exec(compile(code,str(source),'exec'),ns)
rows=[]
def check(name,ok):
 rows.append({'name':name,'passed':bool(ok)});(out/'results.json').write_text(json.dumps(rows,indent=2));print(('PASS ' if ok else 'FAIL ')+name,flush=True)
 if not ok:raise RuntimeError(name)
def run(*args):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=300).stdout
def bot(action):
 result=json.loads(run('docker','exec','php-audit','php','/tmp/backup-new-state-native.php',action))
 check(action+'-bot',result.get('ok'))
 for name,ok in result.get('checks',{}).items():check(action+'-'+name,ok)
def traffic(kind,label,expected=True):
 port=ns['lab'].port();cfg=ns['profile'](kind,port);file=out/(kind+'.json');file.write_text(json.dumps(cfg))
 binary=ROOT/('tests/xray' if kind=='xray' else 'clients/mihomo')
 with (out/(kind+'.log')).open('wb') as log:
  process=subprocess.Popen(list(map(str,ns['lab'].config_args(kind,file,binary=binary))),stdout=log,stderr=log,env=ns['lab'].ENV)
  try:
   check(label+'-'+kind+'-starts',ns['lab'].ready(process,port))
   reply=subprocess.run(['curl','--noproxy','','--socks5-hostname','127.0.0.1:'+str(port),'-sS','--max-time','12','http://11.77.0.2:8080/'],capture_output=True)
   good=reply.returncode==0 and reply.stdout==b'VPNBOT-PROTOCOL-TARGET\n'
   check(label+'-'+kind+'-traffic',good==expected)
  finally:
   process.terminate()
   try:process.wait(5)
   except subprocess.TimeoutExpired:process.kill();process.wait()
# Драйвер проверяет, что Telegram направлен только в синтетическую заглушку.
run('docker','cp',str(ROOT/'backup-new-state-native.php'),'php-audit:/tmp/backup-new-state-native.php')
cron=run('docker','inspect','--format','{{.State.Running}}','service-audit').strip()=='true'
connected=False;saved=False
try:
 if cron:run('docker','stop','service-audit')
 bot('save-baseline');saved=True
 networks=json.loads(run('docker','inspect','--format','{{json .NetworkSettings.Networks}}','xray-audit'))
 if 'vpnbot-protocol-test' not in networks:
  run('docker','network','connect','--gw-priority','-1','vpnbot-protocol-test','xray-audit');connected=True
 bot('seed')
 ns['fetch']()
 for kind in ('xray','mihomo'):traffic(kind,'before')
 bot('mutate')
 for kind in ('xray','mihomo'):traffic(kind,'changed-identity-denied',False)
 # CLI-процесс, открывавший SQLite, завершён; cron на стенде остановлен.
 run('docker','exec','php-audit','sh','-c','rm -f /config/vpnbot.sqlite /config/vpnbot.sqlite-wal /config/vpnbot.sqlite-shm /config/hwid.json')
 bot('restore');bot('verify')
 check('nginx-valid',subprocess.run(['docker','exec','nginx-audit','nginx','-t'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0)
 for kind in ('xray','mihomo'):traffic(kind,'restored-old-profile')
 bot('restore');bot('verify')
 for kind in ('xray','mihomo'):traffic(kind,'repeat-restored-old-profile')
finally:
 try:
  if saved:bot('restore-baseline')
 finally:
  if connected:run('docker','network','disconnect','vpnbot-protocol-test','xray-audit')
  if cron:run('docker','start','service-audit')
