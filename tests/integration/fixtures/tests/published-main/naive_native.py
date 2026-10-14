#!/usr/bin/env python3
import json,os,pathlib,subprocess,time,urllib.parse
ROOT=pathlib.Path('/opt/vpnbot-hosted-ci/stand');OUT=ROOT/'results/naive-native';OUT.mkdir(mode=0o700,exist_ok=True);os.umask(0o077);results=[]
def run(*a,timeout=90): return subprocess.run(a,capture_output=True,text=True,timeout=timeout)
def bot(a):
 r=run('docker','exec','php-audit','php','/tmp/audit-driver.php',a);r.check_returncode();return json.loads(r.stdout)
def check(n,v):
 results.append({'name':n,'passed':bool(v)});(OUT/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if v else 'FAIL ')+n,flush=True)
def creds():
 bot('naive-export');return json.loads((ROOT/'bot/logs/audit-naive.json').read_text())
def test(a,label,expect=True):
 c={'listen':'socks://127.0.0.1:19899','proxy':'https://'+urllib.parse.quote(a['user'],safe='')+':'+urllib.parse.quote(a['password'],safe='')+'@'+a['host']+':443','host-resolver-rules':'MAP '+a['host']+' 10.10.0.10'}
 f=OUT/(label+'.json');f.write_text(json.dumps(c));env=dict(os.environ,SSL_CERT_FILE=str(ROOT/'bot/certs/cert_public'))
 with (OUT/(label+'.log')).open('w') as log:
  p=subprocess.Popen([str(ROOT/'bin/naive'),str(f)],stdout=log,stderr=log,env=env)
  try:
   time.sleep(.7)
   for scheme in ('http','https'):
    r=run('curl','--noproxy','','--socks5-hostname','127.0.0.1:19899','-sS','--max-time','12',scheme+'://example.com/')
    check(label+'-'+scheme,(r.returncode==0 and 'Example Domain' in r.stdout)==expect)
   if expect:
    for name,url in [('docker','http://10.10.0.8:2375/version'),('panel','http://10.10.0.7:8090/'),('adguard','http://10.10.0.5:80/')]:
     r=run('curl','--noproxy','','--socks5-hostname','127.0.0.1:19899','-sS','--max-time','3',url);check(label+'-'+name+'-isolated',r.returncode!=0 and not r.stdout)
  finally:p.terminate();p.wait(timeout=5)
a=creds();test(a,'official-native');bot('naive-rotate');test(a,'old-password',False);test(creds(),'rotated-password')
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}))
raise SystemExit(0 if all(x['passed'] for x in results) else 1)
