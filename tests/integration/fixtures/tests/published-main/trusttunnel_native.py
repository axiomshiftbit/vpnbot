#!/usr/bin/env python3
import json,os,pathlib,re,subprocess,time,tomllib
C='vpnbot-audit-ssclient'
PROBE_PORT=15400
os.umask(0o077);R=pathlib.Path('/opt/vpnbot-hosted-ci/stand');O=R/'results/tt-native';O.mkdir(mode=0o700,exist_ok=True);results=[]
def run(*a,timeout=45):return subprocess.run(list(map(str,a)),capture_output=True,text=True,timeout=timeout)
def check(n,v):results.append({'name':n,'passed':v});(O/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if v else 'FAIL ')+n,flush=True)
def bot(a):
 r=run('docker','exec','php-audit','php','/tmp/audit-driver.php',a,timeout=120);r.check_returncode();j=json.loads(r.stdout);check(a+'-warnings',not j['warnings'])
def export():
 bot('tt-export');a=tomllib.loads((R/'bot/logs/audit-files/trusttunnel-audittt.toml').read_text());a['addresses']=['10.10.0.10:2443'];a['certificate']=(R/'bot/certs/cert_public').read_text()
 (O/'endpoint.toml').write_text('\n'.join(k+' = '+json.dumps(v) for k,v in a.items()))
 r=run(R/'bin/setup_wizard','--mode','non-interactive','--endpoint_config',O/'endpoint.toml','--settings',O/'settings.toml');(O/'wizard.log').write_text(r.stdout+r.stderr);check('official-wizard-accepts-export',r.returncode==0);r.check_returncode();return (O/'settings.toml').read_text()
def settings(s,proto):
 # Replace generated TUN listener with SOCKS so host routes stay untouched.
 s=re.sub(r'(?ms)^\[listener\.tun\].*?(?=^\[|\Z)','',s);s+='\n[listener.socks]\naddress = "127.0.0.1:'+str(PROBE_PORT)+'"\n';s=re.sub(r'(?m)^upstream_protocol\s*=.*$', 'upstream_protocol = "'+proto+'"',s);(O/'client.toml').write_text(s)
def cleanup_client():
 r=run('docker','exec',C,'ps','-eo','pid,comm');r.check_returncode()
 for line in r.stdout.splitlines()[1:]:
  parts=line.split()
  if len(parts)==2 and parts[0].isdigit() and parts[1]=='trusttunnel':
   run('docker','exec',C,'kill','-KILL',parts[0]).check_returncode()
 defunct=run('docker','exec',C,'ps','-eo','pid,comm')
 return defunct

def unused_port():
 pid=run('docker','inspect','--format','{{.State.Pid}}',C).stdout.strip()
 code='import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
 p=run('nsenter','-t',pid,'-n','python3','-c',code);p.check_returncode();return int(p.stdout)

def start(s,proto):
 global PROBE_PORT
 PROBE_PORT=unused_port()
 cleanup_client()
 settings(s,proto);run('docker','cp',O/'client.toml',C+':/tmp/tt-client.toml').check_returncode();f=(O/(proto+'.log')).open('w');p=subprocess.Popen(['docker','exec',C,'/tmp/trusttunnel','-c','/tmp/tt-client.toml','-l','warn'],stdout=f,stderr=f);time.sleep(2);return p,f
def stop(p,f):
 cleanup_client()
 p.terminate()
 try:p.wait(timeout=8)
 except subprocess.TimeoutExpired:p.kill();p.wait()
 f.close()
def http():
 r=run('docker','exec',C,'curl','--retry','3','--retry-all-errors','--retry-delay','1','--socks5-hostname','127.0.0.1:'+str(PROBE_PORT),'--noproxy','','-fsS','--max-time','12','https://example.com/',timeout=60);(O/('curl-'+str(len(results))+'.log')).write_text(r.stdout+r.stderr);return r
def proof(action):
 for attempt in range(20):
  r=run('docker','exec','php-audit','php','/tmp/tt-metrics-proof.php',action);r.check_returncode();v=json.loads(r.stdout)
  if action!='stats' or v['result'] is not None:break
  time.sleep(.25)
 check('metrics-'+action+'-no-PHP-warnings',v['warning_count']==0);return v['result']
run('docker','cp','/opt/vpnbot-hosted-ci/suite/tt_metrics.php','php-audit:/tmp/tt-metrics-proof.php').check_returncode()
check('metrics-migrate-and-start',proof('restart') is True)
check('metrics-API-configured-user',isinstance(proof('stats').get('audittt'),dict))
info=json.loads(run('docker','inspect','trusttunnel-audit').stdout)[0]
address=info['NetworkSettings']['Networks']['vpnbot-audit_default']['IPAddress']
code='import socket,sys;s=socket.socket();s.settimeout(1);sys.exit(0 if s.connect_ex((sys.argv[1],1987))!=0 else 1)'
check('metrics-unreachable-from-other-container',run('docker','exec','php-audit','python3','-c',code,address).returncode==0)
check('metrics-port-not-published','1987/tcp' not in info['HostConfig']['PortBindings'])
s=export()
for proto in ['http2','http3']:
 p,f=start(s,proto)
 try:
  r=http();check(proto+'-https',r.returncode==0 and 'Example Domain' in r.stdout)
  st=proof('stats')['audittt'];check(proto+'-live-session-and-traffic',st['sessions']>0 and st['upload']>0 and st['download']>0)
  check(proto+'-real-user-card',all(proof('menu').values()))
 finally:stop(p,f)
check('metrics-help-route',all(proof('help').values()))
check('metrics-restart-success',proof('restart') is True)
st=proof('stats')['audittt'];check('metrics-reset-on-restart',st['sessions']==0 and st['upload']==0 and st['download']==0)
p,f=start(s,'http2')
try:
 bot('tt-rotate');r=http();check('old-password-rejected',r.returncode!=0)
finally:stop(p,f)
s=export();p,f=start(s,'http2')
try:
 r=http();check('new-password-works',r.returncode==0 and 'Example Domain' in r.stdout)
 bot('tt-delete');r=http();check('deleted-user-rejected',r.returncode!=0)
finally:stop(p,f);bot('tt-init')
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}))
raise SystemExit(0 if all(x['passed'] for x in results) else 1)
