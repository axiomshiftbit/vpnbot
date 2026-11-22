#!/usr/bin/env python3
"""Full synthetic CI stand: reuse old WG/OC/IKE profiles across full restore.

Run after native-before-restore (it prepares the IKE client). This entry never
recreates a client credential after backup, and never exports raw data/logs.
"""
import argparse,hashlib,json,os,pathlib,re,shlex,subprocess,tempfile,time

def main():
 p=argparse.ArgumentParser();p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args();os.umask(0o077);a.out.mkdir(parents=True,exist_ok=True)
 rows=[];saved=False;paused=False;fault=False;failure=None;meta={};wg_types=[];guarded=False
 def run(cmd,timeout=90,input=None):return subprocess.run(cmd,capture_output=True,timeout=timeout,input=input)
 def exe(container,*cmd,timeout=90,input=None):return run(['docker','exec',*(['-i']if input is not None else[]),container,*cmd],timeout,input)
 def check(ok,name):
  rows.append({'name':name,'passed':bool(ok)})
  if not ok:raise RuntimeError(name)
 def bot(action):
  r=exe('php-audit','php','/tmp/backup-protocols-stand-driver.php',action,timeout=900)
  try:d=json.loads(r.stdout)
  except ValueError:d={}
  check(r.returncode==0 and d.get('ok'),'bot-'+action)
  for key,val in d.get('checks',{}).items():check(val,action+'-'+key)
 def wg_down():
  for kind in ['wg','awg']:exe('vpnbot-audit-wgclient',kind+'-quick','down','/etc/wireguard/backup-audit.conf')
 def oc_stop():exe('vpnbot-audit-ovpnclient','pkill','openconnect');time.sleep(.2)
 def ike_stop():exe('vpnbot-audit-ipsecclient','swanctl','--terminate','--ike','auditike','--timeout','5',timeout=12)
 def ike_restart():
  c='vpnbot-audit-ipsecclient';exe(c,'pkill','charon');time.sleep(.2);exe(c,'rm','-f','/var/run/charon.vici','/var/run/charon.pid')
  check(run(['docker','exec','-d',c,'sh','-c','/usr/lib/strongswan/charon >/tmp/backup-native-charon.log 2>&1']).returncode==0,'ike-client-start')
  for _ in range(60):
   if exe(c,'swanctl','--stats').returncode==0:break
   time.sleep(.1)
  check(exe(c,'swanctl','--load-all').returncode==0,'ike-old-client-config-load')
 def payload(c,interface,expected,label,*,new_oc_session=False):
  # On a newly authenticated OpenConnect tunnel the first TLS handshake can
  # be interrupted. Only that transient result gets a bounded readiness check.
  attempts=3 if new_oc_session else 1
  for attempt in range(attempts):
   r=exe(c,'curl','-4','--noproxy','*','--interface',interface,'-sS','--max-time','8','https://example.com/',timeout=15)
   if r.returncode!=35 or attempt+1==attempts:break
   time.sleep(0.5*(attempt+1))
  check((r.returncode==0 and b'Example Domain'in r.stdout)==expected,label)
 def probe(label,expected,profiles):
  for instance,profile in enumerate(profiles):
   c='vpnbot-audit-wgclient';kind=wg_types[instance];wg_down()
   exe(c,'ip','route','replace','default','via','10.10.0.1','dev','eth0')
   check(run(['docker','cp',str(profile),c+':/etc/wireguard/backup-audit.conf']).returncode==0,label+'-old-wg-profile-'+str(instance))
   check(exe(c,kind+'-quick','up','/etc/wireguard/backup-audit.conf').returncode==0,label+'-wg-interface-'+str(instance))
   exe(c,'ip','route','replace','default','dev','backup-audit');payload(c,'backup-audit',expected,label+'-wg-'+str(instance)+'-payload');wg_down()
  c='vpnbot-audit-ovpnclient';oc_stop()
  cmd=['openconnect','https://'+meta['oc_host'],'--resolve='+meta['oc_host']+':10.10.0.10','--user=auditoc','--passwd-on-stdin','--non-inter','--cafile=/tmp/audit-oc-ca.crt','--background','--pid-file=/tmp/backup-native-oc.pid','--interface=backupaudit','--script=/etc/vpnc/vpnc-script']
  r=exe(c,'sh','-c',shlex.join(cmd)+' >/tmp/backup-native-oc.log 2>&1',input=(meta['oc_password']+'\n').encode(),timeout=40)
  check((r.returncode==0)==expected,label+'-old-oc-auth')
  if expected:payload(c,'backupaudit',True,label+'-oc-payload',new_oc_session=True)
  oc_stop();ike_stop();ike_restart();c='vpnbot-audit-ipsecclient'
  r=exe(c,'swanctl','--initiate','--child','audit-tunnel','--timeout','15',timeout=22);check((r.returncode==0)==expected,label+'-old-ike-auth')
  if expected:
   r=exe('php-audit','php','/tmp/audit-driver.php','ike-status');d=json.loads(r.stdout)['result'];check(bool(d.get('online')),'ike-live-session');payload(c,d['virtual'],True,label+'-ike-payload')
  ike_stop()
 def set_fault(enable):
  if enable:
   script='''set -eu
b=$(command -v swanctl)
case "$b" in /usr/bin/swanctl|/usr/sbin/swanctl) ;; *) exit 1;; esac
test ! -e "$b.backup-native-real"
printf '%s\\n' "$b" >/tmp/backup-native-swanctl-path
printf '#!/bin/sh\\nif [ "${1:-}" = --load-all ]; then exit 42; fi\\nexec "%s.backup-native-real" "$@"\\n' "$b" >"$b.backup-native-wrapper"
chmod 755 "$b.backup-native-wrapper"
mv "$b" "$b.backup-native-real"
mv "$b.backup-native-wrapper" "$b"
'''
  else:
   script='''set -eu
test -f /tmp/backup-native-swanctl-path || exit 0
read -r b </tmp/backup-native-swanctl-path
case "$b" in /usr/bin/swanctl|/usr/sbin/swanctl) ;; *) exit 1;; esac
if [ -f "$b.backup-native-real" ]; then mv "$b.backup-native-real" "$b"; fi
rm -f "$b.backup-native-wrapper" /tmp/backup-native-swanctl-path
'''
  check(exe('ipsec-audit','sh','-c',script).returncode==0,'ipsec-fault-'+str(enable))
 try:
  for c in ['php-audit','service-audit','wireguard-audit','wireguard1-audit','ipsec-audit','openconnect-audit','vpnbot-audit-wgclient','vpnbot-audit-ovpnclient','vpnbot-audit-ipsecclient']:
   check(run(['docker','inspect','--format','{{.State.Running}}',c]).stdout.strip()==b'true','required-'+c)
  check(exe('php-audit','php','-r','exit(getenv("TELEGRAM_API")==="tg-audit:8443"?0:1);').returncode==0,'synthetic-telegram-only');guarded=True
  # l2tp.py runs after ikev2.py and replaces the client's swanctl.conf with its
  # IKEv1 profile. Reuse the exact IKEv2 profile ikev2.py generated before the
  # backup; no client credential is created here.
  old_ike=pathlib.Path('/opt/vpnbot-hosted-ci/stand/results/ikev2/swanctl.conf')
  check(old_ike.is_file() and run(['docker','cp',str(old_ike),'vpnbot-audit-ipsecclient:/etc/swanctl/swanctl.conf']).returncode==0,'old-ike-profile-prepared-by-native-before')
  check(run(['docker','cp',str(pathlib.Path(__file__).with_name('stand-driver.php')),'php-audit:/tmp/backup-protocols-stand-driver.php']).returncode==0,'driver-installed')
  check(run(['docker','stop','service-audit']).returncode==0,'cron-paused');paused=True
  bot('save');saved=True
  with tempfile.TemporaryDirectory(prefix='profiles-',dir=a.out.resolve())as tmp:
   tmp=pathlib.Path(tmp);check(run(['docker','cp','php-audit:/logs/audit-backup-protocols-native/client-meta.json',str(tmp/'meta.json')]).returncode==0,'old-credentials-captured')
   meta=json.loads((tmp/'meta.json').read_text());wg_types=meta['wg_types'];profiles=[]
   for instance in [0,1]:
    f=tmp/('wg'+str(instance)+'.conf');check(run(['docker','cp','php-audit:/logs/audit-backup-protocols-native/wg'+str(instance)+'.conf',str(f)]).returncode==0,'saved-client-'+str(instance))
    text=f.read_text();text=re.sub(r'^Endpoint\s*=.*$',f'Endpoint = 10.10.0.{4 if instance==0 else 14}:51820',text,flags=re.M);text=re.sub(r'^DNS\s*=.*\n','',text,flags=re.M);text=text.replace('[Interface]','[Interface]\nTable = off',1);f.write_text(text);profiles.append(f)
   hashes=[hashlib.sha256(f.read_bytes()).hexdigest()for f in profiles]
   def client_fingerprints():
    return [exe(c,'sha256sum',path).stdout for c,path in [('vpnbot-audit-ipsecclient','/etc/swanctl/swanctl.conf'),('vpnbot-audit-ipsecclient','/etc/swanctl/x509ca/audit-ca.crt'),('vpnbot-audit-ovpnclient','/tmp/audit-oc-ca.crt')]]
   credentials_before=client_fingerprints();check(all(credentials_before),'old-oc-ike-profile-files-present')
   probe('before',True,profiles);bot('clear-users');probe('empty-stores',False,profiles);bot('restore');probe('restored',True,profiles)
   fault=True;set_fault(True);bot('restore-failure')
   cli=exe('php-audit','sh','-c','php /app/restore.php </logs/audit-backup-protocols-native/full.json',timeout=900);check(cli.returncode!=0,'native-protocol-failure-cli-nonzero')
   set_fault(False);fault=False;bot('restore');probe('retry',True,profiles)
   check(hashes==[hashlib.sha256(f.read_bytes()).hexdigest()for f in profiles] and credentials_before==client_fingerprints(),'old-profiles-never-regenerated')
 except Exception as e:failure=type(e).__name__+':'+str(e)[:160]
 finally:
  if guarded:
   try:
    wg_down();oc_stop();ike_stop()
    if fault:set_fault(False)
    if saved:bot('restore')
    if saved:exe('php-audit','rm','-rf','/logs/audit-backup-protocols-native')
   except Exception as e:failure=failure or 'cleanup:'+type(e).__name__
   finally:
    if paused and run(['docker','start','service-audit']).returncode!=0:failure=failure or 'cron-resume-failed'
  report={'checks':rows,'error':failure,'bounds':'Actual full Bot importer and WG/OC/IKE runtime on synthetic full stand; client identities reused; empty user stores, not full OS reinstall'}
  (a.out/'results.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'passed':sum(r['passed']for r in rows),'total':len(rows),'error':failure}));return 1 if failure else 0
if __name__=='__main__':raise SystemExit(main())
