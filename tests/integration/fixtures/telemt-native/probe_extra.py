from pathlib import Path
import os,sys,json,socket,subprocess,importlib.util
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE/'support'))
import probe_limits as p
p.ROOT=HERE/'extra';p.ROOT.mkdir(exist_ok=True);p.BINARY=Path(os.environ['TELEMT_BINARY'])
spec=importlib.util.spec_from_file_location('state',Path(os.environ['SOURCE_DIR'])/'scripts/telemt_state.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
checks=[]
def check(name,ok):
 checks.append({'name':name,'ok':bool(ok)});(HERE/'extra-results.json').write_text(json.dumps(checks,indent=2));print(name,'OK' if ok else 'FAIL',flush=True)
 if not ok:raise AssertionError(name)
c=p.Core('ipv6-and-disk',limit=1,quota=10000)
c.config=c.config.replace('ipv6 = false','ipv6 = true').replace('[network]',f'[[server.listeners]]\nip = "::1"\nport = {c.n}\n[network]')
s=m.TelemtState(c.root,'http://127.0.0.1:'+str(c.a))
c.config=c.config.replace(str(c.root/'quota.json'),str(s.path));(c.root/'telemt.toml').write_text(c.config)
s.write({'last_reset_epoch_secs':0,'users':{name:{'used_bytes':0,'last_reset_epoch_secs':0} for name in ('alice','bob')}})
def ipv6():
 n=object.__new__(p.Native);n.s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);n.s.settimeout(2);n.s.bind(('::1',0));n.s.connect(('::1',c.n));hello,n.enc,n.dec=p.client_crypto();n.s.sendall(hello);c.children.append(n);return n
try:
 c.start();n=c.native();check('ipv4_connects',n.echo()==b'test-data'*8)
 n6=ipv6();check('ipv6_is_separate_ip_slot',n6.echo()==b'');n6.close();n.close();p.wait(lambda:c.user()['active_unique_ips']==0)
 n6=ipv6();check('ipv6_connects_after_slot_freed',n6.echo()==b'test-data'*8)
 w=c.web('::1');check('native_and_web_share_ipv6_slot',w.echo()==b'test-data'*8)
 w2=c.web('0:0:0:0:0:0:0:1');check('ipv6_text_forms_canonicalized',w2.echo()==b'test-data'*8)
 check('ipv6_unique_count_correct',c.user()['active_unique_ips']==1)
 check('quota_accounts_ipv4_ipv6_native_web',c.used()==576)
 check('ipv4_rejected_while_ipv6_occupies_slot',c.native().echo()==b'')
 s.checkpoint();before=s.read();n6.echo();used=c.used();subprocess.run(['chattr','+i',str(s.path.parent)],check=True)
 try:s.checkpoint();failed=False
 except OSError:failed=True
 check('write_failure_detected',failed)
 check('write_failure_preserves_previous_snapshot',s.read()==before)
 for child in c.children:child.close()
 c.children=[]
 try:s.stop();failed=False
 except ValueError:failed=True
 check('graceful_save_failure_not_reported_as_success',failed)
 check('failed_stop_does_not_truncate_state',s.read()==before)
finally:
 subprocess.run(['chattr','-i',str(s.path.parent)],check=True);c.close()
print('TOTAL',len(checks))
