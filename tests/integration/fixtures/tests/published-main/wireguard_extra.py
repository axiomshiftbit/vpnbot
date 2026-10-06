#!/usr/bin/env python3
import json, os, pathlib, re, subprocess, sys, time
ROOT=pathlib.Path('/opt/vpnbot-hosted-ci/stand')
OUT=ROOT/'results/wireguard-extra'; OUT.mkdir(exist_ok=True,mode=0o700)
os.umask(0o077)
CLIENT='vpnbot-audit-wgclient'
results=[]
def run(*args,timeout=90): return subprocess.run(args,capture_output=True,text=True,timeout=timeout)
def check(name,value,expected=True):
    ok=value==expected;results.append(dict(name=name,passed=ok,actual=value,expected=expected))
    (OUT/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if ok else 'FAIL ')+name,flush=True)
def bot(*args):
    r=run('docker','exec','php-audit','php','/tmp/audit-driver.php',*map(str,args))
    if r.returncode: raise RuntimeError('Bot command failed')
    return json.loads(r.stdout)
def down():
    run('docker','exec',CLIENT,'sh','-c','awg-quick down /etc/wireguard/audit.conf >/dev/null 2>&1; wg-quick down audit >/dev/null 2>&1; true')
def curl(url,timeout=15):
    return run('docker','exec',CLIENT,'curl','-4','--interface','audit','-sS','--noproxy','*','--max-time',str(timeout),url,timeout=timeout+10)
def up(kind,name):
    run('docker','exec',CLIENT,'ip','route','replace','default','via','10.10.0.1','dev','eth0').check_returncode()
    r=run('docker','exec',CLIENT,kind+'-quick','up','/etc/wireguard/audit.conf')
    (OUT/(name+'-up.log')).write_text(r.stdout+r.stderr)
    if r.returncode==0:
        run('docker','exec',CLIENT,'ip','route','replace','default','dev','audit').check_returncode()
    return r.returncode==0


def prepare(inst,name):
    down(); info=bot('wg-export',inst)
    c=(ROOT/f'bot/logs/audit-wg{inst}.conf').read_text()
    c=re.sub(r'^Endpoint\s*=.*$',f'Endpoint = 10.10.0.{4 if inst==0 else 14}:51820',c,flags=re.M)
    c=re.sub(r'^DNS\s*=.*\n','',c,flags=re.M).replace('[Interface]','[Interface]\nTable = off',1)
    f=OUT/(name+'.conf');f.write_text(c)
    run('docker','cp',str(f),CLIENT+':/etc/wireguard/audit.conf').check_returncode()
    return f

def traffic(name, expected=True):
    r=curl('https://example.com/',8); check(name,r.returncode==0 and 'Example Domain' in r.stdout,expected)

try:
    for inst in (0,1):
        prefix=f'awg{inst}'
        bot('wg-mode',inst,3)
        prepare(inst,prefix+'-before'); check(prefix+'-up',up('awg',prefix));traffic(prefix+'-before-rotation')
        r=bot('wg-flags',inst);check(prefix+'-flags-no-warnings',not r['warnings'])
        prepare(inst,prefix+'-flags');check(prefix+'-flags-up',up('awg',prefix+'-flags'));traffic(prefix+'-flags-traffic')
        old=(OUT/(prefix+'-flags.conf')).read_text()
        r=bot('wg-rotate',inst);check(prefix+'-rotation-no-warnings',not r['warnings']);traffic(prefix+'-old-session-revoked',False)
        down();check(prefix+'-old-config-starts',up('awg',prefix+'-old'));traffic(prefix+'-old-key-denied',False)
        prepare(inst,prefix+'-new');check(prefix+'-new-config-up',up('awg',prefix+'-new'));traffic(prefix+'-new-key-traffic')
        check(prefix+'-client-key-changed',re.search(r'^PrivateKey.*$',old,re.M).group()!=re.search(r'^PrivateKey.*$',(OUT/(prefix+'-new.conf')).read_text(),re.M).group())
        for ip,url in [('10.10.0.5','http://10.10.0.5:80/'),('169.254.169.254','http://169.254.169.254/')]:
            r=curl(url,3);check(prefix+'-private-'+ip,r.returncode!=0 and not r.stdout)
        run('docker','restart','wireguard-audit' if inst==0 else 'wireguard1-audit',timeout=60).check_returncode();time.sleep(3)
        down();check(prefix+'-restart-up',up('awg',prefix+'-restart'));traffic(prefix+'-restart-traffic')
        bot('wg-flags',inst)
finally:
    down();run('docker','exec',CLIENT,'ip','route','replace','default','via','10.10.0.1','dev','eth0')
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}))
raise SystemExit(0 if all(x['passed'] for x in results) else 1)
