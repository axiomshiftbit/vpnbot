#!/usr/bin/env python3
import json, os, pathlib, re, subprocess, sys, time
ROOT=pathlib.Path('/opt/vpnbot-hosted-ci/stand')
OUT=ROOT/'results/wireguard'; OUT.mkdir(exist_ok=True,mode=0o700)
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

cases=[(i,m) for i in (0,1) for m in (0,1,2,3)]
if len(sys.argv)>1: cases=[tuple(map(int,a.split(':'))) for a in sys.argv[1:]]
try:
    for inst,mode in cases:
        name=f'wg{inst}-'+('wireguard' if mode==0 else 'amnezia'+str(mode))
        down()
        info=bot('wg-mode',inst,mode);check(name+'-bot-mode-warnings',len(info['warnings']),0)
        info=bot('wg-export',inst);check(name+'-bot-export-warnings',len(info['warnings']),0)
        kind=info['result']['type']
        c=(ROOT/f'bot/logs/audit-wg{inst}.conf').read_text()
        (OUT/(name+'-generated.conf')).write_text(c)
        # Тестовый клиент в отдельном netns, вход через настоящий UDP socket.
        # Меняем только endpoint на адрес серверного контейнера.
        c=re.sub(r'^Endpoint\s*=.*$',f'Endpoint = 10.10.0.{4 if inst==0 else 14}:51820',c,flags=re.M)
        # Docker монтирует resolv.conf, openresolv в этом тестовом клиенте не
        # управляет им. DNS назначаем вручную; original export сохранён выше.
        c=re.sub(r'^DNS\s*=.*\n','',c,flags=re.M)
        # awg-quick безусловно пишет sysctl, а /proc/sys в Docker read-only.
        # Sysctl уже задан при создании netns; маршрут ставим явно после up.
        c=c.replace('[Interface]','[Interface]\nTable = off',1)
        run('docker','exec',CLIENT,'sh','-c',"printf 'nameserver 1.1.1.1\\n' > /etc/resolv.conf").check_returncode()
        f=OUT/(name+'.conf');f.write_text(c)
        run('docker','cp',str(f),CLIENT+':/etc/wireguard/audit.conf').check_returncode()
        started=up(kind,name);check(name+'-up',started)
        if not started: continue
        for scheme in ('http','https'):
            r=curl(scheme+'://example.com/');check(name+'-'+scheme,r.returncode==0 and 'Example Domain' in r.stdout)
            if r.returncode: (OUT/(name+'-'+scheme+'.log')).write_text(r.stderr)
        hs=run('docker','exec',CLIENT,kind,'show','audit','latest-handshakes')
        check(name+'-handshake',any(int(line.split()[-1])>0 for line in hs.stdout.splitlines() if line.strip()))
        # Bind к audit заставляет идти к Docker API именно через VPN.
        r=curl('http://10.10.0.8:2375/version',4);check(name+'-docker-api-blocked',r.returncode!=0)
        r=curl('http://10.10.0.7:8090/',4);check(name+'-panel-blocked',r.returncode!=0)
        r=curl('http://10.10.0.5:80/',4);check(name+'-adguard-admin-blocked',r.returncode!=0)
        info=bot('wg-toggle',inst);check(name+'-disabled',info['result']['disabled'])
        r=curl('https://example.com/',4);check(name+'-disabled-traffic-blocked',r.returncode!=0)
        info=bot('wg-toggle',inst);check(name+'-enabled',info['result']['disabled'],False)
        down();check(name+'-reconnect-up',up(kind,name+'-reconnect'))
        r=curl('https://example.com/');check(name+'-reconnected',r.returncode==0 and 'Example Domain' in r.stdout)
finally:
    down()
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}))
raise SystemExit(0 if all(x['passed'] for x in results) else 1)
