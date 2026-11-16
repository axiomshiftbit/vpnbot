from pathlib import Path
import hashlib, json, os, re, subprocess, time, sys
R=Path('/opt/vpnbot-hosted-ci/tests')
B=Path('/opt/vpnbot-hosted-ci/stand/bot')
SERVICES=['oc','ovpn','tt','hy','ss','dnstt','telemt','ipsec','anytls','mieru','tuic','shadowtls','masque','snolc']
MANAGED=SERVICES[8:]
rows=[]
def run(*args,timeout=75):
    return subprocess.run(args,capture_output=True,text=True,timeout=timeout)
def check(name,ok,**extra):
    rows.append({'name':name,'ok':bool(ok),**extra})
    (R/'module-cycle-results.json').write_text(json.dumps(rows,indent=2,ensure_ascii=False))
    print(('PASS ' if ok else 'FAIL ')+name,flush=True)
    if not ok:raise RuntimeError(name)
def call(action,service):
    p=run('docker','exec','php-audit','php','-d','error_reporting=32767','/tmp/module-cycle.php',action,service)
    if p.returncode:raise RuntimeError('PHP fixture exit '+str(p.returncode))
    v=json.loads(p.stdout)
    check(service+'-'+action+'-no-errors',not v['errors'] and not v['warnings'],errors=v['errors'],warnings=v['warnings'])
    return v
def identity(service):
    return run('docker','ps','-aq','--filter','label=com.docker.compose.project=vpnbot-audit',
               '--filter','label=com.docker.compose.service='+service).stdout.strip()
def ready(service):
    i=identity(service)
    if not i:return False
    p=run('docker','inspect','--format','{{.State.Running}}',i)
    if p.stdout.strip()!='true':return False
    if service in MANAGED:
        f=B/'config/protocols'/service/'runtime/status.json'
        if not f.exists():return False
        s=json.loads(f.read_text())
        desired=json.loads((B/'config/protocols'/service/'desired.json').read_text())
        return s.get('running') and not s.get('error') and s.get('revision')==desired.get('revision') and time.time()-s.get('time',0)<30
    # Имя TrustTunnel длиннее 15 символов, и точное совпадение зависит от
    # реализации pgrep: procps сравнивает с обрезанным именем, busybox (Alpine) —
    # с полным. Ищем так же, как бот: по командной строке.
    if service=='tt':return run('docker','exec',i,'pgrep','-f','[t]rusttunnel_endpoint').returncode==0
    # ssserver запускает supervisor по полному пути: BusyBox pgrep -x сравнивает
    # argv[0] (/usr/bin/ssserver) целиком. Бот проверяет так же, без -x.
    if service=='ss':return run('docker','exec',i,'pgrep','ssserver').returncode==0
    pattern={'oc':'ocserv','ovpn':'openvpn','hy':'hysteria','ss':'ssserver','dnstt':'dnstt-server','telemt':'telemt','ipsec':'charon'}[service]
    return run('docker','exec',i,'pgrep','-x',pattern).returncode==0
def wait(predicate,seconds=70):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        if predicate():return True
        time.sleep(.5)
    return False
def applied(service,expected):
    f=B/'config/protocol-services.status.json'
    if not f.exists():return False
    s=json.loads(f.read_text())
    return s.get('settings',{}).get(service) is expected and service not in s.get('errors',{})
def fingerprints():
    selected=[]
    for folder in ['ssh','certs','config/openvpn/pki','config/ipsec/pki']:
        d=B/folder
        if d.exists():selected += [p for p in d.rglob('*') if p.is_file() and (p.suffix in ['.key','.crt','.pem'] or p.name in ['key','key.pub','self_public','self_private','cert_public','cert_private'])]
    selected += [p for p in [B/'config/clients.json',B/'config/clients1.json',B/'config/ocpasswd'] if p.is_file()]
    out={str(p.relative_to(B)):hashlib.sha256(p.read_bytes()).hexdigest() for p in selected}
    # OpenVPN штатно обновляет даты CRL при старте. Проверяем подпись и
    # сохранение отозванных серийных номеров, а не меняющийся DER-снимок.
    crl=B/'config/openvpn/pki/crl.pem'
    if crl.exists():
        p=run('openssl','crl','-in',str(crl),'-noout','-text','-verify','-CAfile',str(crl.parent/'ca.crt'))
        if p.returncode:raise RuntimeError('CRL signature invalid')
        revoked=sorted(re.findall(r'Serial Number:\s*([0-9a-fA-F]+)',p.stdout))
        out[str(crl.relative_to(B))]=hashlib.sha256(json.dumps(revoked).encode()).hexdigest()
    c=json.loads((B/'config/pac.json').read_text())
    out['telemt_settings']=hashlib.sha256(json.dumps({k:v for k,v in c.items() if k.startswith('telemt_')},sort_keys=True).encode()).hexdigest()
    for service in MANAGED:
        f=B/'config/protocols'/service/'desired.json'
        if f.exists():
            s=json.loads(f.read_text())
            out[service+'_credentials']=hashlib.sha256(json.dumps({'users':s['users'],'settings':s['settings']},sort_keys=True).encode()).hexdigest()
    return out
def healthy_frontend():
    return run('docker','exec','nginx-audit','nginx','-t').returncode==0 and run('docker','exec','php-audit','curl','-fsS','--max-time','3','--unix-socket','/var/run/control.unit.sock','http://localhost/status').returncode==0
for service in MANAGED:call('setup',service)
for service in ['ipsec','ikev2','l2tp',*SERVICES]:
    if not call('state',service)['requested']:call('toggle',service)
for service in SERVICES:check(service+'-initial-ready',wait(lambda:ready(service)))
baseline=fingerprints()
for cycle in range(2):
    for service in SERVICES:
        label=service+'-cycle'+str(cycle+1)
        old=identity(service)
        state=call('toggle',service);check(label+'-request-off',not state['requested'])
        # Выключатель управляемого протокола меняет оба состояния: модуль и сам протокол.
        if service in MANAGED:check(label+'-protocol-flag-off',state['protocol_enabled'] is False)
        check(label+'-container-removed',wait(lambda:not identity(service) and applied(service,False)))
        time.sleep(1.2)
        check(label+'-stays-disabled',not identity(service))
        check(label+'-frontend-survives',healthy_frontend())
        state=call('toggle',service);check(label+'-request-on',state['requested'])
        if service in MANAGED:check(label+'-protocol-flag-on',state['protocol_enabled'] is True)
        check(label+'-core-ready',wait(lambda:ready(service) and applied(service,True)))
        check(label+'-new-container',identity(service)!=old)
        after=fingerprints()
        check(label+'-credentials-settings-preserved',after==baseline,
              changed=[k for k in baseline if baseline[k]!=after.get(k)])
# IKEv2 and L2TP share IPsec. Each must survive the other's disable;
# with both off the container must disappear and return on enabling either.
for child in ['ikev2','l2tp']:
    call('toggle',child)
    check(child+'-single-off-keeps-ipsec',wait(lambda:applied(child,False) and ready('ipsec')))
    call('toggle',child)
    check(child+'-single-on-ready',wait(lambda:applied(child,True) and ready('ipsec')))
call('toggle','ikev2');call('toggle','l2tp')
check('ipsec-both-children-off-removed',wait(lambda:not identity('ipsec') and applied('ikev2',False) and applied('l2tp',False)))
call('toggle','ikev2')
check('ipsec-ikev2-alone-starts',wait(lambda:ready('ipsec') and applied('ikev2',True)))
call('toggle','l2tp')
check('ipsec-both-children-restored',wait(lambda:ready('ipsec') and applied('l2tp',True)))
check('final-credentials-preserved',fingerprints()==baseline)
print('MODULE CYCLES COMPLETE '+str(len(rows)),flush=True)
