#!/usr/bin/env python3
"""DNS/Xdrive/TLS/routes: actual isolated components, synthetic data, explicit CI entry."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile

ROOT=Path('/opt/vpnbot-hosted-ci/stand')
FAMILIES={'xdrive':('run_baseline.py',{'XD-01','XD-02'}),'dns':('run_native.py',{'DNS-01','TLS-01','ROUTE-01'})}

def command(*args,timeout=45):
    return subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=timeout,check=True)

def cleanup_owned(work):
    for owner in work.glob('*/run-*/owner.json'):
        token=json.loads(owner.read_text()).get('token','')
        if not re.fullmatch(r'[a-f0-9]{8}',token):raise RuntimeError('invalid owned token')
        for kind in ('containers','networks'):
            args=['docker','ps','-a','--format','{{.Names}}'] if kind=='containers' else ['docker','network','ls','--format','{{.Name}}']
            names=command(*args,'--filter','label=vpnbot.audit.id='+token).stdout.splitlines()
            for name in names:
                if not re.fullmatch(r'vpnbot-ci-regression-(?:xd|dns)-'+token+r'-[a-z0-9-]+',name):
                    raise RuntimeError('resource outside fixture namespace')
                command(*(['docker','rm','-f',name] if kind=='containers' else ['docker','network','rm',name]))

def execute(args,work):
    process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        stdout,stderr=process.communicate(timeout=600)
        return subprocess.CompletedProcess(args,process.returncode,stdout,stderr)
    finally:
        if process.poll() is None:
            process.terminate()
            try:process.communicate(timeout=60)
            except subprocess.TimeoutExpired:process.kill();process.communicate()
        cleanup_owned(work)

def interrupted(signum,frame):raise RuntimeError('fixture interrupted')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--component-source',type=Path)
    p.add_argument('--component-images',type=Path)
    p.add_argument('--output',type=Path)
    a=p.parse_args();os.umask(0o077)
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,interrupted)
    if bool(a.component_source)!=bool(a.component_images):p.error('component source and image manifest must be supplied together')
    if a.component_source:
        source=a.component_source.resolve();images=json.loads(a.component_images.read_text())
        if not a.output:p.error('component output required')
    else:
        source=ROOT/'bot';images={}
        for service,container in [('php','php-audit'),('ad','adguard-audit'),('ng','nginx-audit')]:
            metadata=json.loads(command('docker','inspect','--format','{{json .Mounts}}',container).stdout)
            label=command('docker','inspect','--format','{{index .Config.Labels "com.docker.compose.service"}}',container).stdout.strip()
            if label!=service or not any(str(m.get('Source','')).startswith(str(source)+'/') for m in metadata):
                raise RuntimeError('container outside the owned CI stand')
            images[service]=command('docker','inspect','--format','{{.Image}}',container).stdout.strip()
    if set(images)!={'php','ad','ng'} or any(not re.fullmatch(r'sha256:[0-9a-f]{64}',v) for v in images.values()):
        raise RuntimeError('invalid component image identity')
    out=(a.output or ROOT/'results/protocol-regressions').resolve();out.mkdir(parents=True,exist_ok=True)
    result=[]
    with tempfile.TemporaryDirectory(prefix='components-',dir=out) as directory:
        work=Path(directory);snapshot=work/'source';(snapshot/'app').mkdir(parents=True);(snapshot/'scripts').mkdir()
        # Only static source files enter the stand. Never copy config.php, .env,
        # credentials, keys, subscriptions, databases or runtime state.
        files=['app/bot.php','app/i18n.php','app/timezone.php','app/exit_ruleset.py','app/adguard_control.sh',
               'scripts/acme_window.py','scripts/service_daemon.sh','scripts/service_supervisor.sh']
        files += ['app/'+x.name for x in (source/'app').glob('*.php') if re.fullmatch(r'[A-Z][A-Za-z0-9_]*\.php',x.name)]
        manifest={}
        for name in sorted(set(files)):
            target=source/name
            if target.is_symlink() or not target.is_file():raise RuntimeError('static source missing or symlinked')
            content=target.read_bytes();(snapshot/name).write_bytes(content);manifest[name]=hashlib.sha256(content).hexdigest()
        (out/'source-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        (work/'fixture-owner').write_text('vpnbot-protocol-regressions\n')
        (work/'images.json').write_text(json.dumps(images))
        for family,(script,expected) in FAMILIES.items():
            root=work/family;root.mkdir()
            args=[sys.executable,str(Path(__file__).with_suffix('')/family/script),'--source',str(snapshot),'--root',str(root),'--host-tag','ci']
            args += ['--image',images['php']] if family=='xdrive' else ['--images',str(work/'images.json')]
            run=execute(args,work)
            (out/(family+'.log')).write_text(run.stdout+run.stderr)
            evidence=list(root.glob('run-*/results.json'))
            if len(evidence)!=1:raise RuntimeError('component report missing')
            data=json.loads(evidence[0].read_text());(out/(family+'.json')).write_text(json.dumps(data,indent=2)+'\n')
            complete=set(data.get('cases',{}))==expected and data.get('cleanup',{}).get('passed') is True and not data.get('infrastructure_errors')
            for case in sorted(expected):
                passed=complete and run.returncode==0 and data['cases'][case]['verdict']=='PASS'
                result.append({'name':case,'passed':passed});print(('PASS ' if passed else 'FAIL ')+case,flush=True)
    (out/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'passed':sum(r['passed'] for r in result),'total':len(result)}))
    return 0 if len(result)==5 and all(r['passed'] for r in result) else 1

if __name__=='__main__':raise SystemExit(main())
