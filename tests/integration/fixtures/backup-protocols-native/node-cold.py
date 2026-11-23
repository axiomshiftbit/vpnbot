#!/usr/bin/env python3
"""Owned systemd/Docker node lab, exact candidate cores and actual cold restore.

No production config, host socket, host ports, fixed old lab or mutable PHP tag.
Only offline Docker image-name resolution is adapted to verified loaded IDs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import uuid


def parse_checks(stdout):
    checks=[]
    for line in stdout.decode(errors='replace').splitlines():
        if line.startswith(('PASS ', 'FAIL ')):
            checks.append({'name':line[5:], 'passed':line.startswith('PASS ')})
    required={'node-importer-connected_settled_node','node-importer-common_importer_restores_node_pac_and_files',
              'node-importer-restored_controller_pinned_rpc','node-importer-old_external_profile_payload_after',
              'node-importer-external_profile_not_regenerated','old host pin rejects the reinstalled node',
              'restored controller passes traffic after reinstall',
              'previously exported external peer profile works after reinstall and restore',
              'confirmed block rejects previously reachable destination', 'confirmed SSH lists select block, WARP and direct for TCP and UDP',
              'controller rejects explicit block of the probe domain', 'watchdog rolls back after real confirmation deadline',
              'original disposable node restored'}
    if not required.issubset({c['name'] for c in checks}) or len(checks)<30 or not all(c['passed'] for c in checks):
        raise RuntimeError('incomplete cold restore checks')
    return checks


def archive_ids(path, host_ids):
    """Nested image IDs for saved host images, checked against the archive content.

    A containerd image store names an image by its manifest digest, the classic
    store loaded inside the node host by its config digest. Both come from the
    same content-addressed manifest, verified here before it is trusted.
    """
    nested = {}
    with tarfile.open(path) as archive:
        for entry in json.load(archive.extractfile('index.json'))['manifests']:
            digest = entry['digest']
            blob = archive.extractfile('blobs/sha256/' + digest.split(':', 1)[1]).read()
            if 'sha256:' + hashlib.sha256(blob).hexdigest() != digest:
                raise RuntimeError('archive manifest digest mismatch')
            config = json.loads(blob).get('config', {}).get('digest', '')
            if not re.fullmatch(r'sha256:[a-f0-9]{64}', config):
                raise RuntimeError('single-platform image manifest required')
            for host_id in host_ids:
                if host_id in (digest, config):
                    nested[host_id] = config
        # Classic Docker 28 saving several untagged IDs lists one manifest in
        # index.json; manifest.json (what the classic nested daemon loads) names
        # every config. Its config blob is verified against its digest name.
        try:
            legacy = json.load(archive.extractfile('manifest.json'))
        except KeyError:
            legacy = []
        for entry in legacy:
            name = entry.get('Config', '') if isinstance(entry, dict) else ''
            if not re.fullmatch(r'blobs/sha256/[a-f0-9]{64}', name):
                raise RuntimeError('archive config reference invalid')
            config = 'sha256:' + name.rsplit('/', 1)[1]
            if 'sha256:' + hashlib.sha256(archive.extractfile(name).read()).hexdigest() != config:
                raise RuntimeError('archive config digest mismatch')
            if config in host_ids:
                nested[config] = config
    if set(nested) != set(host_ids):
        raise RuntimeError('saved archive does not contain every candidate image')
    return nested


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    for name in ('php','xray','ng'):parser.add_argument('--'+name+'-image',required=True)
    parser.add_argument('--node-host-image',help='Existing disposable infrastructure image; candidate cores remain explicit')
    args=parser.parse_args()
    if os.geteuid()!=0:raise SystemExit('root required for owned namespaces')
    source=args.source.resolve();out=args.out.resolve();out.mkdir(parents=True,exist_ok=True);out.chmod(0o700)
    runid=uuid.uuid4().hex[:12];prefix='vpnbot-ci-node-cold-'+runid;outer=prefix+'-host';controller=prefix+'-main';extract=prefix+'-extract';tag=prefix+':host'
    private=Path(tempfile.mkdtemp(prefix='private-',dir=out));private.chmod(0o700)
    phase='preflight';owned_image=False;result={'run_id':runid,'checks':[],'error':None,'cleanup':False,'source_sha256':{},'candidate_images':{},'bounds':'Actual PHP importer, pinned SSH, systemd, Docker node and Xray payload. Offline Docker names map only exact verified image IDs. No external registry/host config during node run.'}
    def run(command,timeout=120,check=True,**kwargs):
        p=subprocess.run(list(map(str,command)),capture_output=True,timeout=timeout,**kwargs)
        if check and p.returncode:
            result['failure_command']=[Path(str(command[0])).name]+[str(x) for x in command[1:3] if re.fullmatch(r'[A-Za-z0-9_.:/-]+',str(x))]
            result['failure_exit']=p.returncode
            result['diagnostic_locations']=re.findall(r'File "(/lab/[^"\n]+)", line (\d+)',p.stderr.decode(errors='replace'))[-6:]
            raise RuntimeError('command failed during '+phase)
        return p
    def exists(name):return run(['docker','inspect',name],check=False).returncode==0
    try:
        if any(exists(n) for n in (outer,controller,extract)):raise RuntimeError('owned name collision')
        mapping={};images={'php':args.php_image,'xr':args.xray_image,'ng':args.ng_image}
        for name,ref in images.items():
            if not re.fullmatch(r'(?:ghcr\.io/[a-zA-Z0-9_./-]+@)?sha256:[a-f0-9]{64}',ref):raise RuntimeError('immutable candidate image required')
            info=json.loads(run(['docker','image','inspect',ref]).stdout)[0];image_id=info['Id']
            if name in ('xr','ng'):
                prefix_ref='ghcr.io/axiomshiftbit/vpnbot-'+name+'@sha256:'
                refs=[x for x in info.get('RepoDigests',[]) if x.startswith(prefix_ref)]
                if ref.startswith(prefix_ref):canonical=ref
                elif len(refs)==1:canonical=refs[0]
                else:raise RuntimeError('unambiguous node repository digest required')
                mapping[canonical]=image_id;images[name]=canonical
            result['candidate_images'][name]={'reference':images[name],'id':image_id}
        phase='source-copy'
        for part in ('app','scripts','tests'):
            for path in (source/part).rglob('*'):
                if not path.is_file() or path.is_symlink() or path.name=='config.php' or path.suffix not in ('.php','.py','.sh'):continue
                rel=path.relative_to(source);dest=private/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,dest)
                result['source_sha256'][str(rel)]=hashlib.sha256(dest.read_bytes()).hexdigest()
        (private/'bundle.json').write_text(json.dumps({'schema':1,'images':images}))
        host_assets=source/'tests/integration/fixtures/backup-protocols-native/node-host'
        shutil.copyfile(host_assets/'bootstrap.py',private/'bootstrap.py')
        # The nested daemon never pulls from GHCR and sees no host socket.
        alias='#!/usr/bin/python3\nimport json,os,sys\nm=json.load(open("/lab/node-image-map.json"))\nos.execv("/usr/bin/docker",["/usr/bin/docker"]+[m.get(a,a) for a in sys.argv[1:]])\n'
        (private/'docker-offline').write_text(alias);(private/'docker-offline').chmod(0o755)
        phase='candidate-export'
        run(['docker','create','--name',extract,'--entrypoint','/bin/true',images['xr']])
        run(['docker','cp',extract+':/usr/bin/xray',private/'x31']);(private/'x31').chmod(0o755)
        run(['docker','rm',extract])
        run(['docker','save','-o',private/'images.tar',*mapping.values()],timeout=600)
        nested=archive_ids(private/'images.tar',set(mapping.values()))
        mapping={ref:nested[image_id] for ref,image_id in mapping.items()}
        (private/'node-image-map.json').write_text(json.dumps(mapping))
        for name in ('xr','ng'):result['candidate_images'][name]['nested_id']=mapping[images[name]]
        phase='host-image'
        host_image=args.node_host_image
        if not host_image:
            run(['docker','build','-q','-t',tag,host_assets],timeout=1200);owned_image=True;host_image=tag
        result['infrastructure_image_id']=json.loads(run(['docker','image','inspect',host_image]).stdout)[0]['Id']
        phase='host-start'
        run(['docker','run','-d','--name',outer,'--hostname','node-cold','--label','vpnbot.node-cold='+runid,
             '--privileged','--cgroupns','private','--network','none','--memory','2g','--cpus','2','--pids-limit','512',
             '--tmpfs','/run','--tmpfs','/run/lock','--mount','type=bind,src='+str(private)+',dst=/lab,readonly',host_image])
        deadline=time.monotonic()+60
        while time.monotonic()<deadline:
            if run(['docker','exec',outer,'systemctl','is-active','--quiet','docker'],check=False).returncode==0:break
            time.sleep(.5)
        else:raise RuntimeError('nested Docker did not become ready')
        phase='offline-image-load'
        run(['docker','exec',outer,'/usr/bin/docker','load','-i','/lab/images.tar'],timeout=600)
        for image_id in mapping.values():
            loaded=run(['docker','exec',outer,'/usr/bin/docker','image','inspect','-f','{{.Id}}',image_id]).stdout.decode().strip()
            if loaded!=image_id:raise RuntimeError('loaded candidate image mismatch')
        # node_runtime runs commands with PATH=/usr/sbin:/usr/bin:/sbin:/bin, so the
        # offline name map must precede /usr/bin/docker inside that PATH as well.
        run(['docker','exec',outer,'ln','-s','/lab/docker-offline','/usr/sbin/docker'])
        phase='node-bootstrap'
        run(['docker','exec',outer,'python3','-I','/lab/bootstrap.py'],timeout=300)
        phase='cold-restore'
        env=os.environ|{'VPNBOT_NODE_LAB':str(private),'VPNBOT_NODE_OUTER':outer,'VPNBOT_NODE_MAIN':controller,'VPNBOT_NODE_PHP_IMAGE':images['php'],'PYTHONDONTWRITEBYTECODE':'1'}
        completed=run(['python3',private/'tests/integration/fixtures/managed-node-main-run.py','--cold-restore'],timeout=900,check=False,env=env)
        result['checks']=[{'name':line[5:],'passed':line.startswith('PASS ')} for line in completed.stdout.decode(errors='replace').splitlines() if line.startswith(('PASS ','FAIL '))]
        if completed.returncode:raise RuntimeError('native cold restore failed')
        result['checks']=parse_checks(completed.stdout)
    except Exception as error:
        result['error']={'type':type(error).__name__,'phase':phase}
    finally:
        for name in (controller,outer,extract):run(['docker','rm','-f',name],check=False)
        if owned_image:run(['docker','image','rm',tag],check=False)
        result['cleanup']=not any(exists(n) for n in (controller,outer,extract))
        shutil.rmtree(private)
        (out/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'passed':sum(c['passed'] for c in result['checks']),'total':len(result['checks']),'error':result['error'],'cleanup':result['cleanup']}))
    return 1 if result['error'] or not result['cleanup'] else 0

if __name__=='__main__':raise SystemExit(main())
