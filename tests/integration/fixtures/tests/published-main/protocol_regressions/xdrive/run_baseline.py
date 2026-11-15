#!/usr/bin/env python3
"""Переносимый native post-fix XD-01/XD-02/PAC-01. Не содержит SSH/deploy."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time
import uuid

PREFIX = 'vpnbot-ci-regression-xd-'
REQUIRED = ['app/bot.php', 'app/BotXdrive.php']

class InfrastructureError(Exception):
    pass

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--host-tag', required=True)
    p.add_argument('--image', required=True)
    p.add_argument('--cases', nargs='+', choices=('XD-01','XD-02'), default=['XD-01','XD-02'])
    a = p.parse_args()
    os.umask(0o077)
    source, root, harness = a.source.resolve(), a.root.resolve(), Path(__file__).resolve().parent
    if not (root.parent/'fixture-owner').is_file(): p.error('owned fixture root required')
    if not all((source / f).is_file() for f in REQUIRED) or (source / 'app/config.php').exists() or (source / '.env').exists():
        p.error('нужен подготовленный code-only source без app/config.php/.env')
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    token = uuid.uuid4().hex[:8]
    runroot = root / ('run-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + token)
    runroot.mkdir(mode=0o700)
    result = {'host_tag': a.host_tag, 'source_variant': source.name, 'image': a.image,
              'run_token': token, 'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source_sha256': {f: hashlib.sha256((source/f).read_bytes()).hexdigest() for f in REQUIRED},
              'cases': {}, 'infrastructure_errors': [], 'cleanup': {}}
    owned, networks = [], []
    label = 'vpnbot.audit.id=' + token
    (runroot/'owner.json').write_text(json.dumps({'token':token}))
    marker = runroot / 'marker'
    marker.write_text('SYNTHETIC-ONLY\n')
    def save():
        (runroot/'results.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    def run(cmd, timeout=40, check=True):
        try:
            r = subprocess.run(list(map(str, cmd)), capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            raise InfrastructureError(type(e).__name__) from None
        if check and r.returncode:
            # Только категория: не пересказываем окружение и чужие Docker diagnostics.
            raise InfrastructureError('command_failed:' + Path(str(cmd[0])).name + ':' + str(r.returncode))
        return r
    def docker(*args, **kw):
        return run(['docker', *args], **kw)
    def name(s):
        return PREFIX + token + '-' + s
    def check_idle():
        if shutil.disk_usage(root).free < 2 * 1024**3:
            raise InfrastructureError('insufficient_disk')
    def create(kind, net, ip, command, extra=(), memory='128m'):
        check_idle()
        n = name(kind)
        cmd = ['create', '--init', '--name', n, '--label', label, '--network', net,
               '--memory', memory, '--pids-limit', '96', '--read-only',
               '--tmpfs', '/tmp:rw,nosuid,nodev,size=32m',
               '-e', 'PYTHONDONTWRITEBYTECODE=1', '-e', 'HTTP_PROXY=', '-e', 'HTTPS_PROXY=',
               '-e', 'ALL_PROXY=', '-e', 'http_proxy=', '-e', 'https_proxy=', '-e', 'all_proxy=',
               '-v', str(harness)+':/fixture:ro', '-v', str(marker)+':/run/vpnbot-synthetic-audit:ro']
        if ip:
            cmd += ['--ip', ip]
        cmd += list(extra)
        cmd += ['--entrypoint', command[0], a.image, *command[1:]]
        docker(*cmd)
        owned.append(n)
        return n
    def destroy(ns):
        for n in reversed(ns):
            docker('rm', '-f', n, check=False)
    def stats(client, address):
        code = 'import urllib.request; o=urllib.request.build_opener(urllib.request.ProxyHandler({})); print(o.open("http://' + address + ':8098/stats", timeout=3).read().decode())'
        out = docker('exec', client, 'python3', '-c', code).stdout
        return json.loads(out)
    def wait_ready(client, address):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            try:
                return stats(client, address)
            except (InfrastructureError, ValueError):
                time.sleep(.2)
        raise InfrastructureError('http_fixture_not_ready')
    def probe(client, mode, memory='32M'):
        started = time.monotonic()
        r = docker('exec', client, 'php', '-d', 'memory_limit='+memory,
                   '/fixture/xdrive_probe_real.php', mode, check=False, timeout=30)
        output = r.stdout + r.stderr
        parsed = None
        for line in reversed(r.stdout.splitlines()):
            try:
                candidate = json.loads(line)
                if isinstance(candidate, dict) and 'returned' in candidate:
                    parsed = candidate
                    break
            except ValueError:
                pass
        return {'exit_code': r.returncode, 'structured_result': parsed,
                'memory_limit_fatal': bool(re.search(r'Allowed memory size of \d+ bytes exhausted', output)),
                'other_fatal': 'Fatal error' in output and 'Allowed memory size' not in output,
                'seconds': round(time.monotonic()-started, 3), 'php_memory_limit': memory}
    def network_phase(tag, rebind=False, large=False, dns=True):
        ns = []
        try:
            public_cmd = ['python3', '/fixture/controlled_http.py', '--bind', '11.77.78.2', '--label', 'large' if large else 'public']
            if large:
                public_cmd += ['--propfind-bytes', str(64*1024*1024)]
            pub = create(tag+'-public', public_net, '11.77.78.2', public_cmd)
            ns.append(pub)
            private = create(tag+'-private', private_net, '172.30.79.3', ['python3','/fixture/controlled_http.py','--bind','172.30.79.3','--label','private'])
            ns.append(private)
            if dns:
                dns_cmd = ['python3','/fixture/controlled_dns.py','--bind','11.77.78.53','--port','53']
                if rebind:
                    dns_cmd += ['--private-after']
                resolver = create(tag+'-dns', public_net, '11.77.78.53', dns_cmd)
                ns.append(resolver)
            client = create(tag+'-php', public_net, '11.77.78.10', ['/bin/sleep','240'],
                extra=('--dns','11.77.78.53','-v',str(source)+':/src:ro'))
            ns.append(client)
            docker('network','connect','--ip','172.30.79.10', private_net, client)
            for n in ns:
                docker('start',n)
            wait_ready(client, '11.77.78.2')
            wait_ready(client, '172.30.79.3')
            time.sleep(.3)
            outcome = probe(client, 'rebind' if dns else ('large' if large else 'baseline'))
            outcome['public_http'] = stats(client,'11.77.78.2')
            outcome['private_http'] = stats(client,'172.30.79.3')
            if dns:
                docker('kill','--signal','USR1',resolver)
                time.sleep(.1)
                lines = docker('logs',resolver).stdout.splitlines()
                outcome['dns_counts'] = next((json.loads(x)['dns_counts_before_reset'] for x in lines if 'dns_counts_before_reset' in x), None)
            return outcome
        finally:
            destroy(ns)
    def healthy(r):
        return r['exit_code'] == 0 and (r['structured_result'] or {}).get('error') == '' and r['public_http']['counts'].get('PUT',0) == 1 and not r['private_http']['counts']
    def interrupted(signum, frame):
        raise InfrastructureError('interrupted:'+str(signum))
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
        signal.signal(sig,interrupted)
    try:
        check_idle()
        if docker('image','inspect','--format','{{.Id}}',a.image).stdout.strip()!=a.image:
            raise InfrastructureError('image_digest_mismatch')
        if any(c in a.cases for c in ('XD-01','XD-02')):
            public_net, private_net = name('public-net'), name('private-net')
            for net, subnet in ((public_net,'11.77.78.0/24'),(private_net,'172.30.79.0/24')):
                docker('network','create','--internal','--label',label,'--subnet',subnet,net)
                networks.append(net)
        if 'XD-01' in a.cases:
            baseline = network_phase('dns-control')
            result['cases']['XD-01']={'evidence_kind':'native-network','control':baseline,'verdict':'ERROR'}
            if healthy(baseline):
                fault = network_phase('dns-fault',rebind=True)
                observed = fault['private_http']['counts'].get('PROPFIND',0)>0
                queried = (fault.get('dns_counts') or {}).get('private_answers',0)>0
                result['cases']['XD-01'].update(fault=fault,verdict='PASS' if not observed and queried and fault['exit_code'] in (0,1) and (fault['structured_result'] or {}).get('returned') is True and (fault['structured_result'] or {}).get('error') else 'FAIL')
            else:
                result['cases']['XD-01']['reason']='control_failed'
            save(); print('XD-01 '+result['cases']['XD-01']['verdict'],flush=True)
        if 'XD-02' in a.cases:
            baseline = network_phase('size-control',dns=False)
            result['cases']['XD-02']={'evidence_kind':'native-network','control':baseline,'verdict':'ERROR'}
            if healthy(baseline):
                fault = network_phase('size-fault',large=True,dns=False)
                observed = fault['memory_limit_fatal'] and fault['public_http']['counts'].get('PROPFIND',0)>0
                result['cases']['XD-02'].update(fault=fault,verdict='PASS' if not observed and fault['exit_code'] in (0,1) and (fault['structured_result'] or {}).get('returned') is True and not fault['other_fatal'] and (fault['structured_result'] or {}).get('error') and fault['public_http']['counts'].get('PROPFIND',0)>0 else 'FAIL')
            else:
                result['cases']['XD-02']['reason']='control_failed'
            save(); print('XD-02 '+result['cases']['XD-02']['verdict'],flush=True)
    except InfrastructureError as e:
        result['infrastructure_errors'].append(str(e))
        print('ERROR '+str(e),flush=True)
    except Exception as e:
        result['infrastructure_errors'].append(type(e).__name__)
        print('ERROR '+type(e).__name__,flush=True)
    finally:
        for n in reversed(owned):
            if n.startswith(PREFIX+token+'-'):
                docker('rm','-f',n,check=False)
        for n in reversed(networks):
            docker('network','rm',n,check=False)
        remaining_containers=docker('ps','-aq','--filter','label='+label).stdout.splitlines()
        remaining_networks=docker('network','ls','-q','--filter','label='+label).stdout.splitlines()
        result['cleanup']={'containers_remaining':len(remaining_containers),'networks_remaining':len(remaining_networks),
                           'passed':not remaining_containers and not remaining_networks}
        result['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
        print(json.dumps({'result_path':str(runroot/'results.json'),'cases':{k:v['verdict'] for k,v in result['cases'].items()},
                          'cleanup_passed':result['cleanup']['passed'],'errors':result['infrastructure_errors']}),flush=True)
    if result['infrastructure_errors'] or not result['cleanup']['passed'] or any(v['verdict']=='ERROR' for v in result['cases'].values()):
        return 2
    return 3 if any(v['verdict'] in ('INCONCLUSIVE','FAIL') for v in result['cases'].values()) else 0

if __name__=='__main__':
    raise SystemExit(main())
