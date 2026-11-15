#!/usr/bin/env python3
"""Real Shadowsocks rotation with file bind mounts and checked controller RPC.

All credentials are generated inside a private tmpfs volume. The only replaced
boundary is SSH: fixed Bot commands run through docker exec in owned containers.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import tempfile
import time
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--php-image')
    parser.add_argument('--ss-image')
    parser.add_argument('--proxy-image')
    parser.add_argument('--lifecycle-source', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    args.out.mkdir(parents=True, exist_ok=True)
    runid = uuid.uuid4().hex[:10]
    owned, volumes, checks = [], [], []
    report = {'errors': [], 'checks': checks, 'run_id': runid,
              'bounds': 'Native ssserver/sslocal authentication and active stream, production controller and PHP; docker exec replaces SSH. DNSTT and external network are not exercised.'}
    tools = Path(__file__).resolve().parent
    stage = 'initial'

    def run(argv, timeout=65):
        return subprocess.run(argv, capture_output=True, timeout=timeout)

    def required(argv, timeout=65):
        result = run(argv, timeout)
        if result.returncode:
            raise RuntimeError('fixture command failed')
        return result.stdout

    def check(label, ok):
        checks.append({'name': label, 'ok': bool(ok)})

    def image(value, default):
        if value is None:
            value = required(['docker', 'inspect', '--format', '{{.Image}}', default]).decode().strip()
        return required(['docker', 'image', 'inspect', '--format', '{{.Id}}', value]).decode().strip()

    def poll(fn, timeout=12):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if fn():
                return True
            time.sleep(.15)
        return False

    try:
        php_image = image(args.php_image, 'php-audit')
        ss_image = image(args.ss_image, 'shadowsocks-audit')
        proxy_image = image(args.proxy_image or args.ss_image, 'proxy-audit')
        report['images'] = {'php': php_image, 'ss': ss_image, 'proxy': proxy_image}
        report['fixture_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                    for p in tools.iterdir() if p.is_file() and p.suffix in ('.php', '.py')}
        with tempfile.TemporaryDirectory(prefix='classic-proxy-', dir=args.out.resolve()) as temporary:
            source = Path(temporary) / 'source'
            for part in ('app', 'scripts'):
                for p in (args.source / part).rglob('*'):
                    if not p.is_file() or p.is_symlink() or p.name == 'config.php' or p.suffix not in ('.php', '.py', '.sh'):
                        continue
                    target = source / p.relative_to(args.source)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(p, target)
            lifecycle = args.lifecycle_source or args.source / 'scripts'
            for name in ('service_supervisor.sh', 'service_daemon.sh'):
                shutil.copyfile(lifecycle / name, source / 'scripts' / name)
            report['source_sha256'] = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                                       for p in source.rglob('*') if p.is_file()}
            for case in ('failed-stop', 'rotate', 'failed-second-start'):
                stage = case + ':setup'
                prefix = 'vpnbot-audit-classic-' + runid + '-' + case
                php, ss, proxy = [prefix + '-' + name for name in ('php', 'ss', 'proxy')]
                volume = prefix + '-data'
                volumes.append(volume)
                required(['docker', 'volume', 'create', '--label', 'vpnbot.classic.run=' + runid,
                          '--driver', 'local', '--opt', 'type=tmpfs', '--opt', 'device=tmpfs',
                          '--opt', 'o=size=16m,uid=0,mode=0700', volume])
                data = required(['docker', 'volume', 'inspect', '--format', '{{.Mountpoint}}', volume]).decode().strip()

                def create(name, img, network, mounts, command):
                    owned.append(name)
                    cmd = ['docker', 'run', '-d', '--init', '--name', name, '--network', network, '--read-only',
                           '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--memory', '512m',
                           '--cpus', '1', '--pids-limit', '128', '--label', 'vpnbot.classic.run=' + runid,
                           '--env', 'PYTHONDONTWRITEBYTECODE=1', '--env', 'TOKIO_WORKER_THREADS=1']
                    for path in ('/run', '/tmp', '/logs'):
                        cmd += ['--tmpfs', path + ':rw,exec,nosuid,nodev,mode=0700,size=32m']
                    for mount in mounts:
                        cmd += ['--mount', mount]
                    cmd += ['--entrypoint', command[0], img] + command[1:]
                    required(cmd)

                create(php, php_image, 'none', [
                    'type=volume,src=' + volume + ',dst=/config',
                    'type=bind,src=' + str(source) + ',dst=/audit-source,readonly',
                    'type=bind,src=' + str(tools) + ',dst=/audit-tools,readonly'],
                    ['/bin/sh', '-ec', 'php -l /audit-source/app/bot.php >/dev/null; '
                     'php -l /audit-tools/driver.php >/dev/null; exec python3 -B /audit-tools/probe.py serve'])
                if not poll(lambda: run(['docker', 'exec', php, 'test', '-s', '/config/sslocal.json']).returncode == 0):
                    raise RuntimeError('fixture seed failed')
                for name, img, conf, group in ((ss, ss_image, 'ssserver', 'ss'), (proxy, proxy_image, 'sslocal', 'proxy')):
                    mounts = ['type=bind,src=' + data + '/' + conf + '.json,dst=/config.json,readonly',
                              'type=volume,src=' + volume + ',dst=/config,readonly']
                    for helper in ('service_supervisor.sh', 'service_daemon.sh'):
                        mounts += ['type=bind,src=' + str(source / 'scripts' / helper) + ',dst=/' + helper + ',readonly']
                    create(name, img, 'container:' + php, mounts,
                           ['/bin/sh', '/service_supervisor.sh', 'supervise', group])
                for container, name in ((ss, 'ssserver'), (proxy, 'sslocal')):
                    if not poll(lambda: run(['docker', 'exec', container, '/bin/sh', '/service_supervisor.sh', 'status', name]).returncode == 0):
                        raise RuntimeError('native service not ready')
                for generation in ('old', 'new'):
                    required(['docker', 'exec', '-d', ss, '/usr/bin/sslocal', '-c', '/config/client-' + generation + '.json'])

                def probe(mode, *argv):
                    return json.loads(required(['docker', 'exec', php, 'python3', '-B', '/audit-tools/probe.py', mode, *argv], 10))

                def traffic(port):
                    return probe('traffic', str(port))['ok']

                if not poll(lambda: traffic(1088) and traffic(1080)):
                    raise RuntimeError('native positive control failed')
                check(case + ':old_auth_and_proxy_positive_control', True)
                check(case + ':new_auth_initially_denied', not traffic(1089))
                required(['docker', 'exec', '-d', php, 'python3', '-B', '/audit-tools/probe.py', 'hold'])
                check(case + ':old_stream_established', poll(lambda: probe('state')['stream_open']))

                def mutate(fault):
                    process = subprocess.Popen(['docker', 'exec', '-i', php, 'php', '/audit-tools/driver.php'],
                                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
                    injected = False
                    responses = []
                    try:
                        deadline = time.monotonic() + 100
                        while time.monotonic() < deadline:
                            if not select.select([process.stdout], [], [], max(.01, deadline - time.monotonic()))[0]:
                                break
                            line = process.stdout.readline()
                            if not line:
                                break
                            value = json.loads(line)
                            if 'result' in value:
                                process.wait(timeout=5)
                                return value['result'], injected, responses
                            rpc = value['rpc']; command = rpc['cmd']; service = rpc['service']
                            if service not in ('ss', 'proxy'):
                                raise RuntimeError('unexpected transport target')
                            dropped = not injected and ((fault == 'stop' and service == 'ss' and
                                       (' stop ssserver' in command or command.startswith('pkill ssserver'))) or
                                      (fault == 'start' and service == 'proxy' and 'sslocal' in command and
                                       (' start sslocal' in command or (not command.startswith('pkill') and '/service_supervisor.sh' not in command))))
                            if dropped:
                                injected = True; response = {'ok': False, 'output': ''}
                            else:
                                result = run(['docker', 'exec', ss if service == 'ss' else proxy, '/bin/sh', '-c', command])
                                response = {'ok': result.returncode == 0, 'output': result.stdout.decode()}
                            responses.append({'service': service, 'dropped': dropped, 'ok': response['ok']})
                            process.stdin.write((json.dumps(response) + '\n').encode()); process.stdin.flush()
                        raise RuntimeError('mutation did not finish')
                    finally:
                        if process.poll() is None:
                            process.kill(); process.wait(timeout=5)

                stage = case + ':mutation'
                value, injected, operations = mutate('stop' if case == 'failed-stop' else 'start' if case == 'failed-second-start' else '')
                report.setdefault('operations', {})[case] = operations
                state = probe('state')
                check(case + ':both_file_inodes_retained', all(state[n]['same_inode'] for n in ('ssserver', 'sslocal')))
                if case == 'rotate':
                    check(case + ':reported_success', value['ok'] and value['menus'] == 1)
                    check(case + ':both_files_new_private', all(state[n]['new'] and state[n]['private'] for n in ('ssserver', 'sslocal')))
                    check(case + ':active_old_stream_closed', poll(lambda: probe('state')['stream_closed']))
                    check(case + ':new_auth_and_proxy_work', poll(lambda: traffic(1089) and traffic(1080)))
                    check(case + ':old_auth_revoked', not traffic(1088))
                else:
                    check(case + ':fault_injected', injected)
                    check(case + ':failure_without_success_menu', not value['ok'] and value['menus'] == 0)
                    check(case + ':both_files_old', all(state[n]['old'] for n in ('ssserver', 'sslocal')))
                    if case == 'failed-stop':
                        check(case + ':unconfirmed_revocation_not_disguised', traffic(1088))
                    else:
                        check(case + ':controller_both_off', all(run(['docker', 'exec', c, '/bin/sh', '/service_supervisor.sh', 'status', n]).returncode == 3
                                                               for c, n in ((ss, 'ssserver'), (proxy, 'sslocal'))))
                        check(case + ':old_and_new_access_denied', not traffic(1088) and not traffic(1089))
                        check(case + ':active_old_stream_closed', poll(lambda: probe('state')['stream_closed']))
                        value, _, _ = mutate('')
                        check(case + ':explicit_retry_succeeds', value['ok'] and value['menus'] == 1 and poll(lambda: traffic(1089) and traffic(1080)))
                        check(case + ':retry_keeps_old_revoked', not traffic(1088))
                for container in (proxy, ss, php):
                    run(['docker', 'rm', '-f', container])
                run(['docker', 'volume', 'rm', volume])
    except Exception as error:
        report['errors'].append({'type': type(error).__name__, 'stage': stage})
    finally:
        for name in reversed(owned):
            run(['docker', 'rm', '-f', name])
        for name in volumes:
            run(['docker', 'volume', 'rm', name])
        remaining = run(['docker', 'ps', '-a', '--filter', 'label=vpnbot.classic.run=' + runid, '--format', '{{.Names}}'])
        remaining_volumes = run(['docker', 'volume', 'ls', '--filter', 'label=vpnbot.classic.run=' + runid, '--format', '{{.Name}}'])
        report['cleanup_confirmed'] = remaining.returncode == 0 and not remaining.stdout.strip() and remaining_volumes.returncode == 0 and not remaining_volumes.stdout.strip()
        report['status'] = 'PASS' if checks and all(c['ok'] for c in checks) and not report['errors'] and report['cleanup_confirmed'] else 'FAIL'
        (args.out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('status', 'checks', 'errors', 'cleanup_confirmed')}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
