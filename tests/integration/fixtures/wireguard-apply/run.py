#!/usr/bin/env python3
"""Native WG/AWG apply failure + cron retry, in dedicated network-none containers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--php-image')
    parser.add_argument('--wg-image')
    args = parser.parse_args()
    os.umask(0o077)
    args.out.mkdir(parents=True, exist_ok=True)
    owned = []
    report = {'results': {}, 'errors': [], 'bounds': 'Native kernel/userspace peer tables; SSH replaced by local process execution; no tunnel payload'}
    runid = uuid.uuid4().hex[:10]

    def run(argv, timeout=60):
        return subprocess.run(argv, capture_output=True, timeout=timeout)

    def image(value, container):
        if value is None:
            p = run(['docker', 'inspect', '--format', '{{.Image}}', container])
            if p.returncode:
                raise RuntimeError('stand image unavailable')
            value = p.stdout.decode().strip()
        p = run(['docker', 'image', 'inspect', '--format', '{{.Id}}', value])
        if p.returncode:
            raise RuntimeError('required local image unavailable')
        return p.stdout.decode().strip()

    try:
        php_image = image(args.php_image, 'php-audit')
        wg_image = image(args.wg_image, 'wireguard-audit')
        report['images'] = {'php': php_image, 'wireguard': wg_image}
        with tempfile.TemporaryDirectory(prefix='wg-apply-', dir=args.out.resolve()) as temporary:
            scratch = Path(temporary)
            source = scratch / 'source'
            # Only application source. Never mount or copy .env/config.php,
            # runtime config, credentials or cookies from the installed stand.
            for path in (args.source / 'app').rglob('*.php'):
                if not path.is_file() or path.is_symlink() or path.name == 'config.php':
                    continue
                target = source / path.relative_to(args.source)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
            if not (source / 'app/BotWireguardState.php').is_file():
                raise RuntimeError('WireGuard apply source unavailable')
            report['source_sha256'] = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                                       for p in source.rglob('*.php')}
            binary = scratch / 'bin'
            binary.mkdir()
            name = 'vpnbot-audit-wgapply-extract-' + runid
            owned.append(name)
            if run(['docker', 'create', '--name', name, '--network', 'none', '--label', 'vpnbot.wgapply.run=' + runid, '--entrypoint', '/bin/true', wg_image]).returncode:
                raise RuntimeError('binary extraction container failed')
            paths = ['/usr/bin/wg', '/usr/bin/awg', '/usr/bin/amneziawg-go', '/usr/bin/wg-quick', '/usr/bin/awg-quick',
                     '/bin/bash', '/sbin/ip', '/usr/lib/libelf.so.1', '/usr/lib/libmnl.so.0', '/usr/lib/libcap.so.2',
                     '/usr/lib/libz.so.1', '/usr/lib/libzstd.so.1', '/usr/lib/libreadline.so.8', '/usr/lib/libncursesw.so.6']
            for path in paths:
                if run(['docker', 'cp', '-L', name + ':' + path, str(binary / Path(path).name)]).returncode:
                    raise RuntimeError('required native binary/library unavailable')
            report['binary_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in binary.iterdir()}
            run(['docker', 'rm', '-f', name])
            driver = Path(__file__).with_name('driver.php').resolve()
            report['driver_sha256'] = hashlib.sha256(driver.read_bytes()).hexdigest()
            for mode in ('wg', 'awg'):
                name = 'vpnbot-audit-wgapply-' + mode + '-' + runid
                owned.append(name)
                command = ['docker', 'run', '--rm', '--init', '--name', name, '--network', 'none', '--read-only',
                           '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--device', '/dev/net/tun',
                           '--security-opt', 'no-new-privileges', '--memory', '512m', '--cpus', '1', '--pids-limit', '96',
                           '--label', 'vpnbot.wgapply.run=' + runid]
                for path, options in [('/tmp', 'exec,mode=1777'), ('/config', 'mode=0700'), ('/logs', 'mode=0700'),
                                      ('/run', 'mode=0755'), ('/etc/wireguard', 'mode=0700'), ('/etc/amnezia', 'mode=0700')]:
                    command += ['--tmpfs', path + ':rw,nosuid,nodev,size=32m,' + options]
                for origin, target in [(source, '/audit-source'), (binary, '/audit-bin'), (driver, '/audit-driver.php')]:
                    command += ['--mount', 'type=bind,src=' + str(origin) + ',dst=' + target + ',readonly']
                command += ['--env', 'VPNBOT_TEST_SOURCE=/audit-source', '--env', 'PATH=/audit-bin:/usr/sbin:/usr/bin:/sbin:/bin',
                            '--env', 'LD_LIBRARY_PATH=/audit-bin', '--entrypoint', '/bin/sh', php_image, '-ec',
                            'umask 077; ln -s /etc/wireguard /etc/amnezia/amneziawg; '
                            'php -l /audit-source/app/bot.php >/dev/null; '
                            'php -l /audit-source/app/BotWireguardState.php >/dev/null; '
                            'php -l /audit-driver.php >/dev/null; '
                            'exec php -d display_errors=0 /audit-driver.php "$1"', 'sh', mode]
                try:
                    p = run(command, timeout=120)
                    try:
                        result = json.loads(p.stdout)
                    except ValueError:
                        result = {'status': 'ERROR', 'reason': 'invalid result JSON'}
                    result.update(exit=p.returncode, stderr_bytes=len(p.stderr))
                    report['results'][mode] = result
                finally:
                    run(['docker', 'rm', '-f', name])
    except Exception as error:
        report['errors'].append(type(error).__name__)
    finally:
        for name in owned:
            run(['docker', 'rm', '-f', name])
        p = run(['docker', 'ps', '-a', '--filter', 'label=vpnbot.wgapply.run=' + runid, '--format', '{{.Names}}'])
        report['own_containers_remaining'] = p.stdout.decode().splitlines()
        report['cleanup_confirmed'] = p.returncode == 0 and not report['own_containers_remaining']
        (args.out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    passed = (not report['errors'] and report['cleanup_confirmed'] and len(report['results']) == 2
              and all(r.get('status') == 'PASS' and r.get('exit') == 0 and r.get('stderr_bytes') == 0
                      for r in report['results'].values()))
    print(json.dumps({'passed': passed, 'backends': {k: v.get('backend') for k, v in report['results'].items()},
                      'checks': sum(len(v.get('checks', {})) for v in report['results'].values()),
                      'cleanup_confirmed': report['cleanup_confirmed']}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
