#!/usr/bin/env python3
"""Shared-access failure isolation with real AnyTLS traffic in an isolated container."""
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
    parser.add_argument('--protocol-image')
    parser.add_argument('--stats-binary', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    args.out.mkdir(parents=True, exist_ok=True)
    owned = []
    runid = uuid.uuid4().hex[:10]
    report = {'errors': [], 'result': {}, 'bounds': 'Real AnyTLS auth, live stream revoke, TLS, stats API and Supervisor; Xray source/other protocol ledgers are synthetic files'}

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
        protocol_image = image(args.protocol_image, 'anytls-audit') if args.stats_binary is None else None
        report['images'] = {'php': php_image, 'protocol': protocol_image}
        with tempfile.TemporaryDirectory(prefix='managed-sync-', dir=args.out.resolve()) as temporary:
            scratch = Path(temporary)
            source = scratch / 'source'
            # Application sources only, never installed configuration or secrets.
            for part in ('app', 'scripts'):
                for path in (args.source / part).rglob('*'):
                    if not path.is_file() or path.is_symlink() or path.name == 'config.php' or path.suffix not in ('.php', '.py'):
                        continue
                    target = source / path.relative_to(args.source)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, target)
            report['source_sha256'] = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                                       for p in source.rglob('*') if p.is_file()}
            binary = scratch / 'bin'
            binary.mkdir()
            if args.stats_binary is not None:
                shutil.copyfile(args.stats_binary, binary / 'protocol-stats')
            else:
                name = 'vpnbot-audit-mpsync-extract-' + runid
                owned.append(name)
                if run(['docker', 'create', '--name', name, '--network', 'none', '--label', 'vpnbot.mpsync.run=' + runid,
                        '--entrypoint', '/bin/true', protocol_image]).returncode:
                    raise RuntimeError('binary extraction failed')
                if run(['docker', 'cp', name + ':/usr/local/bin/protocol-stats', str(binary / 'protocol-stats')]).returncode:
                    raise RuntimeError('native stats API client unavailable')
                run(['docker', 'rm', '-f', name])
            (binary / 'protocol-stats').chmod(0o700)
            report['stats_binary_sha256'] = hashlib.sha256((binary / 'protocol-stats').read_bytes()).hexdigest()
            tools = Path(__file__).resolve().parent
            report['fixture_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in tools.iterdir()
                                        if p.is_file() and p.suffix in ('.php', '.py')}
            name = 'vpnbot-audit-mpsync-' + runid
            owned.append(name)
            command = ['docker', 'run', '--rm', '--init', '--name', name, '--network', 'none', '--read-only',
                       '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--security-opt', 'no-new-privileges',
                       '--memory', '512m', '--cpus', '1', '--pids-limit', '128', '--label', 'vpnbot.mpsync.run=' + runid,
                       '--env', 'PYTHONDONTWRITEBYTECODE=1']
            for path in ('/tmp', '/audit-fixture', '/config', '/logs', '/certs'):
                command += ['--tmpfs', path + ':rw,exec,nosuid,nodev,mode=0700,size=64m']
            for origin, target in [(source, '/audit-source'), (binary, '/audit-bin'), (tools, '/audit-tools')]:
                command += ['--mount', 'type=bind,src=' + str(origin) + ',dst=' + target + ',readonly']
            command += ['--entrypoint', '/bin/sh', php_image, '-ec',
                        'php -l /audit-source/app/bot.php >/dev/null; '
                        'php -l /audit-source/app/BotProtocolSubscriptions.php >/dev/null; '
                        'php -l /audit-tools/driver.php >/dev/null; '
                        'exec python3 -B /audit-tools/probe.py']
            try:
                p = run(command, timeout=240)
                try:
                    report['result'] = json.loads(p.stdout)
                except ValueError:
                    report['result'] = {'status': 'ERROR', 'stdout_bytes': len(p.stdout)}
                report.update(container_exit=p.returncode, stderr_bytes=len(p.stderr))
            finally:
                run(['docker', 'rm', '-f', name])
    except Exception as error:
        report['errors'].append(type(error).__name__)
    finally:
        for name in owned:
            run(['docker', 'rm', '-f', name])
        p = run(['docker', 'ps', '-a', '--filter', 'label=vpnbot.mpsync.run=' + runid, '--format', '{{.Names}}'])
        report['cleanup_confirmed'] = p.returncode == 0 and not p.stdout.strip()
        (args.out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    passed = not report['errors'] and report['cleanup_confirmed'] and report.get('container_exit') == 0 and report['result'].get('status') == 'PASS'
    print(json.dumps({'passed': passed, 'checks': len(report['result'].get('checks', [])), 'cleanup_confirmed': report['cleanup_confirmed']}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
