#!/usr/bin/env python3
"""Isolated native Xray quota/reset smoke. Requires already cached images."""
import argparse
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
    parser.add_argument('--php-image', required=True)
    parser.add_argument('--xray-image', required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    prefix = 'vpnbot-xray-ledger-' + uuid.uuid4().hex[:10]
    containers = []
    report = {'checks': [], 'error': None, 'cleanup': False}

    def idle():
        workers = subprocess.run(['pgrep', '-x', 'Runner.Worker'], capture_output=True).stdout.split()
        if not workers:
            return
        # Full CI may run its own entry, but may never overlap another worker.
        ancestors = set()
        pid = os.getpid()
        while pid > 1:
            ancestors.add(pid)
            pid = int(Path('/proc/' + str(pid) + '/stat').read_text().rsplit(')', 1)[1].split()[1])
        if not {int(pid) for pid in workers}.issubset(ancestors):
            raise RuntimeError('Another Runner.Worker is active')

    def run(*command):
        return subprocess.run(command, capture_output=True, check=True, timeout=60)

    try:
        idle()
        report['images'] = {name: run('docker', 'image', 'inspect', '--format', '{{.Id}}', value).stdout.decode().strip()
                            for name, value in [('php', args.php_image), ('xray', args.xray_image)]}
        with tempfile.TemporaryDirectory(prefix=prefix + '-', dir=args.out) as temporary:
            work = Path(temporary)
            source_code = work / 'source'
            for part in ('app', 'scripts'):
                for path in (args.source / part).rglob('*'):
                    if not path.is_file() or path.is_symlink() or path.name in ('config.php', 'debug.php') or path.suffix not in ('.php', '.py', '.sh'):
                        continue
                    target = source_code / path.relative_to(args.source)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, target)
            extractor = prefix + '-extract'; containers.append(extractor)
            run('docker', 'create', '--name', extractor, '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges', '--entrypoint', '/bin/true', args.xray_image)
            run('docker', 'cp', extractor + ':/usr/bin/xray', str(work / 'xray'))
            run('docker', 'rm', extractor); containers.remove(extractor)
            (work / 'xray').chmod(0o700)
            (work / 'xray.json').write_text('{}')
            (work / 'xray.json').chmod(0o600)
            idle()
            container = prefix + '-runtime'; containers.append(container)
            command = ['docker', 'run', '--rm', '--init', '--name', container, '--network', 'none', '--read-only',
                       '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--cpus', '1', '--memory', '768m', '--pids-limit', '128',
                       '--tmpfs', '/tmp:rw,exec,size=192m', '--tmpfs', '/logs:rw,size=32m', '--tmpfs', '/config:rw,size=16m', '--tmpfs', '/run:rw,size=16m']
            mounts = [(source_code.resolve(), '/source', True), (work / 'xray', '/usr/bin/xray', True),
                      (work / 'xray', '/usr/local/bin/xray', True), (work / 'xray.json', '/xray.json', False), (work / 'xray.json', '/config/xray.json', False),
                      (args.source.resolve() / 'scripts/xray_hot_apply.py', '/xray_hot_apply.py', True),
                      (Path(__file__).with_name('driver.php').resolve(), '/native-driver.php', True)]
            for source, target, readonly in mounts:
                command += ['--mount', 'type=bind,src=' + str(source) + ',dst=' + target + (',readonly' if readonly else '')]
            command += ['--entrypoint', 'php', args.php_image, '/native-driver.php']
            result = subprocess.run(command, capture_output=True, timeout=150)
            report.update(json.loads(result.stdout))
            report['exit'] = result.returncode
            report['stderr_bytes'] = len(result.stderr)
            # The driver emits only test names and booleans; no profiles or keys.
    except Exception as error:
        report['error'] = type(error).__name__
        report['exit'] = 1
    finally:
        for container in containers:
            subprocess.run(['docker', 'rm', '-f', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        state = subprocess.run(['docker', 'ps', '-a', '--format', '{{.Names}}'], capture_output=True, text=True)
        report['cleanup'] = state.returncode == 0 and not any(name.startswith(prefix) for name in state.stdout.splitlines())
        if not report['cleanup']:
            report['exit'] = 1
            report['error'] = 'CleanupUnconfirmed'
        (args.out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'exit': report.get('exit', 1), 'passed': report.get('passed', 0), 'total': report.get('total', 0), 'error': report['error']}))
    return report.get('exit', 1)


if __name__ == '__main__':
    raise SystemExit(main())
