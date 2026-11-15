#!/usr/bin/env python3
"""Изолированная регрессия Panel на Unit; вызывается существующим panel.py."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    stand = Path('/opt/vpnbot-hosted-ci/stand')
    parser.add_argument('--source', type=Path, default=stand / 'bot')
    parser.add_argument('--output', type=Path, default=stand / 'results/panel-security')
    parser.add_argument('--php-image')
    args = parser.parse_args()
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=True)
    image = args.php_image
    if not image:
        inspected = subprocess.run(['docker', 'inspect', '--format',
            '{{.Image}} {{index .Config.Labels \"com.docker.compose.service\"}}', 'php-audit'], capture_output=True, text=True, check=True, timeout=15)
        fields = inspected.stdout.split()
        if len(fields) != 2 or fields[1] != 'php':
            raise RuntimeError('expected hosted-CI PHP service')
        image = fields[0]
    name = 'vpnbot-ci-panel-sec-' + uuid.uuid4().hex[:12]
    helper = Path(__file__).resolve().parent
    result = {'status': 'ERROR', 'image': image, 'source': {}, 'cleanup': False}
    def interrupted(_signum, _frame):
        raise InterruptedError('interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    with tempfile.TemporaryDirectory(prefix='source-', dir=args.output) as scratch:
        source = Path(scratch)
        files = list((args.source / 'app').glob('*.php'))
        files += list((args.source / 'app/panel').glob('*.php'))
        files += [args.source / 'app/panel/ui.html']
        for path in files:
            if path.name == 'config.php' or path.is_symlink():
                continue
            relative = path.relative_to(args.source)
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            result['source'][str(relative)] = hashlib.sha256(destination.read_bytes()).hexdigest()
        for required in ('app/bot.php', 'app/panel/Panel.php', 'app/panel/ui.html'):
            if required not in result['source']:
                raise RuntimeError('missing static Panel source')
        try:
            command = ['docker', 'run', '--name', name, '--network', 'none',
                '--label', 'vpnbot.ci.panel-security=true', '--memory', '256m', '--cpus', '1',
                '--pids-limit', '64', '--tmpfs', '/scratch:rw,size=64m,mode=0700',
                '-e', 'PANEL_TEST_ISOLATED=owned-unit-panel-v1',
                '-v', str(source.resolve()) + ':/source:ro',
                '-v', str(helper) + ':/probe:ro', '--entrypoint', 'python3', image, '-B', '/probe/probe.py']
            completed = subprocess.run(command, capture_output=True, text=True, timeout=150)
            result['probe'] = json.loads(completed.stdout)
            result['status'] = result['probe'].get('status', 'ERROR')
            if completed.returncode not in (0, 1, 2):
                result['status'] = 'ERROR'
        except Exception as error:
            result['error_class'] = type(error).__name__
        finally:
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=20)
            result['cleanup'] = subprocess.run(['docker', 'inspect', name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15).returncode != 0
            if not result['cleanup']:
                result['status'] = 'ERROR'
    (args.output / 'results.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'cleanup': result['cleanup']}))
    return {'PASS': 0, 'FAIL': 1}.get(result['status'], 2)


if __name__ == '__main__':
    raise SystemExit(main())
