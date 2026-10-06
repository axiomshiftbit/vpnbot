#!/usr/bin/env python3
"""Run the provisioned VPNBotTest suite; never use production credentials/data."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from image_bundle import atomic, canonical, command, fingerprint, read

ROOT = Path('/opt/vpnbot-ci')
REQUIRED = {'unit', 'native', 'modules', 'backup_restore', 'update_rollback', 'faults', 'telegram_http'}


def suite_identity(suite):
    files = set(p for p in suite.rglob('*') if p.is_file() and p.suffix in ('.py', '.php', '.sh'))
    dependencies = suite / 'dependencies.json'
    if dependencies.exists():
        files.add(dependencies)
        paths = json.loads(dependencies.read_text())
        if not isinstance(paths, list) or any(not isinstance(p, str) or not Path(p).is_absolute() for p in paths):
            raise ValueError('invalid test dependency manifest')
        files.update(Path(p) for p in paths)
    if not files or not (suite / 'run.py').is_file():
        raise ValueError('native test suite is not provisioned')
    digest = hashlib.sha256()
    for file in sorted(files):
        digest.update(str(file).encode() + b'\0' + file.read_bytes())
    return digest.hexdigest()


def main():
    if Path('/etc/vpnbot-ci-test-host').read_text().strip() != 'vpnbot-test':
        raise ValueError('not the designated test host')
    bundle = read(sys.argv[1])
    if bundle['source'] != command('git', 'rev-parse', 'HEAD'):
        raise ValueError('checkout and candidate differ')
    # Every run requires fresh results; no cached report can admit another set.
    output = Path(sys.argv[2])
    output.unlink(missing_ok=True)
    with (ROOT / 'test.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        suite = ROOT / 'suite'
        identity = suite_identity(suite)
        results = ROOT / 'results' / (str(bundle['run']) + '-' + str(bundle['attempt']))
        results.mkdir(mode=0o700, parents=True, exist_ok=False)
        with (results / 'test.log').open('wb') as log:
            result = subprocess.run([sys.executable, str(suite / 'run.py'), '--checkout', str(Path.cwd()),
                                     '--manifest', str(Path(sys.argv[1]).resolve()), '--results', str(results)],
                                    stdout=log, stderr=subprocess.STDOUT, timeout=6600)
        if result.returncode:
            raise RuntimeError('test failure; private logs retained on VPNBotTest')
        checks = json.loads((results / 'summary.json').read_text())
        if set(checks) != REQUIRED or any(type(n) is not int or n <= 0 for n in checks.values()):
            raise ValueError('incomplete native test matrix')
        if identity != suite_identity(suite) or bundle != read(sys.argv[1]):
            raise ValueError('test inputs changed during the run')
        if bundle['source'] != command('git', 'rev-parse', 'HEAD'):
            raise ValueError('checkout changed during the run')
        evidence = dict(source=bundle['source'], bundle=fingerprint(bundle), suite=identity,
                        status='success', checks=sum(checks.values()))
        atomic(output, canonical(evidence))
        print('VPNBotTest:', evidence['checks'], 'checks passed; all required groups completed')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print('VPNBotTest admission rejected: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
