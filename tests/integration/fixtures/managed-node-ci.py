#!/usr/bin/env python3
"""Test managed nodes with the exact candidate image binaries in isolated nets."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile

os.umask(0o077)
parser = argparse.ArgumentParser()
parser.add_argument('results', type=Path)
parser.add_argument('checkout', type=Path)
parser.add_argument('--manifest', type=Path, default=os.environ.get('VPNBOT_BUNDLE_FILE'))
args = parser.parse_args()
if os.geteuid() != 0 or not args.manifest:
    raise SystemExit('Root and the candidate image manifest are required')
args.results.mkdir(parents=True, exist_ok=True)
private = args.results/'private'
private.mkdir(mode=0o700, exist_ok=True)
images = json.loads(args.manifest.read_bytes())['images']
source = args.checkout.resolve()
fixtures = source/'tests/integration/fixtures'
environment = {k: os.environ[k] for k in ('PATH', 'HOME', 'LANG') if k in os.environ}
rows = []
container = 'vpnbot-ci-node-core-extract'


def command(argv, **kwargs):
    result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=90, env=environment, **kwargs)
    if result.returncode:
        raise RuntimeError('candidate node fixture command failed: '+str(argv[0]))
    return result.stdout


try:
    with tempfile.TemporaryDirectory(prefix='node-core-', dir=private) as temporary:
        cores = Path(temporary)
        command(['docker', 'create', '--name', container, '--entrypoint', '/bin/true', images['xr']])
        for name, binary in [('x31', 'xray'), ('origin2', 'xray-2'), ('origin3', 'xray-3'),
                             ('fork', 'xray-smux'), ('wireproxy', 'wireproxy-node')]:
            command(['docker', 'cp', container+':/usr/bin/'+binary, cores/name])
            (cores/name).chmod(0o755)
        command(['docker', 'rm', container])
        rules = cores/'freedom.json'
        rules.write_bytes(command(['docker', 'run', '--rm', '--network', 'none', '--cap-drop', 'ALL',
                                  '--entrypoint', 'php', '-v', str(source)+':/src:ro', images['php'],
                                  '/src/tests/integration/fixtures/freedom-guard-profile.php']))
        environment.update(NODE_SOURCE_DIR=str(source), CORE_TEST_DIR=str(cores),
                           AWG_PROXY=str(cores/'wireproxy'), FREEDOM_RULES=str(rules), NODE_ADVANCED_CASES='1')
        for name in ('native', 'wg-native', 'awg-native', 'dns-guard', 'firewall'):
            print('START managed-node-'+name, flush=True)
            environment['NODE_RESULTS_FILE'] = str(private/(name+'.json'))
            log = private/(name+'.log')
            with log.open('wb') as stream:
                process = subprocess.Popen(['unshare', '--net', sys.executable, str(fixtures/('managed-node-'+name+'.py'))],
                                           stdout=stream, stderr=subprocess.STDOUT, env=environment, start_new_session=True)
                try:
                    status = process.wait(timeout=900)
                except BaseException:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    raise
            checks = []
            for line in log.read_text(errors='replace').splitlines():
                if line.startswith(('PASS ', 'FAIL ')) and not re.match(r'^PASS [0-9]+ .*checks$', line):
                    checks.append({'name': name+': '+line[5:], 'passed': line.startswith('PASS ')})
            rows.extend(checks)
            (args.results/'results.json').write_text(json.dumps(rows, indent=2))
            if status or not checks or any(not row['passed'] for row in checks):
                raise RuntimeError('managed-node-'+name+' failed; private diagnostics retained on test host')
            print('PASS managed-node-'+name+' '+str(len(checks))+' checks', flush=True)
finally:
    subprocess.run(['docker', 'rm', '-f', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, env=environment)
