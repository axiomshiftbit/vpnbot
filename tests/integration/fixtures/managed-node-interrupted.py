#!/usr/bin/env python3
"""Kill a real systemd maintenance job; the node must remain manageable."""
import json
from pathlib import Path
import subprocess
import sys
import time

if subprocess.run(['systemd-detect-virt', '--container'], capture_output=True).stdout.strip() != b'docker':
    raise SystemExit('Run only in the disposable Docker test host')
sys.path.insert(0, '/lab/scripts')
import node_install as install
import node_manager as manager
import node_runtime as runtime
import node_state as state

results = []


def run(args):
    return subprocess.run(args, capture_output=True, timeout=20)


def check(label, ok):
    results.append({'case': label, 'ok': bool(ok)})
    print(('PASS ' if ok else 'FAIL ') + label, flush=True)
    if not ok:
        raise AssertionError(label)


override = Path('/etc/systemd/system/vpnbot-node-worker.service.d/fixture.conf')
try:
    install.install_code('/lab/scripts')
    store = state.Store('/var/lib/vpnbot-node')
    host = state.decode((install.ETC/'deployment.json').read_bytes())
    control = manager.Manager(store, runtime.Runtime(store, host))
    run(['systemctl', 'start', 'vpnbot-node-watch.service']).check_returncode()
    override.parent.mkdir(exist_ok=True)
    override.write_text('[Service]\nExecStartPre=/usr/bin/sleep 300\n')
    run(['systemctl', 'daemon-reload']).check_returncode()
    job = control.submit({'operation': 'restart', 'value': None})
    time.sleep(2)
    check('real-worker-starting', run(['systemctl', 'show', '-p', 'ActiveState', '--value',
                                     'vpnbot-node-worker.service']).stdout.strip() == b'activating')
    run(['systemctl', 'kill', '--signal=SIGKILL', 'vpnbot-node-worker.service']).check_returncode()
    override.unlink()
    run(['systemctl', 'daemon-reload']).check_returncode()
    # Permit the queue grace period used to distinguish scheduling from a lost job.
    time.sleep(32)
    run(['systemctl', 'start', 'vpnbot-node-watch.service']).check_returncode()
    check('watchdog-marks-interrupted-job-failed', control.rpc({'action': 'job', 'id': job['job']})['state'] == 'failed')
    next_job = control.submit({'operation': 'restart', 'value': None})
    for _ in range(60):
        status = control.rpc({'action': 'job', 'id': next_job['job']})
        if status['state'] not in ('queued', 'running'):
            break
        time.sleep(.5)
    check('next-operation-works-without-reboot', status['state'] == 'done')
finally:
    override.unlink(missing_ok=True)
    run(['systemctl', 'daemon-reload'])
    Path('/run/node-interrupted-results.json').write_text(json.dumps(results, indent=2))
