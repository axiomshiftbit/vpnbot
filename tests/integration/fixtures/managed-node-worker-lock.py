#!/usr/bin/env python3
"""A scheduled worker must survive the submitting RPC still owning the lock."""
import fcntl
import os
from pathlib import Path
import subprocess
import sys
import time

def run(args):
    return subprocess.run(args, capture_output=True, timeout=30)

if run(['systemd-detect-virt', '--container']).stdout.strip() != b'docker':
    raise SystemExit('Disposable Docker host required')
sys.path.insert(0, '/lab/scripts')
import node_manager as manager
import node_runtime as runtime
import node_state as state

store = state.Store('/var/lib/vpnbot-node')
host = state.decode(Path('/etc/vpnbot-node/deployment.json').read_bytes())
watch = run(['systemctl', 'is-active', '--quiet', 'vpnbot-node-watch.timer']).returncode == 0
saved = {name: (store.root/name).read_bytes() if (store.root/name).exists() else None for name in ('job.json', 'request.json')}
fd = os.open(store.root/'lock', os.O_RDWR)
try:
    run(['systemctl', 'stop', 'vpnbot-node-watch.timer'])
    run(['systemctl', 'reset-failed', 'vpnbot-node-worker.service'])
    fcntl.flock(fd, fcntl.LOCK_EX)
    control = manager.Manager(store, runtime.Runtime(store, host))
    control.submit({'operation': 'restart', 'value': None})
    # Model a slow SSH response after submit(): the worker has already started,
    # but the submitting RPC releases this lock only when its response is sent.
    time.sleep(1)
    fcntl.flock(fd, fcntl.LOCK_UN)
    done = False
    for _ in range(120):
        job = store.read('job.json') or {}
        if job.get('state') == 'done':
            done = True
            break
        if run(['systemctl', 'is-failed', '--quiet', 'vpnbot-node-worker.service']).returncode == 0:
            break
        time.sleep(.25)
    print(('PASS ' if done else 'FAIL ')+'scheduled worker waits for submitting RPC lock', flush=True)
finally:
    fcntl.flock(fd, fcntl.LOCK_UN)
    run(['systemctl', 'stop', 'vpnbot-node-worker.service'])
    fcntl.flock(fd, fcntl.LOCK_EX)
    for name, body in saved.items():
        if body is None:
            (store.root/name).unlink(missing_ok=True)
        else:
            state.atomic(store.root/name, body)
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)
    if watch:
        run(['systemctl', 'start', 'vpnbot-node-watch.timer'])
raise SystemExit(0 if done else 1)
