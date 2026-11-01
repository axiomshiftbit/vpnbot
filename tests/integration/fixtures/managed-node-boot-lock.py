#!/usr/bin/env python3
"""Boot and the recovery timer must serialize on the actual systemd host."""
import fcntl
import os
import subprocess
import time


def run(args):
    return subprocess.run(args, capture_output=True, timeout=90)


if run(['systemd-detect-virt', '--container']).stdout.strip() != b'docker':
    raise SystemExit('Disposable Docker host required')
watch = run(['systemctl', 'is-active', '--quiet', 'vpnbot-node-watch.timer']).returncode == 0
fd = os.open('/var/lib/vpnbot-node/lock', os.O_RDWR | os.O_NOFOLLOW)
process = None
ok = False
try:
    run(['systemctl', 'stop', 'vpnbot-node-watch.timer', 'vpnbot-node-watch.service', 'vpnbot-node.service']).check_returncode()
    fcntl.flock(fd, fcntl.LOCK_EX)
    process = subprocess.Popen(['systemctl', 'start', 'vpnbot-node.service'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    waited = process.poll() is None
    print(('PASS ' if waited else 'FAIL ')+'boot waits for an existing state lock', flush=True)
    fcntl.flock(fd, fcntl.LOCK_UN)
    ok = process.wait(timeout=90) == 0 and waited
    print(('PASS ' if ok else 'FAIL ')+'boot becomes active after lock release', flush=True)
finally:
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)
    if process and process.poll() is None:
        process.wait(timeout=90)
    restored = run(['systemctl', 'start', 'vpnbot-node.service']).returncode == 0
    print(('PASS ' if restored else 'FAIL ')+'disposable node service restored', flush=True)
    if watch:
        run(['systemctl', 'start', 'vpnbot-node-watch.timer'])
raise SystemExit(0 if ok and restored else 1)
