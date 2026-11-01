#!/usr/bin/env python3
"""Exercise the real bounded RPC with a root-owned large public ASN list."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys

def run(args, **kwargs):
    return subprocess.run(args, capture_output=True, timeout=30, **kwargs)

if run(['systemd-detect-virt', '--container']).stdout.strip() != b'docker':
    raise SystemExit('Disposable Docker host required')
sys.path.insert(0, '/lab/scripts')
import node_state as state
import node_config as config

path = Path('/etc/vpnbot-node/deployment.json')
before = path.read_bytes()
host = json.loads(before)
host['ssh_networks'] = [f'11.{n//256}.{n%256}.0/24' for n in range(6000)]
fd = os.open('/var/lib/vpnbot-node/lock', os.O_RDWR)
try:
    fcntl.flock(fd, fcntl.LOCK_EX)
    state.atomic(path, json.dumps(host).encode())
    fcntl.flock(fd, fcntl.LOCK_UN)
    result = run(['python3', '-I', '/usr/local/lib/vpnbot-node/node_manager.py', 'rpc'], input=b'{"action":"status"}')
    reply = json.loads(result.stdout)
    ok = result.returncode == 0 and reply.get('ok') is True and reply.get('result', {}).get('running') is True
    print(('PASS ' if ok else 'FAIL ')+'RPC remains available with 6000 public ASN networks', flush=True)
    store = state.Store('/var/lib/vpnbot-node')
    rules = 'delete table inet vpnbot_node\n'+config.firewall(store.load()['options'], host)
    syntax = run(['nft', '-c', '-f', '-'], input=rules.encode()).returncode == 0
    print(('PASS ' if syntax else 'FAIL ')+'full ASN firewall validates without applying to host', flush=True)
finally:
    fcntl.flock(fd, fcntl.LOCK_EX)
    state.atomic(path, before)
    os.close(fd)
raise SystemExit(0 if ok and syntax else 1)
