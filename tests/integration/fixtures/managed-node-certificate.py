#!/usr/bin/env python3
"""Certificate hostname checks on real OpenSSL without changing the running node."""
import json
from pathlib import Path
import subprocess
import sys

if subprocess.run(['systemd-detect-virt', '--container'], capture_output=True).stdout.strip() != b'docker':
    raise SystemExit('Run only in the disposable Docker test host')
sys.path.insert(0, '/lab/scripts')
import node_install as install
import node_runtime as runtime
import node_state as state

install.install_code('/lab/scripts')
store = state.Store('/var/lib/vpnbot-node')
backend = runtime.Runtime(store, state.decode((install.ETC/'deployment.json').read_bytes()))
directory = backend.prepare(store.current())
results = []
for domain, valid in [('node.example.test', True), ('wrong.example.test', False)]:
    try:
        backend.check_certificate(directory, domain)
        accepted = True
    except Exception:
        accepted = False
    ok = accepted == valid
    label = 'matching-certificate-accepted' if valid else 'wrong-certificate-hostname-rejected'
    results.append({'case': label, 'ok': ok})
    print(('PASS ' if ok else 'FAIL ')+label, flush=True)
Path('/run/node-certificate-results.json').write_text(json.dumps(results, indent=2))
raise SystemExit(0 if all(row['ok'] for row in results) else 1)
