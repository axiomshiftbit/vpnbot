#!/usr/bin/env python3
"""Mandatory native common-access revocation and unknown-quota regression."""
from pathlib import Path
import json
import subprocess
import sys

ROOT = Path('/opt/vpnbot-hosted-ci/stand')
out = ROOT / 'results/managed-sync-failure'
p = subprocess.run([sys.executable, str(ROOT.parent / 'managed-sync/run.py'), '--source', str(ROOT / 'bot'), '--out', str(out)],
                   capture_output=True, timeout=300)
try:
    result = json.loads((out / 'results.json').read_text())
except (OSError, ValueError):
    result = {}
checks = result.get('result', {}).get('checks', [])
ok = p.returncode == 0 and checks and all(row['passed'] for row in checks) and result.get('cleanup_confirmed') is True
print(json.dumps({'passed': sum(bool(r['passed']) for r in checks), 'total': len(checks), 'cleanup_confirmed': result.get('cleanup_confirmed', False)}))
raise SystemExit(0 if ok else 1)
