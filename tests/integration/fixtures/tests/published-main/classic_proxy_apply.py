#!/usr/bin/env python3
"""Mandatory real Shadowsocks credential failure/retry regression."""
from pathlib import Path
import json
import subprocess
import sys

ROOT = Path('/opt/vpnbot-hosted-ci/stand')
out = ROOT / 'results/classic-proxy-apply'
p = subprocess.run([sys.executable, str(ROOT.parent / 'classic-proxy/run.py'), '--source', str(ROOT / 'bot'), '--out', str(out)],
                   capture_output=True, timeout=420)
try:
    result = json.loads((out / 'results.json').read_text())
except (OSError, ValueError):
    result = {}
checks = result.get('checks', [])
ok = p.returncode == 0 and checks and all(row['ok'] for row in checks) and result.get('cleanup_confirmed') is True
print(json.dumps({'passed': sum(bool(r['ok']) for r in checks), 'total': len(checks), 'cleanup_confirmed': result.get('cleanup_confirmed', False)}))
raise SystemExit(0 if ok else 1)
