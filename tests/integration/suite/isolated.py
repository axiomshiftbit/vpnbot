#!/usr/bin/env python3
"""Self-contained native suites on their own runner; no stand, same checks.

ci_hosted_test.py prepares /opt/vpnbot-hosted-ci (fixtures, client tools,
candidate xray) and runs this with a cleared environment. Raw logs stay in the
results directory on the disposable runner; only counters leave it.
"""
from pathlib import Path
import argparse, importlib.util, json, os, signal, subprocess, sys

os.umask(0o077)
p = argparse.ArgumentParser()
p.add_argument('--checkout', type=Path, required=True)
p.add_argument('--manifest', type=Path, required=True)
p.add_argument('--results', type=Path, required=True)
p.add_argument('--cases', required=True)
a = p.parse_args()
sys.path.insert(0, str(a.checkout / 'scripts'))
import image_bundle as ib  # noqa: E402

spec = importlib.util.spec_from_file_location('isolated_cases', Path(__file__).with_name('isolated_cases.py'))
isolated = importlib.util.module_from_spec(spec)
spec.loader.exec_module(isolated)
cases = a.cases.split(',')
if not cases or len(set(cases)) != len(cases) or not set(cases) <= set(isolated.CASES):
    raise ValueError('unknown or repeated isolated native case')
candidate = ib.read(a.manifest)
O = a.results
env = {k: os.environ[k] for k in ('PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR') if k in os.environ}
counts = dict.fromkeys(('unit', 'native', 'modules', 'backup_restore', 'update_rollback', 'faults', 'telegram_http'), 0)
retries = []


def interrupted(signum, frame):
    raise InterruptedError('test interrupted')


signal.signal(signal.SIGTERM, interrupted)


def run(name, cmd, timeout=180):
    print('START ' + name, flush=True)
    with (O / (name + '.log')).open('wb') as out:
        q = subprocess.run(cmd, cwd=isolated.ROOT, env=env, stdout=out, stderr=subprocess.STDOUT, timeout=timeout)
    if q.returncode:
        raise RuntimeError(name + ' exit ' + str(q.returncode))
    return q.returncode


def check(group, name, ok):
    print(('PASS ' if ok else 'FAIL ') + name, flush=True)
    if not ok:
        raise RuntimeError(name)
    counts[group] += 1
    (O / 'partial.json').write_text(json.dumps(counts))


def twice(name, attempt):
    # Same policy as run.py: one retry of a self-contained suite, no retry of a timeout.
    try:
        return attempt()
    except RuntimeError as error:
        print('RETRY ' + name + ': ' + str(error), flush=True)
    if (O / (name + '.log')).exists():
        (O / (name + '.log')).replace(O / (name + '.attempt1.log'))
    retries.append(name)
    (O / 'retries.json').write_text(json.dumps(retries))
    return attempt()


ctx = dict(candidate=candidate, checkout=a.checkout, results=O, run=run, check=check, counts=counts, twice=twice)
for name in cases:
    isolated.run_case(name, ctx)
(O / 'summary.json').write_text(json.dumps(counts, indent=2))
(O / 'warnings.json').write_text('[]')
print(json.dumps(counts), flush=True)
