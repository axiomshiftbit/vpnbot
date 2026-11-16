"""Self-contained native suites: own containers, candidate images, checkout only.

They need no running stand: run.py executes them inside the full stand (one
machine, e.g. the home runner) and isolated.py on separate GitHub runners.
Both use these definitions, so the checks and their counts cannot drift apart.
"""
import json
from pathlib import Path

ROOT = Path('/opt/vpnbot-hosted-ci')
# Order of the former sequential run.
CASES = ('backup-node-cold', 'naive-upgrade', 'mieru-idle', 'ocserv-upgrade',
         'telemt-native', 'masque-native', 'hysteria-native', 'snolc-native')
NATIVE_MINI = ('telemt-native', 'masque-native', 'hysteria-native', 'snolc-native')
CLIENT_IMAGE = 'vpnbot-hosted-clients:current'


def run_case(name, ctx):
    """ctx: candidate, checkout, results, run, check, counts, twice."""
    images, out = ctx['candidate']['images'], ctx['results']
    run, check, counts, twice = ctx['run'], ctx['check'], ctx['counts'], ctx['twice']
    if name == 'backup-node-cold':
        script = ctx['checkout'] / 'tests/integration/fixtures/backup-protocols-native/node-cold.py'
        output = out / name
        run(name, ['python3', str(script), '--out', str(output), '--source', str(ctx['checkout']),
                   '--php-image', images['php'], '--xray-image', images['xr'], '--ng-image', images['ng']],
            timeout=1800)
        result = json.loads((output / 'results.json').read_text())
        rows = result['checks']
        check('backup_restore', name + '-complete', not result['error'] and len(rows) >= 30
              and all(r['passed'] for r in rows) and result.get('cleanup') is True)
        counts['backup_restore'] += len(rows)
    elif name == 'naive-upgrade':
        run(name, ['python3', str(ROOT / 'naive-upgrade/run.py'), images['np'], images['php'],
                   str(ROOT / 'stand/bin/naive'), str(out / 'naive-upgrade')], timeout=180)
        rows = json.loads((out / 'naive-upgrade/results.json').read_text())
        check('native', 'Naive-H2-H3-auth-idle', len(rows) == 15 and all(x['passed'] for x in rows))
        counts['native'] += len(rows)
    elif name == 'mieru-idle':
        run(name, ['python3', str(ROOT / 'mieru-idle/run.py'), str(ctx['checkout']), images['mieru'], images['php'],
                   str(ROOT / 'stand/bin/mieru-previous'), str(out / 'mieru-idle')], timeout=150)
        rows = json.loads((out / 'mieru-idle/results.json').read_text())
        check('native', 'Mieru-idle-old-client', len(rows) == 9 and all(x['passed'] for x in rows))
        counts['native'] += len(rows)
    elif name == 'ocserv-upgrade':
        run(name, ['python3', str(ROOT / 'ocserv-upgrade/run.py'), images['oc'], CLIENT_IMAGE,
                   str(out / 'ocserv-upgrade')], timeout=240)
        rows = json.loads((out / 'ocserv-upgrade/results.json').read_text())
        check('native', 'ocserv-TLS13-DTLS-strict-config', len(rows) == 15 and all(x['passed'] for x in rows))
        counts['native'] += len(rows)
    elif name in NATIVE_MINI:
        extra = {'telemt-native': [images['telemt'], images['php'], images['ng']],
                 'masque-native': [images['masque'], images['php'], str(ROOT / 'tests/xray')],
                 'hysteria-native': [images['hysteria'], images['php']],
                 'snolc-native': [images['snolc'], images['php']]}[name]

        def attempt():
            result = ROOT / name / 'results.json'
            result.unlink(missing_ok=True)
            run(name, ['python3', str(result.with_name('run.py')), str(ctx['checkout']), *extra], timeout=1500)
            rows = json.loads(result.read_text())
            check('native', name + '-complete', bool(rows) and all(
                x['exit'] == 0 and x['total'] > 0 and x['passed'] == x['total'] for x in rows))
            counts['native'] += sum(x['total'] for x in rows)
            (out / (name + '.json')).write_bytes(result.read_bytes())
        twice(name, attempt)
    else:
        raise ValueError('unknown isolated native case')
