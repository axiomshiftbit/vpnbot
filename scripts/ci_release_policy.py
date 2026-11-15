#!/usr/bin/env python3
"""Explicit release exceptions and public, bounded evidence; never raw logs."""
import json
import os
from pathlib import Path
import re

FLAGS = {'allow_test_failures': 'CI_ALLOW_TEST_FAILURES',
         'allow_vulnerabilities': 'CI_ALLOW_VULNERABILITIES', 'allow_waivers': 'CI_ALLOW_WAIVERS'}
# Explicit presentation-only inventory. New tests and mixed protocol/security
# suites stay mandatory; a filename containing "menu" is not sufficient.
FUNCTIONAL_TESTS = frozenset(name+'_test.php' for name in (
    'audit_i18n', 'i18n_literals', 'version_parse'))


def stages():
    from image_bundle import IMAGES
    return {'components', 'security-assets', 'unit-host', 'unit-alpine84', 'unit-alpine85'} | {'security-'+name for name in IMAGES}


def validate_stage(stage):
    if not isinstance(stage, str) or stage not in stages() | {'native', 'security', 'master'}:
        raise ValueError('invalid admission stage')


def policy():
    values = {key: os.environ.get(variable, '0') for key, variable in FLAGS.items()}
    if any(value not in ('0', '1') for value in values.values()):
        raise ValueError('invalid release policy')
    return {key: value == '1' for key, value in values.items()}


def critical_test(name):
    return name not in FUNCTIONAL_TESTS


def warning(kind, name, count=1):
    row = dict(kind=kind, name=name, count=count)
    validate_warning(row)
    return row


def validate_warning(row):
    if not isinstance(row, dict) or set(row) != {'kind', 'name', 'count'} \
            or type(row['count']) is not int or not 1 <= row['count'] <= 100000:
        raise ValueError('invalid warning')
    name, kind = row['name'], row['kind']
    if not isinstance(name, str):
        raise ValueError('invalid warning name')
    if kind == 'test':
        if critical_test(name):
            raise ValueError('critical or unknown test cannot be waived')
    elif kind in ('vulnerability', 'waiver'):
        if not re.fullmatch(r'(CVE-\d{4}-\d{4,}|GHSA(?:-[a-z0-9]{4}){3})', name):
            raise ValueError('invalid advisory identifier')
    else:
        raise ValueError('invalid warning category')


def validate_warnings(rows, allowed):
    if not isinstance(rows, list) or len(rows) > 4096:
        raise ValueError('invalid warning list')
    for row in rows:
        validate_warning(row)
        flag = {'test': 'allow_test_failures', 'vulnerability': 'allow_vulnerabilities', 'waiver': 'allow_waivers'}[row['kind']]
        if allowed.get(flag) is not True:
            raise ValueError('release exception was not explicitly allowed')
        if row['kind'] == 'waiver':
            import ci_waivers
            if not any(entry['id'] == row['name'] and entry['active'] for entry in ci_waivers.load()):
                raise ValueError('release waiver expired or was removed')
    return rows


def announce(rows, stage):
    validate_stage(stage)
    for row in rows:
        validate_warning(row)
        text = 'Допуск с предупреждением: '+stage+' / '+row['kind']+' / '+row['name']+'; количество: '+str(row['count'])
        print('::warning::'+text if os.environ.get('GITHUB_ACTIONS') == 'true' else text)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
            stream.write('\n### Допуск: '+stage+'\n\n')
            if not rows:
                stream.write('Пропущенных ошибок нет.\n')
            for row in rows:
                stream.write('- '+row['kind']+': `'+row['name']+'` ('+str(row['count'])+').\n')


def write_report(stage, rows, checks, path=None):
    validate_stage(stage)
    if type(checks) is not int or checks < 1:
        raise ValueError('incomplete admission checks')
    rows = validate_warnings(rows, policy())
    value = dict(schema=1, source=os.environ['GITHUB_SHA'], run=int(os.environ['GITHUB_RUN_ID']),
                 attempt=int(os.environ['GITHUB_RUN_ATTEMPT']), stage=stage, policy=policy(), warnings=rows, checks=checks)
    destination = Path(path or os.environ['CI_REPORT_FILE'])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(value, sort_keys=True)+'\n')
    destination.chmod(0o644)  # Public IDs only; container/root writes, runner uploads.
    announce(rows, stage)
    return value


def collect(directory, bundle, native, stages):
    """All expected reports are mandatory, including clean scans and tests."""
    # Rerun-failed preserves a successful bundle job from an earlier attempt.
    # Repeated security/tests jobs may therefore be newer than bundle.attempt.
    attempt = int(os.environ['GITHUB_RUN_ATTEMPT'])
    if attempt < bundle['attempt'] or int(os.environ['GITHUB_RUN_ID']) != bundle['run'] \
            or os.environ['GITHUB_SHA'] != bundle['source']:
        raise ValueError('admission belongs to another workflow run')
    files = list(Path(directory).glob('*.json'))
    if {p.stem for p in files} != set(stages):
        raise ValueError('missing or extra admission reports')
    warnings = []
    for path in sorted(files):
        value = json.loads(path.read_text())
        if not isinstance(value, dict) or set(value) != {'schema', 'source', 'run', 'attempt', 'stage', 'policy', 'warnings', 'checks'} \
                or type(value['schema']) is not int or value['schema'] != 1 \
                or value['source'] != bundle['source'] or type(value['run']) is not int or value['run'] != bundle['run'] \
                or type(value['attempt']) is not int or not 1 <= value['attempt'] <= attempt \
                or value['stage'] != path.stem or not isinstance(value['policy'], dict) \
                or any(type(v) is not bool for v in value['policy'].values()) or value['policy'] != policy() \
                or type(value['checks']) is not int or value['checks'] < 1:
            raise ValueError('invalid admission report')
        rows = validate_warnings(value['warnings'], policy())
        warnings.extend(dict(row, stage=path.stem) for row in rows)
    rows = validate_warnings(native.get('warnings', []), policy())
    warnings.extend(dict(row, stage='native') for row in rows)
    from image_bundle import fingerprint
    proof = dict(schema=1, source=bundle['source'], bundle=fingerprint(bundle), policy=policy(), warnings=warnings)
    validate_proof(proof, bundle, policy())
    return proof


def validate_proof(proof, bundle, allowed):
    from image_bundle import fingerprint
    if not isinstance(proof, dict) or set(proof) != {'schema', 'source', 'bundle', 'policy', 'warnings'} \
            or type(proof['schema']) is not int or proof['schema'] != 1 \
            or proof['source'] != bundle['source'] or proof['bundle'] != fingerprint(bundle) \
            or not isinstance(proof['policy'], dict) or set(proof['policy']) != set(FLAGS) \
            or any(type(v) is not bool for v in proof['policy'].values()) \
            or not isinstance(proof['warnings'], list) or len(proof['warnings']) > 100000:
        raise ValueError('invalid release admission proof')
    for item in proof['warnings']:
        if not isinstance(item, dict) or set(item) != {'stage', 'kind', 'name', 'count'}:
            raise ValueError('invalid release warning')
        validate_stage(item['stage'])
        row = {k: v for k, v in item.items() if k != 'stage'}
        validate_warnings([row], proof['policy'])
        validate_warnings([row], allowed)
    return proof
