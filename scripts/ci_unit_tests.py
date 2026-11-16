#!/usr/bin/env python3
"""Run functional PHP tests, retaining safe failure IDs and strict core checks."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

import ci_release_policy as release


def run(root, directory, allow=False):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    files = sorted((root/'tests').glob('*_test.php'))
    if len(files) < 100:
        raise ValueError('PHP test inventory is incomplete')
    warnings, blocked = [], []
    for path in files:
        try:
            result = subprocess.run(['php', '-d', 'error_reporting=32767', '-d', 'error_log=/dev/stderr',
                                     '-d', 'display_errors=1', str(path)], cwd=root, capture_output=True, timeout=150)
        except subprocess.TimeoutExpired:
            blocked.append(path.name)
            print('BLOCK timeout '+path.name, flush=True)
            continue
        output = result.stdout+result.stderr
        bad = result.returncode != 0 or bool(re.search(rb'(?:PHP )?(?:Warning|Deprecated|Fatal error):', output))
        # CI provides every core, extension and tool these tests ask for: a test
        # that reports SKIP there did not run and cannot count as passed.
        if os.environ.get('GITHUB_ACTIONS') == 'true' and re.search(rb'(?m)^[\w.-]+:? SKIP\b', output):
            bad = True
        if bad:
            log = directory/(path.stem+'.log')
            log.write_bytes(output); log.chmod(0o600)
            if allow and result.returncode in (0, 1, 255) and not release.critical_test(path.name):
                warnings.append(release.warning('test', path.name))
                print('WARNING '+path.name, flush=True)
            else:
                blocked.append(path.name)
                print('BLOCK '+path.name, flush=True)
        else:
            print('PASS '+path.name, flush=True)
    return dict(checks=len(files), warnings=warnings, blocked=blocked)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--stage', required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--local-result', action='store_true')
    args = parser.parse_args()
    release.validate_stage(args.stage)
    result = run(Path.cwd(), args.report.parent/(args.stage+'-private-logs'), release.policy()['allow_test_failures'])
    if args.local_result:
        args.report.write_text(json.dumps(result)+'\n')
    elif not result['blocked']:
        release.write_report(args.stage, result['warnings'], result['checks'], args.report)
    return bool(result['blocked'])


if __name__ == '__main__':
    raise SystemExit(main())
