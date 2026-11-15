#!/usr/bin/env python3
"""Проверяет установщик на настоящих rsyslog/logrotate в отдельных namespace.

Хостовые конфигурации, журналы, /dev/log и kernel log не подключаются.
systemctl заменяется адаптером только для собственного процесса rsyslog.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('root required for isolated namespaces')
    for tool in ('unshare', 'mount', 'rsyslogd', 'logrotate', 'nft', 'logger', 'flock', 'bash'):
        if not shutil.which(tool):
            raise RuntimeError('missing test dependency: ' + tool)
    os.umask(0o077)
    repo = Path(__file__).resolve().parents[2]
    cases = ('root-owner', 'syslog-owner', 'writable-log-parent', 'writable-ancestor',
             'symlink-directory', 'validation-rollback', 'restart-rollback', 'history-rotation')
    result = {'passed': False, 'cases': [], 'source': {}}
    with tempfile.TemporaryDirectory(prefix='nft-logging-native-') as temporary:
        base = Path(temporary)
        (base/'source').mkdir()
        for name in ('install-nft-logging.sh', 'nft-log-verdicts.py'):
            source = repo/'nftables/logging'/name
            shutil.copyfile(source, base/'source'/name)
            result['source'][name] = hashlib.sha256(source.read_bytes()).hexdigest()
        for name in ('case.py', 'namespace.py', 'systemctl.py'):
            shutil.copyfile(repo/'tests/integration/nft-logging'/name, base/name)
            (base/name).chmod(0o755)
        parent = os.readlink('/proc/self/ns/net')
        for case in cases:
            root = base/('root-' + case)
            root.mkdir()
            command = ['unshare', '--mount', '--propagation', 'private', '--net', '--pid', '--fork',
                       '--mount-proc', '--kill-child=KILL', 'python3', '-B', str(base/'namespace.py'),
                       str(root), str(base), parent, case]
            completed = subprocess.run(command, capture_output=True, text=True, timeout=150)
            try:
                row = json.loads(completed.stdout)
            except ValueError:
                row = {'case': case, 'passed': False, 'error': 'namespace fixture did not return JSON'}
            row['exit'] = completed.returncode
            result['cases'].append(row)
    result['passed'] = all(row['passed'] and row['exit'] == 0 for row in result['cases'])
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'passed': result['passed'], 'cases': len(result['cases'])}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
