#!/usr/bin/env python3
"""Полные nft-профили в одноразовых namespace; firewall и файлы хоста не меняются."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--report', type=Path, required=True)
args = parser.parse_args()
if os.geteuid() != 0:
    raise SystemExit('Требуется root для создания изолированного стенда')
root = Path(__file__).resolve().parents[2]
fixtures = Path(__file__).resolve().parent / 'nft-security'
for command in ('nft', 'ip', 'nsenter', 'unshare', 'mount'):
    if not shutil.which(command):
        raise SystemExit('Не найдена команда: ' + command)
with tempfile.TemporaryDirectory(prefix='vpnbot-nft-security-') as directory:
    work = Path(directory)
    source = work / 'source'
    source.mkdir()
    manifest = {}
    # Не монтируем .env, конфиги приложения, Docker socket или данные сервера.
    paths = [root/'nftables/nftables.conf', root/'nftables/noda.conf', *sorted((root/'scripts').glob('*.py'))]
    for path in paths:
        name = path.relative_to(root)
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        manifest[str(name)] = hashlib.sha256(target.read_bytes()).hexdigest()
    for name in ('namespace.py', 'packets.py'):
        shutil.copyfile(fixtures/name, work/name)
    jail = work/'root-sandbox'
    jail.mkdir()
    command = ['unshare', '--mount', '--propagation', 'private', '--net', '--pid', '--fork',
               '--mount-proc', '--kill-child=KILL', 'python3', str(work/'namespace.py'),
               str(jail), str(source), str(work), os.readlink('/proc/self/ns/net')]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=180)
        report = json.loads(result.stdout)
        report['exit'] = result.returncode
        report['source'] = manifest
        if result.stderr:
            # Здесь только собственные синтетические fixtures; содержимое
            # конфигурации сервера никогда не передаётся в namespace.
            report['harness_error'] = result.stderr[-3000:]
    except subprocess.TimeoutExpired:
        report = {'passed': False, 'exit': 124, 'error': 'Превышено время изолированного теста'}
    except (ValueError, OSError):
        report = {'passed': False, 'exit': 1, 'error': 'Стенд не вернул полный результат'}
args.report.parent.mkdir(parents=True, exist_ok=True)
args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
print('nftables: случаев', len(report.get('cases', [])), '; результат', 'PASS' if report.get('passed') and report['exit'] == 0 else 'FAIL')
raise SystemExit(0 if report.get('passed') and report['exit'] == 0 else 1)
