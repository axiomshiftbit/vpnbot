#!/usr/bin/env python3
"""Ephemeral GitHub VM tests. Only synthetic state; publish identifiers only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

import ci_retry
from ci_retry import retrying
from image_bundle import BUNDLE_REPO, atomic, canonical, command, fingerprint, read


def network(*args):
    return retrying(command, *args)

ROOT = Path('/opt/vpnbot-hosted-ci')
GROUPS = {'unit', 'native', 'modules', 'backup_restore', 'update_rollback', 'faults', 'telegram_http'}
CLIENT_IMAGE = 'vpnbot-hosted-clients:current'


def client_downloads(destination):
    # Public upstream releases; pinned archives, no copied VPS executables.
    releases = [
        ('https://github.com/klzgrad/naiveproxy/releases/download/v154.0.8037.49-2/naiveproxy-v154.0.8037.49-2-linux-x64.tar.xz',
         '4823f654b1a3856efefa6980a97997b6c5153a693e4a4541a9a10e03d7e7d9e3', {'naive': 'naive'}),
        ('https://github.com/TrustTunnel/TrustTunnelClient/releases/download/v1.1.7/trusttunnel_client-v1.1.7-linux-x86_64.tar.gz',
         '791f00819e0242b2c38a04bb1403c30aa32701efbcdb059fbc3a6793ff0a45b5',
         {'trusttunnel_client': 'trusttunnel', 'setup_wizard': 'setup_wizard'}),
    ]
    destination.mkdir(mode=0o700)
    for url, digest, names in releases:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'client.tar'
            retrying(urllib.request.urlretrieve, url, archive, errors=(OSError,))
            if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
                raise ValueError('client archive checksum mismatch')
            with tarfile.open(archive) as tar:
                for name, target in names.items():
                    members = [m for m in tar.getmembers() if m.isfile() and Path(m.name).name == name]
                    if len(members) != 1:
                        raise ValueError('unexpected client archive layout')
                    # No extractall: ignore config.json, links and archive paths.
                    (destination / target).write_bytes(tar.extractfile(members[0]).read())
                    (destination / target).chmod(0o700)


def identity(checkout):
    digest = hashlib.sha256()
    for p in sorted((checkout / 'tests/integration').rglob('*')):
        if p.is_file() and '__pycache__' not in p.parts:
            digest.update(str(p.relative_to(checkout)).encode() + b'\0' + p.read_bytes())
    return digest.hexdigest()


def evidence(bundle, checks, suite):
    if set(checks) != GROUPS or any(type(n) is not int or n <= 0 for n in checks.values()):
        raise ValueError('incomplete native matrix')
    return dict(source=bundle['source'], bundle=fingerprint(bundle), suite=suite,
                status='success', checks=sum(checks.values()))


def failed_protocols(checkout):
    """Only reviewed test names may enter the public failure log."""
    results = ROOT / 'tests/published-main/results.json'
    if not results.is_file():
        return []
    try:
        rows = json.loads(results.read_text())
    except (OSError, ValueError):
        return []
    allowed = {p.stem for p in (checkout / 'tests/integration/fixtures/tests/published-main').glob('*.py')}
    if not isinstance(rows, list):
        return []
    return sorted({r['case'] for r in rows if isinstance(r, dict)
                   and isinstance(r.get('case'), str) and r['case'] in allowed
                   and (r.get('exit') == 'timeout' or type(r.get('exit')) is int and r['exit'] != 0)})


def retried_suites(results):
    """Наборы стенда, прошедшие со второй попытки; в журнал — только имена наборов."""
    try:
        names = json.loads((results / 'retries.json').read_text())
    except (OSError, ValueError):
        return []
    if not isinstance(names, list):
        return []
    return [n for n in names if isinstance(n, str) and re.fullmatch(r'[a-z0-9_-]{1,40}(/[a-z0-9_-]{1,40})?', n)]


def host(local):
    if local:
        if Path('/etc/vpnbot-ci-test-host').read_text().strip() != 'home-build':
            raise ValueError('local proof requires the designated disposable test host')
    elif not (os.environ.get('GITHUB_ACTIONS') == 'true'
              and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'):
        raise ValueError('a fresh GitHub-hosted VM is required')


def rollback_reference(branch):
    channel = 'dev' if branch == 'dev' else 'latest'
    ref = BUNDLE_REPO + ':bundle-' + channel
    # Сбой сети повторяем; «манифеста нет» — окончательный ответ реестра.
    for delay in (*ci_retry.DELAYS, None):
        probe = subprocess.run(['docker', 'manifest', 'inspect', ref], capture_output=True,
                               text=True, timeout=90)
        if probe.returncode == 0:
            return ref
        if delay is None or re.search(r'\b(?:manifest unknown|no such manifest)\b', probe.stderr, re.I):
            break
        time.sleep(delay)
    # The first master publication has no stable bundle yet. Use a previously
    # admitted dev release, never the untested candidate. An authentication or
    # network error must not silently select a different rollback release.
    if channel == 'latest' and re.search(r'\b(?:manifest unknown|no such manifest)\b', probe.stderr, re.I):
        print('First stable publication: rollback uses the admitted dev bundle')
        return BUNDLE_REPO + ':bundle-dev'
    raise RuntimeError('cannot resolve the previous admitted release')


def assets(checkout, manifest):
    bundle = read(manifest)
    for image in bundle['images'].values():
        network('docker', 'pull', image)
    # The former complete release is a rollback input, never an admission report.
    # It may lack the snolc image (image_bundle.ABSENT_BEFORE).
    ref = rollback_reference(os.environ.get('GITHUB_REF_NAME'))
    network('docker', 'pull', ref)
    image = command('docker', 'image', 'inspect', '--format', '{{.Id}}', ref)
    container = command('docker', 'create', '--network', 'none', image, '/bundle.json')
    try:
        with tempfile.TemporaryDirectory() as directory:
            previous = Path(directory) / 'bundle.json'
            command('docker', 'cp', container + ':/bundle.json', str(previous))
            previous = read(previous, previous=True)
    finally:
        command('docker', 'rm', container)
    # The pair changes together; current protocol data is never replaced by an
    # old backup during rollback. No mutable tag is used to select these images.
    atomic(manifest.with_name('rollback-bundle.json'), canonical(previous))
    previous = {name: previous['images'][name] for name in ('php', 'ng')}
    for image in previous.values():
        network('docker', 'pull', image)
    atomic(manifest.with_name('rollback-images.json'), canonical(previous))
    values = dict(line.split('=', 1) for line in (checkout / '.env').read_text().splitlines()
                  if line and not line.startswith('#') and '=' in line)
    args = ['docker', 'build', '--pull', '-t', CLIENT_IMAGE, '-f', str(checkout / 'tests/integration/clients.dockerfile')]
    inputs = {name.upper() + '_IMAGE': bundle['images'][name] for name in ('wg', 'php', 'ss', 'ipsec')}
    inputs['GO_IMAGE'] = 'golang:' + values['PROTOCOL_GO_VERSION'] + '-alpine'
    inputs.update({name: values[name] for name in ('MIERU_VERSION', 'MIERU_SOURCE_SHA256', 'DNSTT_REF',
                                                'SINGBOX_VERSION', 'SINGBOX_SHA256')})
    for name, value in inputs.items():
        args += ['--build-arg', name + '=' + value]
    # This context contains test code only, never the checkout's .git or state.
    args.append(str(checkout / 'tests/integration'))
    # Сборка скачивает базовые образы и исходники клиентов: сетевой сбой — не
    # повод перезапускать всё задание.
    retrying(lambda: subprocess.run(args, check=True, timeout=1200), errors=(subprocess.CalledProcessError,))
    client_downloads(manifest.with_name('client-tools'))
    print('Candidate images, rollback pair and disposable clients prepared')


def test(checkout, manifest, output):
    if os.geteuid() != 0:
        raise ValueError('network namespace tests require root on the disposable VM')
    if ROOT.exists():
        raise ValueError('an old test directory exists; refusing to reuse state')
    bundle = read(manifest)
    if command('git', '-c', 'safe.directory=' + str(checkout), '-C', str(checkout), 'rev-parse', 'HEAD') != bundle['source']:
        raise ValueError('candidate does not match checkout')
    output.unlink(missing_ok=True)
    suite = identity(checkout)
    ROOT.mkdir(mode=0o700)
    (ROOT / 'home').mkdir(mode=0o700)
    (ROOT / 'owner').write_text('vpnbot-hosted-ci\n')
    sys.path.insert(0, str(checkout / 'tests/integration'))
    import bootstrap
    # Whitelist, rather than blacklist: Actions runtime/registry credentials and
    # SSH_AUTH_SOCK must not be inherited by the stand or test subprocesses.
    os.environ.clear()
    os.environ.update(bootstrap.ENV)
    command('git', 'config', '--global', '--add', 'safe.directory', str(checkout))
    baseline = json.loads(manifest.with_name('rollback-images.json').read_text())
    atomic(ROOT / 'rollback-images.json', canonical(baseline))
    previous = read(manifest.with_name('rollback-bundle.json'), previous=True)
    atomic(ROOT / 'rollback-bundle.json', canonical(previous))
    results = ROOT / 'results'
    results.mkdir(mode=0o700)
    with (ROOT / 'private.log').open('wb') as log:
        # Redirect Python and child process output, including tracebacks, away
        # from the Actions log. The public result is an allowlist of counters.
        original_out, original_err = os.dup(1), os.dup(2)
        try:
            sys.stdout.flush(); sys.stderr.flush()
            os.dup2(log.fileno(), 1); os.dup2(log.fileno(), 2)
            shutil.copytree(manifest.with_name('client-tools'), ROOT / 'stand/bin')
            bootstrap.bootstrap(checkout, bundle, CLIENT_IMAGE)
            run = subprocess.run([sys.executable, str(ROOT / 'suite/run.py'), '--checkout', str(checkout),
                                  '--manifest', str(manifest), '--results', str(results)], timeout=9000)
        finally:
            sys.stdout.flush(); sys.stderr.flush()
            os.dup2(original_out, 1); os.dup2(original_err, 2)
            os.close(original_out); os.close(original_err)
    if run.returncode:
        raise RuntimeError('ephemeral VPN matrix failed')
    checks = json.loads((results / 'summary.json').read_text())
    result = evidence(bundle, checks, suite)
    if identity(checkout) != suite or bundle != read(manifest):
        raise ValueError('test inputs changed')
    if command('git', '-C', str(checkout), 'rev-parse', 'HEAD') != bundle['source']:
        raise ValueError('checkout changed during tests')
    atomic(output, canonical(result))
    output.chmod(0o644)  # Only public identifiers; uploader runs without sudo.
    print('Ephemeral VPN stand: all required groups passed; checks:', result['checks'])
    retried = retried_suites(results)
    if retried:
        print('Passed on the second attempt:', ', '.join(retried))


def cleanup():
    if not (ROOT / 'owner').is_file() or (ROOT / 'owner').read_text() != 'vpnbot-hosted-ci\n':
        raise ValueError('refusing to clean an unowned directory')
    bot = ROOT / 'stand/bot'
    if (bot / 'scripts/stop_update.sh').is_file():
        subprocess.run(['sh', 'scripts/stop_update.sh', 'update/update_pid'], cwd=bot, capture_output=True)
    # Cleanup only the disposable installation/clients, never a global prune.
    ids = command('docker', 'ps', '-aq').split()
    for ident in ids:
        data = json.loads(command('docker', 'inspect', ident))[0]
        labels = data['Config'].get('Labels') or {}
        name = data['Name'].removeprefix('/')
        owned_probe = name.startswith(('vpnbot-ci-retain-', 'vpnbot-warp-udp-', 'vpnbot-warp-modules-')) or name == 'vpnbot-ci-unit'
        if labels.get('com.docker.compose.project') == 'vpnbot-audit' or labels.get('vpnbot.hosted-ci') == 'true' or owned_probe:
            command('docker', 'rm', '-f', ident)
    for network in ('vpnbot-audit_default', 'vpnbot-audit_xray', 'vpnbot-protocol-test', 'vpnbot-warp-udp-test'):
        subprocess.run(['docker', 'network', 'rm', network], capture_output=True)
    for volume in ('vpnbot-audit_adguard', 'vpnbot-audit_warp'):
        subprocess.run(['docker', 'volume', 'rm', volume], capture_output=True)
    shutil.rmtree(ROOT)
    print('Disposable data and one-run keys removed')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('assets', 'test', 'cleanup'))
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--local-test', action='store_true')
    args = parser.parse_args()
    host(args.local_test)
    checkout = Path(__file__).resolve().parents[1]
    if args.action == 'assets': assets(checkout, args.manifest.resolve())
    elif args.action == 'test': test(checkout, args.manifest.resolve(), args.output.resolve())
    else: cleanup()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Do not serialize command arguments, generated data or raw exceptions.
        print('Ephemeral test rejected: ' + type(error).__name__, file=sys.stderr)
        failed = failed_protocols(Path(__file__).resolve().parents[1])
        if failed:
            print('Failed protocol groups: ' + ', '.join(failed), file=sys.stderr)
        log = ROOT / 'private.log'
        if log.is_file():
            stages = re.findall(r'^START ([a-z][a-z0-9-]{0,70})$', log.read_text(errors='replace'), re.M)
            if stages:
                print('Last test stage: ' + stages[-1], file=sys.stderr)
        sys.exit(1)
