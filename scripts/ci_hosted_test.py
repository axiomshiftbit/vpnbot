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

import ci_retry
from ci_retry import retrying
from image_bundle import BUNDLE_REPO, atomic, canonical, command, fingerprint, read


def network(*args):
    return retrying(command, *args)

ROOT = Path('/opt/vpnbot-hosted-ci')
GROUPS = {'unit', 'native', 'modules', 'backup_restore', 'update_rollback', 'faults', 'telegram_http'}
CLIENT_IMAGE = 'vpnbot-hosted-clients:current'


def download_client(url, archive):
    # The shared downloader owns the bounded retries and GitHub API fallback.
    # Do not multiply its attempts by wrapping it in another retry loop.
    helper = Path(__file__).resolve().parents[1] / 'dockerfile/download-file.sh'
    subprocess.run(['sh', str(helper), url, str(archive)], check=True, timeout=900)


def client_downloads(destination):
    # Public upstream releases; pinned archives, no copied VPS executables.
    releases = [
        # -5: блокировка скомпрометированных промежуточных eMudhra; файлы прежних
        # выпусков автор удалил 2026-10-22, поэтому -2 больше не скачивается.
        ('https://github.com/klzgrad/naiveproxy/releases/download/v154.0.8037.49-5/naiveproxy-v154.0.8037.49-5-linux-x64.tar.xz',
         '80214dfea1767f6ecf63a3a79dc9f48b203460f51abc609357fff48dd5844c7d', {'naive': 'naive'}),
        ('https://github.com/TrustTunnel/TrustTunnelClient/releases/download/v1.1.11/trusttunnel_client-v1.1.11-linux-x86_64.tar.gz',
         '00e0546a6b35840dbb92b741dff3da6732a74bf2d6c581e044bb4567c0d96825',
         {'trusttunnel_client': 'trusttunnel', 'setup_wizard': 'setup_wizard'}),
        # Проверка уже выданных профилей и клиента до обновления сервера Mieru.
        ('https://github.com/enfein/mieru/releases/download/v3.38.1/mieru_3.38.1_linux_amd64.tar.gz',
         'f7ec3b1c2caf338803426d2b3ff32d85654ce585b391556ebe5d2ea55d72d34f', {'mieru': 'mieru-previous'}),
    ]
    destination.mkdir(mode=0o700)
    for url, digest, names in releases:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'client.tar'
            download_client(url, archive)
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
    files = list((checkout / 'tests/integration').rglob('*')) + [checkout / 'dockerfile' / name
                                                            for name in ('download-file.sh', 'go-retry.sh')]
    for p in sorted(files):
        if p.is_file() and '__pycache__' not in p.parts:
            digest.update(str(p.relative_to(checkout)).encode() + b'\0' + p.read_bytes())
    return digest.hexdigest()


def evidence(bundle, checks, suite, warnings=None, allow_test_failures=False):
    if set(checks) != GROUPS or any(type(n) is not int or n <= 0 for n in checks.values()):
        raise ValueError('incomplete native matrix')
    from ci_release_policy import validate_warnings
    rows = validate_warnings(warnings if warnings is not None else [], {'allow_test_failures': allow_test_failures})
    result = dict(source=bundle['source'], bundle=fingerprint(bundle), suite=suite,
                  status='success_with_warnings' if rows else 'success', checks=sum(checks.values()))
    if rows:
        result['warnings'] = rows
    return result


# Self-contained suites that may run on separate runners; must equal
# tests/integration/suite/isolated_cases.py CASES (checked by a unit test).
ISOLATED = ('backup-node-cold', 'naive-upgrade', 'mieru-idle', 'ocserv-upgrade',
            'telemt-native', 'masque-native', 'hysteria-native', 'snolc-native')


def part(bundle, counts, suite, split, cases=(), warnings=None):
    """Counters of one runner's share; merge() turns all shares into evidence."""
    if set(counts) != GROUPS or any(type(n) is not int or n < 0 for n in counts.values()):
        raise ValueError('malformed native counters')
    return dict(source=bundle['source'], bundle=fingerprint(bundle), suite=suite, split=split,
                cases=sorted(cases), counts=counts, warnings=warnings or [])


def merge(bundle, parts, allow_test_failures=False):
    """One admission from the core stand and the isolated runners of this run.

    Every share must describe this very candidate and test suite; the isolated
    shares must cover each self-contained suite exactly once.
    """
    if any(p.get('source') != bundle['source'] or p.get('bundle') != fingerprint(bundle) for p in parts):
        raise ValueError('native share of another candidate')
    suites = {p.get('suite') for p in parts}
    if len(suites) != 1 or not re.fullmatch('[0-9a-f]{64}', next(iter(suites)) or ''):
        raise ValueError('native shares of different test suites')
    core = [p for p in parts if p.get('split') == 'core']
    isolated = [p for p in parts if p.get('split') == 'isolated']
    if len(core) != 1 or len(core) + len(isolated) != len(parts) or core[0]['cases']:
        raise ValueError('exactly one core stand share is required')
    covered = [case for p in isolated for case in p['cases']]
    if not all(p['cases'] and not p['warnings'] for p in isolated) or sorted(covered) != sorted(ISOLATED):
        raise ValueError('isolated native suites missing or repeated')
    counts = dict.fromkeys(GROUPS, 0)
    for p in parts:
        if set(p['counts']) != GROUPS or any(type(n) is not int or n < 0 for n in p['counts'].values()):
            raise ValueError('malformed native counters')
        for group, n in p['counts'].items():
            counts[group] += n
    if not all(p['counts']['native'] + p['counts']['backup_restore'] > 0 for p in isolated):
        raise ValueError('isolated native share without checks')
    return evidence(bundle, counts, core[0]['suite'], core[0]['warnings'], allow_test_failures)


def failed_checks(group, limit=10):
    """Names (only) of failed checks in a failed group, and the last check run."""
    try:
        rows = json.loads((ROOT / 'stand/results' / group / 'results.json').read_text())
    except (OSError, ValueError):
        return [], None
    if not isinstance(rows, list):
        return [], None
    names = [r.get('name') for r in rows if isinstance(r, dict)]
    safe = [n if isinstance(n, str) and re.fullmatch(r'[A-Za-z0-9 ._:/-]{1,80}', n) else '<unnamed>' for n in names]
    failed = [n for n, r in zip(safe, rows) if isinstance(r, dict) and r.get('passed') is False]
    return failed[:limit], (safe[-1] if safe else None)


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
    if os.environ.get('CI_FIRST_RELEASE') == '1':
        # Явный флажок первой публикации в новом реестре: прежнего допущенного
        # комплекта ещё нет, откат проверяется на сам кандидат.
        print('First release: no admitted release yet; rollback checks use the candidate itself')
        previous = read(manifest, previous=True)
    else:
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
    args = ['docker', 'build', '--pull', '--build-context', 'download-tools=' + str(checkout / 'dockerfile'),
            '-t', CLIENT_IMAGE, '-f', str(checkout / 'tests/integration/clients.dockerfile')]
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


def test(checkout, manifest, output, allow_test_failures=False, split=None, cases=None):
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
            if cases:
                # No stand: only what the self-contained suites read.
                if command('docker', 'ps', '-aq'):
                    raise RuntimeError('isolated suites require a Docker host without containers')
                source = checkout / 'tests/integration'
                shutil.copytree(source / 'fixtures', ROOT, dirs_exist_ok=True)
                shutil.copytree(source / 'suite', ROOT / 'suite', dirs_exist_ok=True)
                bootstrap.docker_file(bundle['images']['masque'], '/usr/local/bin/xray', ROOT / 'tests/xray')
                run = subprocess.run([sys.executable, str(ROOT / 'suite/isolated.py'), '--checkout', str(checkout),
                                      '--manifest', str(manifest), '--results', str(results),
                                      '--cases', ','.join(cases)], timeout=6600)  # 2 suites x 2 attempts x 1500 s
            else:
                bootstrap.bootstrap(checkout, bundle, CLIENT_IMAGE)
                if split == 'core':
                    os.environ['VPNBOT_NATIVE_SPLIT'] = 'core'
                run = subprocess.run([sys.executable, str(ROOT / 'suite/run.py'), '--checkout', str(checkout),
                                      '--manifest', str(manifest), '--results', str(results)] +
                                     (['--allow-test-failures'] if allow_test_failures else []), timeout=9000)
        finally:
            sys.stdout.flush(); sys.stderr.flush()
            os.dup2(original_out, 1); os.dup2(original_err, 2)
            os.close(original_out); os.close(original_err)
    if run.returncode:
        raise RuntimeError('ephemeral VPN matrix failed')
    checks = json.loads((results / 'summary.json').read_text())
    warnings = json.loads((results / 'warnings.json').read_text())
    if cases or split == 'core':
        result = part(bundle, checks, suite, 'isolated' if cases else 'core', cases or (), warnings)
        if cases and warnings:
            raise ValueError('isolated suites produce no warnings')
    else:
        result = evidence(bundle, checks, suite, warnings, allow_test_failures)
    if identity(checkout) != suite or bundle != read(manifest):
        raise ValueError('test inputs changed')
    if command('git', '-C', str(checkout), 'rev-parse', 'HEAD') != bundle['source']:
        raise ValueError('checkout changed during tests')
    atomic(output, canonical(result))
    output.chmod(0o644)  # Only public identifiers; uploader runs without sudo.
    print('Ephemeral VPN stand: all required groups passed; checks:',
          result['checks'] if 'checks' in result else sum(result['counts'].values()))
    from ci_release_policy import announce
    announce(warnings, 'native')
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
    for network in command('docker', 'network', 'ls', '-q', '--filter', 'label=vpnbot.hosted-ci=true').split():
        command('docker', 'network', 'rm', network)
    for network in ('vpnbot-audit_default', 'vpnbot-audit_xray', 'vpnbot-protocol-test', 'vpnbot-warp-udp-test'):
        subprocess.run(['docker', 'network', 'rm', network], capture_output=True)
    for volume in ('vpnbot-audit_adguard', 'vpnbot-audit_warp'):
        subprocess.run(['docker', 'volume', 'rm', volume], capture_output=True)
    shutil.rmtree(ROOT)
    print('Disposable data and one-run keys removed')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('assets', 'test', 'cleanup', 'merge'))
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--local-test', action='store_true')
    parser.add_argument('--allow-test-failures', action='store_true')
    # Split native testing (GitHub-hosted only): the stand without the
    # self-contained suites, or a comma-separated set of those suites.
    parser.add_argument('--split', choices=('core',))
    parser.add_argument('--cases')
    parser.add_argument('--parts', type=Path)
    args = parser.parse_args()
    cases = args.cases.split(',') if args.cases else None
    if cases is not None and (len(set(cases)) != len(cases) or not set(cases) <= set(ISOLATED)):
        raise ValueError('unknown or repeated isolated native suite')
    if (args.split or cases) and (args.local_test or args.action != 'test' or (args.split and cases)):
        raise ValueError('split native testing runs on GitHub-hosted runners only')
    if args.action == 'merge':
        # Only reads shares already produced by the runners of this run.
        bundle = read(args.manifest.resolve())
        parts = [json.loads(path.read_text()) for path in sorted(args.parts.glob('*.json'))]
        atomic(args.output.resolve(), canonical(merge(bundle, parts, args.allow_test_failures)))
        print('Native admission merged from', len(parts), 'shares')
        return
    host(args.local_test)
    checkout = Path(__file__).resolve().parents[1]
    if args.action == 'assets': assets(checkout, args.manifest.resolve())
    elif args.action == 'test': test(checkout, args.manifest.resolve(), args.output.resolve(), args.allow_test_failures,
                                     args.split, cases)
    else: cleanup()


FINALLY_STAGES = {'stop-worker', 'final-pause-cron', 'restore-baseline'}


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Do not serialize command arguments, generated data or raw exceptions.
        print('Ephemeral test rejected: ' + type(error).__name__, file=sys.stderr)
        failed = failed_protocols(Path(__file__).resolve().parents[1])
        if failed:
            print('Failed protocol groups: ' + ', '.join(failed), file=sys.stderr)
            for group in failed:
                checks, last = failed_checks(group)
                print('  ' + group + ': failed checks: ' + (', '.join(checks) or 'none recorded')
                      + '; last check: ' + (last or 'none'), file=sys.stderr)
        log = ROOT / 'private.log'
        if log.is_file():
            stages = re.findall(r'^START ([a-z][a-z0-9-]{0,70})$', log.read_text(errors='replace'), re.M)
            if stages:
                print('Last test stage: ' + stages[-1], file=sys.stderr)
            # After a failure the suite still runs its finally stages; name the
            # stage that failed before them (names only, no output).
            work = [stage for stage in stages if stage not in FINALLY_STAGES]
            if work and work[-1] != stages[-1]:
                print('Failed test stage: ' + work[-1], file=sys.stderr)
        sys.exit(1)
