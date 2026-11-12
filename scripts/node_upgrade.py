#!/usr/bin/env python3
"""Code phase of the node's full update: published bundle commit -> host code.

Runs as vpnbot-node-upgrade.service (root, outside the worker sandbox: it
writes /usr/local/lib, systemd units, nftables and sysctl like the manual
upgrade). The image phase then runs in the ordinary worker with the new code."""
import fcntl
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time

import image_bundle
import node_state as state
from node_runtime import command

REPOSITORY = Path('/root/vpnbot')
BRANCHES = {'latest': 'master', 'dev': 'dev'}
RELEASE = 'upgrade-release.json'
CODE = 'code.json'
SOURCE = 'upgrade-source'
UNIT = 'vpnbot-node-upgrade.service'
# Stage names are fixed identifiers; never exception or command text.
SETUP_STAGE = re.compile(r'Этап \[([a-z]{1,16})\]')


class UpgradeError(RuntimeError):
    def __init__(self, stage):
        super().__init__('node code upgrade failed')
        self.stage = stage


def git(*args, timeout=120):
    # core.sshCommand of the clone uses paths relative to its top directory.
    result = subprocess.run(['git', '-C', str(REPOSITORY), *args], capture_output=True, timeout=timeout,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8',
                                 'GIT_TERMINAL_PROMPT': '0'})
    return result


def ancestor(older, newer):
    result = git('merge-base', '--is-ancestor', older, newer)
    if result.returncode not in (0, 1):
        raise UpgradeError('fetch')
    return result.returncode == 0


def installed(store):
    value = store.read(CODE)
    if isinstance(value, dict) and isinstance(value.get('source'), str) and image_bundle.COMMIT.fullmatch(value['source']):
        return value['source']
    return None


def extract(source, target):
    """Only scripts/ of the verified commit, regular files and directories."""
    archive = git('archive', '--format=tar', source, 'scripts', timeout=120)
    if archive.returncode:
        raise UpgradeError('source')
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as stream:
        for member in stream.getmembers():
            name = Path(member.name)
            if name.is_absolute() or '..' in name.parts or name.parts[:1] != ('scripts',) \
                    or not (member.isfile() or member.isdir()):
                raise UpgradeError('source')
            path = target/name
            if member.isdir():
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with stream.extractfile(member) as data, open(path, 'xb') as output:
                    shutil.copyfileobj(data, output)
                os.chmod(path, 0o600)
    if not (target/'scripts/node_setup.py').is_file():
        raise UpgradeError('source')
    return target/'scripts'


def fast_forward(branch, source):
    """Advance a clean clone of the same branch; never touch local edits."""
    head = git('symbolic-ref', '--short', '-q', 'HEAD')
    dirty = git('status', '--porcelain', '--untracked-files=no')
    current = git('rev-parse', 'HEAD')
    if current.returncode == 0 and current.stdout.decode().strip() == source:
        return 'current'
    if head.returncode or head.stdout.decode().strip() != branch or dirty.returncode or dirty.stdout.strip() \
            or not ancestor('HEAD', source):
        return 'kept'
    return 'updated' if git('merge', '-q', '--ff-only', source).returncode == 0 else 'kept'


def code_phase(store, job, channel):
    """Returns the installed commit and the clone result; raises UpgradeError."""
    branch = BRANCHES[channel]
    release = store.root/RELEASE
    try:
        bundle = image_bundle.fetch(channel, release)
    except Exception as error:
        raise UpgradeError('bundle') from error
    source = bundle['source']
    if git('rev-parse', '--git-dir').returncode:
        raise UpgradeError('repository')
    fetched = git('fetch', '-q', 'origin', '+refs/heads/'+branch+':refs/remotes/origin/'+branch, timeout=180)
    if fetched.returncode or not ancestor(source, 'refs/remotes/origin/'+branch):
        raise UpgradeError('fetch')
    previous = installed(store)
    if previous == source:
        return source, fast_forward(branch, source)
    # Never install older code than the node already runs: a dev node
    # cannot be downgraded by the master button.
    baseline = previous or git('rev-parse', 'HEAD').stdout.decode().strip()
    if not image_bundle.COMMIT.fullmatch(baseline) or not ancestor(baseline, source):
        raise UpgradeError('downgrade')
    scripts = extract(source, store.root/SOURCE)
    try:
        result = subprocess.run(['/usr/bin/python3', '-I', '-B', str(scripts/'node_setup.py'), '--upgrade-code', '--job', job],
                                capture_output=True, timeout=1500, cwd='/',
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/root'})
    finally:
        shutil.rmtree(store.root/SOURCE, ignore_errors=True)
    if result.returncode:
        stages = SETUP_STAGE.findall(result.stderr.decode(errors='replace'))
        raise UpgradeError('setup_'+stages[-1] if stages else 'setup')
    state.atomic(store.root/CODE, state.encode({'source': source, 'time': int(time.time())}))
    return source, fast_forward(branch, source)


def run(store, lock):
    """lock: path of the node lock; it is held only around job state changes."""
    def locked(edit):
        descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            return edit()
        finally:
            os.close(descriptor)

    def begin():
        job, request = store.read('job.json'), store.read('request.json')
        if not job or job.get('state') != 'queued' or not isinstance(request, dict) \
                or request.get('operation') != 'upgrade' or request.get('value') not in BRANCHES:
            return None
        job.update(state='running', phase='code', time=int(time.time()))
        state.atomic(store.root/'job.json', state.encode(job))
        return job['id'], request['value']

    started = locked(begin)
    if not started:
        return
    identifier, channel = started
    try:
        source, checkout = code_phase(store, identifier, channel)
        failure = None
    except UpgradeError as error:
        failure = error.stage
    except Exception:
        failure = 'unexpected'

    def finish():
        job = store.read('job.json')
        if not job or job.get('id') != identifier or job.get('state') != 'running' or job.get('phase') != 'code':
            return False
        if failure:
            (store.root/RELEASE).unlink(missing_ok=True)
            (store.root/'request.json').unlink(missing_ok=True)
            job.update(state='failed', error='code_upgrade_failed', stage=failure, time=int(time.time()))
            state.atomic(store.root/'job.json', state.encode(job))
            return False
        # The worker installs exactly the images of the commit just installed.
        job.update(state='queued', phase='images', code=source, checkout=checkout, time=int(time.time()))
        state.atomic(store.root/'job.json', state.encode(job))
        return True

    if locked(finish):
        try:
            command(['systemctl', 'start', '--no-block', 'vpnbot-node-worker.service'], timeout=10)
        except Exception:
            # The watch timer fails a queued job whose worker never started.
            pass
