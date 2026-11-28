#!/usr/bin/env python3
"""Code phase of the node's full update: published bundle commit -> host code.

Runs as vpnbot-node-upgrade.service (root, outside the worker sandbox: it
writes /usr/local/lib, systemd units, nftables and sysctl like the manual
upgrade). The image phase then runs in the ordinary worker with the new code."""
import fcntl
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time

import image_bundle
import node_code
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


# Modules copied to the node's code directory by node_setup.py --upgrade-code.
MODULES = ('node_manager.py', 'node_runtime.py', 'node_config.py', 'node_xray.py', 'node_dpi.py', 'node_cover.py',
           'node_counters.py', 'node_wg.py', 'node_awg.py', 'node_warp.py', 'node_policy.py', 'node_geodat.py', 'warp_masque.sh', 'node_state.py', 'node_upgrade.py', 'image_bundle.py', 'node_code.py')
LIB = Path('/usr/local/lib/vpnbot-node')
INSTALLED = 'code-installed.json'


def digest(directory=None):
    """SHA-256 over the installed modules: names, sizes and contents."""
    result = hashlib.sha256()
    directory = Path(directory) if directory is not None else node_code.active_path(LIB)
    for name in MODULES:
        data = (directory/name).read_bytes()
        result.update(name.encode() + b'\0' + str(len(data)).encode() + b'\0' + data)
    return result.hexdigest()


def checkout_commit(source):
    """Commit of the Git checkout that holds exactly these modules in scripts/, else None.

    A manual --upgrade-code may run from a clone with local edits or from an
    unpacked archive: then no commit is claimed for the installed code."""
    source = Path(source)
    if source.name != 'scripts':
        return None
    def run(*args):
        result = subprocess.run(['git', '-C', str(source.parent), *args], capture_output=True, timeout=30,
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8',
                                     'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_NOSYSTEM': '1'})
        return result.stdout if result.returncode == 0 else None
    try:
        head = (run('rev-parse', '--verify', '-q', 'HEAD^{commit}') or b'').decode().strip()
        if not image_bundle.COMMIT.fullmatch(head):
            return None
        for name in MODULES:
            if run('show', head + ':scripts/' + name) != (source/name).read_bytes():
                return None
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None
    return head


def record(root, source, manual):
    """After installation: what was installed, for the node status."""
    path = Path(root)/INSTALLED
    try:
        value = {'digest': digest(), 'manual': bool(manual), 'time': int(time.time()),
                 'source': checkout_commit(source) if manual else None}
        state.atomic(path, state.encode(value))
    except Exception:
        # Never report an earlier installation as the current one.
        path.unlink(missing_ok=True)


def code_status(store, directory=None):
    """Installed code: commit, how it was installed and whether files still match."""
    try:
        recorded = store.read(INSTALLED)
    except (OSError, ValueError):
        recorded = None
    if not isinstance(recorded, dict) or not re.fullmatch('[a-f0-9]{64}', str(recorded.get('digest', ''))):
        recorded = None
    button = installed(store)
    manual = recorded['source'] if recorded and recorded.get('manual') and isinstance(recorded.get('source'), str) \
        and image_bundle.COMMIT.fullmatch(recorded['source']) else None
    result = {'source': button or manual, 'upgrade': True,
              'origin': 'button' if button else ('manual' if recorded and recorded.get('manual') else None)}
    if recorded:
        try:
            actual = digest(directory)
            result['verified'] = actual == recorded['digest']
            if button and result['verified']:
                # Older button records lack a checksum bound to their commit.
                expected = store.read(CODE).get('digest')
                result['verified'] = actual == expected if expected else active_modules_match(button, directory)
        except OSError:
            result['verified'] = False
    return result


def matching_bundle(store, images, generation=None):
    """Find the generation's manifest, or an unambiguous match for an older installation."""
    generation = generation or store.current()
    pinned = store.path(generation)/'image-bundle.json' if generation else None
    match = None
    for path in (pinned, store.root/RELEASE, store.root/'release.json'):
        if path is None:
            continue
        try:
            bundle = image_bundle.read(path)
        except (OSError, ValueError, TypeError):
            continue
        if not images.get('xr') or any(bundle['images'].get(name) != ref for name, ref in images.items()):
            continue
        if path == pinned:
            return bundle
        if match and any(match['images'][name] != bundle['images'][name] for name in ('xr', 'ng', 'wg', 'ad')):
            return None
        match = match or bundle
    return match


def images_source(store):
    """Commit of the bundle whose images the current generation runs, if known."""
    try:
        bundle = matching_bundle(store, store.load()['images'])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return bundle['source'] if bundle else None


def preserve_current_bundle(store):
    """Before a download replaces a legacy cache, retain the manifest for rollback."""
    generation = store.current()
    if generation:
        path = store.path(generation)/'image-bundle.json'
        if not path.exists():
            bundle = matching_bundle(store, store.load(generation)['images'], generation)
            if bundle is not None:
                state.atomic(path, state.encode(bundle))


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


def active_modules_match(source, directory=None):
    """Legacy status files may refer to a commit whose installation was only partial."""
    active = Path(directory) if directory is not None else node_code.active_path(LIB)
    try:
        for name in MODULES:
            committed = git('show', source + ':scripts/' + name)
            if committed.returncode or committed.stdout != (active/name).read_bytes():
                return False
    except OSError:
        return False
    return True


def code_phase(store, job, channel):
    """Returns the installed commit and the clone result; raises UpgradeError."""
    branch = BRANCHES[channel]
    release = store.root/RELEASE
    preserve_current_bundle(store)
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
    if previous == source and active_modules_match(source):
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
    record = {'source': source, 'time': int(time.time())}
    files = store.read(INSTALLED)
    if isinstance(files, dict) and re.fullmatch('[a-f0-9]{64}', str(files.get('digest', ''))):
        record['digest'] = files['digest']
    state.atomic(store.root/CODE, state.encode(record))
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
