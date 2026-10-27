#!/usr/bin/env python3
"""Immutable image sets. Only identifiers go into a published bundle, never host data."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

REGISTRY = 'ghcr.io/axiomshiftbit/vpnbot-'
# Reuse the PHP package's existing registry access; no new PAT is required on
# installations. These tags contain metadata only, never a PHP runtime.
BUNDLE_REPO = REGISTRY + 'php'
SERVICES = {
    'ng': 'ng', 'up': 'ng', 'dockerproxy': 'ng', 'php': 'php', 'service': 'php',
    'wg': 'wg', 'wg1': 'wg', 'wp': 'wg', 'ad': 'ad', 'telemt': 'telemt',
    'xr': 'xr', 'oc': 'oc', 'np': 'np', 'ss': 'ss', 'proxy': 'ss',
    'dnstt': 'dnstt', 'ovpn': 'ovpn', 'ipsec': 'ipsec', 'tt': 'tt',
    'hy': 'hysteria', 'anytls': 'protocol', 'tuic': 'protocol',
    'shadowtls': 'protocol', 'mieru': 'mieru', 'snolc': 'snolc', 'masque': 'masque',
}
IMAGES = sorted(set(SERVICES.values()))
# Комплекты, выпущенные без snolc (2026-10-06 … 2026-10-16), его образа не
# содержат. Такой комплект допустим только как предыдущий (откат): текущий
# обязан закрепить digest каждого сервиса.
ABSENT_BEFORE = {'snolc'}
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def fingerprint(bundle):
    validate(bundle)
    return hashlib.sha256(canonical(bundle)).hexdigest()


def validate(bundle, *, previous=False):
    if not isinstance(bundle, dict) or set(bundle) != {'schema', 'source', 'run', 'attempt', 'state_epoch', 'images'}:
        raise ValueError('invalid bundle fields')
    if bundle['schema'] != 1 or bundle['state_epoch'] != 1:
        raise ValueError('unsupported bundle or state format')
    if not isinstance(bundle['source'], str) or not COMMIT.fullmatch(bundle['source']):
        raise ValueError('invalid source commit')
    if any(type(bundle[k]) is not int or bundle[k] < 1 for k in ('run', 'attempt')):
        raise ValueError('invalid build identity')
    images = bundle['images']
    expected = set(IMAGES)
    if previous and isinstance(images, dict) and not ABSENT_BEFORE & set(images):
        expected -= ABSENT_BEFORE
    if not isinstance(images, dict) or set(images) != expected:
        raise ValueError('incomplete image set')
    for name, ref in images.items():
        prefix = REGISTRY + name + '@'
        if not isinstance(ref, str) or not ref.startswith(prefix) or not DIGEST.fullmatch(ref[len(prefix):]):
            raise ValueError('invalid image digest: ' + name)
    return bundle


def read(path, *, previous=False):
    return validate(json.loads(Path(path).read_text()), previous=previous)


def atomic(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def overlay(bundle):
    validate(bundle)
    return {'services': {service: {'image': bundle['images'][name], 'pull_policy': 'missing'}
                         for service, name in SERVICES.items()}}


def command(*args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        # Docker/Git errors may include authentication or private URLs.
        raise RuntimeError(args[0] + ' operation failed')
    return result.stdout.decode().strip()


def check_image_overrides(root):
    # Let Compose resolve YAML, env files and interpolation itself. Never print
    # the resolved configuration: it can contain installation credentials.
    args = ['docker', 'compose', '--profile', '*', '--env-file', '.env']
    if (root / 'override.env').exists():
        args += ['--env-file', 'override.env']
    result = subprocess.run(args + ['config', '--format', 'json'], cwd=root, capture_output=True)
    if result.returncode:
        raise ValueError('cannot validate local Compose settings')
    services = json.loads(result.stdout)['services']
    for service, name in SERVICES.items():
        if service not in services:
            continue
        image = services[service].get('image', '')
        if image not in {REGISTRY + name + ':' + tag for tag in ('dev', 'latest', 'nightly')}:
            raise ValueError('custom image override prevents a bundle update: ' + service)


def source_reference(source):
    """Неизменяемая ссылка на допущенный комплект конкретного коммита."""
    if not isinstance(source, str) or not COMMIT.fullmatch(source):
        raise ValueError('invalid source commit')
    return BUNDLE_REPO + ':bundle-source-' + source


def fetch(channel, destination):
    if channel not in ('dev', 'latest', 'nightly'):
        raise ValueError('unknown release channel')
    return fetch_reference(BUNDLE_REPO + ':bundle-' + channel, destination)


def fetch_reference(ref, destination):
    parent = Path(destination).parent
    parent.mkdir(parents=True, exist_ok=True)
    # Serialize metadata replacement against Bot.cleanDocker's inventory scan.
    with (parent / 'image-bundle.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        command('docker', 'pull', ref)
        # Resolve once. A concurrent promotion cannot change the object being read.
        image = command('docker', 'image', 'inspect', '--format', '{{.Id}}', ref)
        container = command('docker', 'create', image, '/bundle.json')
        try:
            with tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / 'bundle.json'
                command('docker', 'cp', container + ':/bundle.json', str(target))
                bundle = read(target)
                atomic(destination, canonical(bundle))
                return bundle
        finally:
            command('docker', 'rm', container)


def activate(root, bundle):
    root = Path(root)
    validate(bundle)
    if command('git', '-C', str(root), 'rev-parse', 'HEAD') != bundle['source']:
        raise ValueError('code does not match the tested image set')
    # The JSON manifest is the only pointer. Compose derives its overlay from it;
    # there is no second mutable file which could select half of another release.
    current = root / 'update/image-bundle.json'
    current.parent.mkdir(parents=True, exist_ok=True)
    with (current.parent / 'image-bundle.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if current.exists():
            prior = read(current, previous=True)
            if prior != bundle:
                atomic(root / 'update/image-bundle.previous.json', canonical(prior))
        atomic(current, canonical(bundle))


def prepare(root, branch, destination):
    root = Path(root).resolve()
    if branch not in ('dev', 'master'):
        raise ValueError('automatic updates require a released branch')
    for file in (root / '.env', root / 'override.env'):
        if file.exists() and re.search(r'^VPNBOT_TAG=sha-', file.read_text(), re.M):
            raise ValueError('explicit image pin prevents an automatic update')
    check_image_overrides(root)
    bundle = fetch('latest' if branch == 'master' else 'dev', destination)
    command('git', '-C', str(root), 'fetch', '-q', 'origin')
    command('git', '-C', str(root), 'merge-base', '--is-ancestor', bundle['source'], 'origin/' + branch)
    # Preserve local commits, and never rewind a branch to an older release.
    exists = subprocess.run(['git', '-C', str(root), 'show-ref', '--verify', '--quiet', 'refs/heads/' + branch])
    if exists.returncode == 0:
        command('git', '-C', str(root), 'merge-base', '--is-ancestor', branch, bundle['source'])
    elif exists.returncode != 1:
        raise ValueError('cannot inspect local branch')
    # Fetch all enabled images before stopping a working installation. Registry
    # failure/ENOSPC leave its containers, code and runtime settings untouched.
    env = os.environ.copy()
    env['VPNBOT_BUNDLE_FILE'] = str(Path(destination).resolve())
    result = subprocess.run([sys.executable, str(Path(__file__).with_name('protocol_modules.py')), 'compose', 'pull', '--policy', 'missing'],
                            cwd=root, env=env, capture_output=True)
    if result.returncode:
        raise RuntimeError('candidate image pull failed')
    return bundle


def ensure(root):
    root = Path(root).resolve()
    if os.environ.get('VPNBOT_BUNDLE_FILE'):
        return read(os.environ['VPNBOT_BUNDLE_FILE'])
    path = root / 'update/image-bundle.json'
    if path.exists():
        value = read(path)
        if value['source'] != command('git', '-C', str(root), 'rev-parse', 'HEAD'):
            raise ValueError('checkout and active bundle differ')
        check_image_overrides(root)
        return value
    # Explicit immutable legacy pins are deliberate manual rollback choices.
    for file in (root / '.env', root / 'override.env'):
        if file.exists() and re.search(r'^VPNBOT_TAG=sha-', file.read_text(), re.M):
            return None
    branch = command('git', '-C', str(root), 'rev-parse', '--abbrev-ref', 'HEAD')
    if branch not in ('dev', 'master'):
        raise ValueError('start requires a released branch or an explicit image pin')
    check_image_overrides(root)
    value = fetch('latest' if branch == 'master' else 'dev', root / 'update/image-bundle.pending.json')
    activate(root, value)
    return value


def compose_files(root, env):
    """Add pins to every lifecycle operation, including disabled -> recreated."""
    root = Path(root)
    # The network is host-specific and opt-in. Backup data alone cannot enable it.
    enabled6 = (root / 'config/ipv6-egress.json').exists()
    if enabled6:
        import importlib.util
        spec = importlib.util.spec_from_file_location('ipv6_egress', Path(__file__).with_name('ipv6_egress.py'))
        ipv6 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ipv6)
        ipv6.load(root)
    separator = env.get('COMPOSE_PATH_SEPARATOR', os.pathsep)
    files = env.get('COMPOSE_FILE', '').split(separator) if env.get('COMPOSE_FILE') else ['docker-compose.yml']
    if not env.get('COMPOSE_FILE') and (root / 'docker-compose.override.yml').is_file():
        files.append('docker-compose.override.yml')
    if enabled6:
        files.append(str(root / 'docker-compose.ipv6.yml'))
    selected = env.get('VPNBOT_BUNDLE_FILE')
    path = Path(selected) if selected else root / 'update/image-bundle.json'
    if not path.exists():
        if selected:
            raise ValueError('requested image bundle is missing')
        return [part for f in files for part in ('-f', f)] if enabled6 else []
    bundle = read(path)
    if not selected and command('git', '-C', str(root), 'rev-parse', 'HEAD') != bundle['source']:
        raise ValueError('image bundle belongs to a different code revision')
    # Respect explicit rollback pins; do not silently replace them on an update.
    if env.get('VPNBOT_TAG', '').startswith('sha-') and not selected:
        raise ValueError('remove the explicit image pin before a bundle update')
    target = root / 'update' / ('compose-images-' + fingerprint(bundle) + '.json')
    # Файл того же комплекта мог записать прежний код (prepare перед обновлением)
    # по своему списку сервисов: сверяем содержимое, а не только имя.
    data = canonical(overlay(bundle))
    if not target.exists() or target.read_bytes() != data:
        atomic(target, data)
    # Only image and pull policy change; ports, mounts, TZ and local settings stay.
    return [part for f in files + [str(target)] for part in ('-f', f)]


def admit(bundle, evidence, statuses):
    if set(statuses) != {'build', 'tests', 'security', 'native'} or any(v != 'success' for v in statuses.values()):
        raise ValueError('required checks did not all succeed')
    if evidence.get('source') != bundle['source'] or evidence.get('bundle') != fingerprint(bundle):
        raise ValueError('test evidence does not match this candidate')
    if evidence.get('status') != 'success' or type(evidence.get('checks')) is not int or evidence['checks'] < 1:
        raise ValueError('native testing is incomplete')
    if not re.fullmatch('[0-9a-f]{64}', evidence.get('suite', '')):
        raise ValueError('test suite identity is missing')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('collect')
    p.add_argument('directory'); p.add_argument('output'); p.add_argument('--source', required=True)
    p.add_argument('--run', required=True, type=int); p.add_argument('--attempt', required=True, type=int)
    p = sub.add_parser('fetch'); p.add_argument('channel'); p.add_argument('output')
    p = sub.add_parser('prepare'); p.add_argument('branch'); p.add_argument('output'); p.add_argument('--root', default='.')
    p = sub.add_parser('ensure'); p.add_argument('--root', default='.')
    p = sub.add_parser('activate'); p.add_argument('manifest'); p.add_argument('--root', default='.')
    p = sub.add_parser('overlay'); p.add_argument('manifest'); p.add_argument('output')
    p = sub.add_parser('verify'); p.add_argument('manifest')
    p = sub.add_parser('admit'); p.add_argument('manifest'); p.add_argument('evidence'); p.add_argument('statuses')
    args = parser.parse_args()
    if args.action == 'collect':
        images = {}
        paths = list(Path(args.directory).glob('*.json'))
        if len(paths) != len(IMAGES):
            raise ValueError('missing or extra build descriptors')
        for path in paths:
            data = json.loads(path.read_text())
            if set(data) != {'image', 'digest', 'source', 'run', 'attempt'} or data['image'] in images:
                raise ValueError('invalid build descriptor')
            # Образ задан неизменяемым digest, поэтому сборка из более ранней
            # попытки ТОГО ЖЕ запуска и коммита равноценна: перезапуск одной
            # упавшей сборки не должен требовать пересборки остальных.
            if (data['source'], data['run']) != (args.source, args.run) \
                    or type(data['attempt']) is not int or not 1 <= data['attempt'] <= args.attempt:
                raise ValueError('descriptor belongs to another build')
            images[data['image']] = REGISTRY + data['image'] + '@' + data['digest']
        bundle = validate(dict(schema=1, source=args.source, run=args.run, attempt=args.attempt, state_epoch=1, images=images))
        atomic(args.output, canonical(bundle))
    elif args.action == 'fetch':
        bundle = fetch(args.channel, args.output)
    elif args.action == 'prepare':
        bundle = prepare(args.root, args.branch, args.output)
        print(bundle['source'])
        return
    elif args.action == 'ensure':
        bundle = ensure(args.root)
        if bundle is None:
            return
    else:
        bundle = read(args.manifest)
        if args.action == 'activate':
            activate(args.root, bundle)
        elif args.action == 'overlay':
            atomic(args.output, canonical(overlay(bundle)))
        elif args.action == 'admit':
            admit(bundle, json.loads(Path(args.evidence).read_text()), json.loads(args.statuses))
    print(fingerprint(bundle))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print('image bundle: ' + type(error).__name__ + ': operation rejected', file=sys.stderr)
        sys.exit(1)
