#!/usr/bin/env python3
"""Encrypted diagnostics of a failed native run; nothing readable is published.

Only allow-listed logs and result files of the disposable stand are collected,
known credential formats are redacted before packing, and the archive is
encrypted (CMS AuthEnvelopedData, AES-256-GCM, RSA-OAEP-SHA256) to the
repository's public diagnostics certificate. The plaintext never leaves a
private temporary directory and is removed in every case. The console shows
counts and the ciphertext digest only.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path('/opt/vpnbot-hosted-ci')
# Logs and machine-readable results of the stand only. No configuration,
# state, certificates, keys, backups or the bot checkout.
INCLUDE = [
    ('private.log', None), ('bootstrap-private.log', None), ('host-worker.log', None),
    ('results', ('.log', '.json', '.txt')),
    ('stand/results', ('.log', '.json', '.txt')),
    ('tests', ('results.json', '-results.json')),
    ('masque-native', ('.log', 'results.json')), ('telemt-native', ('.log', 'results.json')),
    ('hysteria-native', ('.log', 'results.json')), ('snolc-native', ('.log', 'results.json')),
    ('mieru-idle', ('.log', 'results.json')), ('naive-upgrade', ('.log', 'results.json')),
    ('ocserv-upgrade', ('.log', 'results.json')),
]
EXCLUDED_NAME = re.compile(r'(key|secret|passw|token|credential|cookie|\.pem$|\.crt$|\.p12$|\.env$|config\.php$|'
                           r'authorized_keys|id_(rsa|ed25519|ecdsa)|known_hosts|\.conf$)', re.I)
# results/unit is a disposable checkout with generated (synthetic) configs.
EXCLUDED_DIR = re.compile(r'(^|/)(ssh|certs?|pki|keys?|secrets?|backups?|bot|state|config|\.git)(/|$)|^results/unit/', re.I)
MAX_FILE, MAX_TOTAL = 4 * 1024 * 1024, 48 * 1024 * 1024
# Credential formats that must never be packed, even encrypted.
PATTERNS = [
    ('github-token', re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})')),
    ('private-key', re.compile(rb'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)', re.S)),
    ('authorization', re.compile(rb'(?i)\b(authorization|proxy-authorization)\s*[:=]\s*[^\r\n]+')),
    ('basic-auth-url', re.compile(rb'(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@')),
    ('jwt', re.compile(rb'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}')),
    ('telegram-bot-token', re.compile(rb'\b\d{6,12}:[A-Za-z0-9_-]{30,}\b')),
    ('signed-url-query', re.compile(rb'(?i)([?&](?:sig|signature|x-amz-signature|x-amz-credential|token|access_token|se|sv|skoid)=)[^&\s"\']+')),
    ('aws-key', re.compile(rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
]


def forbidden_values():
    """Exact secret values handed to this step; also their common encodings."""
    import base64
    values = []
    for name in ('CI_DIAG_FORBIDDEN_1', 'CI_DIAG_FORBIDDEN_2', 'CI_DIAG_FORBIDDEN_3'):
        value = os.environ.get(name, '')
        if len(value) >= 8:
            raw = value.encode()
            values += [raw, base64.b64encode(raw), base64.b64encode(b'x-access-token:' + raw)]
    return values


def redact(data, counts, values):
    for name, pattern in PATTERNS:
        def replace(match, name=name):
            counts[name] = counts.get(name, 0) + 1
            prefix = match.group(1) if name in ('authorization', 'basic-auth-url', 'signed-url-query') else b''
            return prefix + b'[REDACTED:' + name.encode() + b']'
        data = pattern.sub(replace, data)
    for value in values:
        if value in data:
            counts['forbidden-value'] = counts.get('forbidden-value', 0) + data.count(value)
            data = data.replace(value, b'[REDACTED:forbidden-value]')
    return data


def inside(path, root):
    # rglob may traverse a symlinked directory; only real files of the stand.
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
        return True
    except (OSError, ValueError):
        return False


def candidates(root=ROOT):
    for relative, suffixes in INCLUDE:
        base = root / relative
        if base.is_file() and not base.is_symlink() and inside(base, root):
            yield base
        elif base.is_dir() and not base.is_symlink():
            for path in sorted(base.rglob('*')):
                if path.is_symlink() or not path.is_file() or not inside(path, root):
                    continue
                rel = path.relative_to(root).as_posix()
                if EXCLUDED_DIR.search(rel) or EXCLUDED_NAME.search(path.name):
                    continue
                if suffixes and not path.name.endswith(suffixes):
                    continue
                yield path


def docker_state():
    """Container status and recent logs of the stand; never env or mounts."""
    out = {}
    names = subprocess.run(['docker', 'ps', '-a', '--format', '{{.Names}}'], capture_output=True, text=True, timeout=60)
    if names.returncode:
        return out
    for name in names.stdout.split():
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name):
            continue
        state = subprocess.run(['docker', 'inspect', '--format',
                                '{{json .State}} {{.RestartCount}} {{.Config.Image}}', name],
                               capture_output=True, timeout=60)
        logs = subprocess.run(['docker', 'logs', '--tail', '300', name], capture_output=True, timeout=60)
        out['containers/' + name + '.state'] = state.stdout
        out['containers/' + name + '.log'] = (logs.stdout + logs.stderr)[-MAX_FILE:]
    return out


def collect(root=ROOT, include_docker=True):
    counts, values, entries, total = {}, forbidden_values(), {}, 0
    for path in candidates(root):
        data = path.read_bytes()[-MAX_FILE:]
        if total + len(data) > MAX_TOTAL:
            counts['truncated-files'] = counts.get('truncated-files', 0) + 1
            continue
        entries['stand/' + path.relative_to(root).as_posix()] = redact(data, counts, values)
        total += len(data)
    if include_docker:
        for name, data in docker_state().items():
            if total + len(data) > MAX_TOTAL:
                counts['truncated-files'] = counts.get('truncated-files', 0) + 1
                continue
            entries[name] = redact(data, counts, values)
            total += len(data)
    return entries, counts


def pack(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
        for name, data in sorted(entries.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o600, 0
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def encrypt(archive, certificate, output):
    with tempfile.TemporaryDirectory(prefix='vpnbot-diag-') as directory:
        os.chmod(directory, 0o700)
        plain = Path(directory) / 'diagnostics.tar.gz'
        fd = os.open(plain, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(archive)
        try:
            result = subprocess.run(['openssl', 'cms', '-encrypt', '-binary', '-aes-256-gcm',
                                     '-recip', str(certificate), '-keyopt', 'rsa_padding_mode:oaep',
                                     '-keyopt', 'rsa_oaep_md:sha256', '-outform', 'DER',
                                     '-in', str(plain), '-out', str(output)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
        finally:
            plain.unlink(missing_ok=True)
        if result.returncode or not output.is_file() or output.stat().st_size == 0:
            output.unlink(missing_ok=True)
            raise RuntimeError('encryption failed')
        if archive[:64] and archive[:64] in output.read_bytes():
            output.unlink(missing_ok=True)
            raise RuntimeError('ciphertext contains plaintext')


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--certificate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(arguments)
    os.umask(0o077)
    entries, counts = collect()
    if not entries:
        print('Diagnostics: nothing to collect')
        return 0
    archive = pack(entries)
    encrypt(archive, args.certificate, args.output)
    # Ciphertext only: hand it to the runner user for upload.
    if os.environ.get('SUDO_UID', '').isdigit() and os.environ.get('SUDO_GID', '').isdigit():
        os.chown(args.output, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print('Diagnostics: files ' + str(len(entries)) + '; encrypted bytes ' + str(args.output.stat().st_size)
          + '; sha256 ' + digest)
    print('Diagnostics redactions: ' + json.dumps(counts, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        # Paths and messages of failures may contain stand data; type only.
        print('Diagnostics not produced: ' + type(error).__name__, file=sys.stderr)
        sys.exit(0)
