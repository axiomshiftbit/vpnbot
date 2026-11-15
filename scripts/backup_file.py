#!/usr/bin/env python3
"""Save a bounded CLI export without truncating the last usable backup."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import selectors
import time

MAX_BYTES = 20 * 1024 * 1024  # BotBackup::BACKUP_MAX_BYTES
EXPORT_TIMEOUT = 900
SECTIONS = {'pac', 'wg', 'wg1', 'ad', 'hwid', 'ssl', 'dnstt', 'xray', 'hy',
            'hy_users', 'oc', 'ocu', 'tt', 'ss', 'sl', 'cloak', 'ckusers',
            'ovpn', 'ipsec', 'xraystats', 'managed_protocols', 'extra_files'}


def save(destination=Path('backup.json')):
    fd, temporary = tempfile.mkstemp(prefix='.backup-', suffix='.tmp', dir=destination.parent)
    process = None
    committed = False
    try:
        with os.fdopen(fd, 'w+b') as stream:
            os.fchmod(stream.fileno(), 0o600)
            process = subprocess.Popen(['docker', 'compose', 'exec', '-T', 'php', 'timeout', str(EXPORT_TIMEOUT), 'php', 'backup.php'],
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            total = 0
            deadline = time.monotonic() + EXPORT_TIMEOUT + 5
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise TimeoutError('Backup export timed out')
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_BYTES:
                        raise ValueError('Backup exceeds the restore size limit')
                    stream.write(chunk)
            if process.wait(timeout=max(.01, deadline - time.monotonic())) != 0:
                raise RuntimeError('Backup export failed')
            stream.seek(0)
            def invalid_constant(value):
                raise ValueError('Invalid JSON constant')
            data = json.load(stream, parse_constant=invalid_constant)
            if not isinstance(data, dict) or not SECTIONS.intersection(data):
                raise ValueError('Invalid backup export')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        committed = True
        directory = os.open(destination.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        # The exporter can contain credentials: never echo its output/errors.
        if committed:
            raise RuntimeError('Backup saved, but directory durability could not be confirmed') from None
        raise RuntimeError('Backup not saved; previous file preserved') from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()
        Path(temporary).unlink(missing_ok=True)


if __name__ == '__main__':
    try:
        save()
    except Exception as error:
        raise SystemExit(str(error))
