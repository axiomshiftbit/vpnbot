#!/usr/bin/python3
"""Обычная установка, отказ при небезопасных путях и ротация синтетических логов."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

case = sys.argv[1]
assert os.getpid() == 1 and os.readlink('/proc/self/ns/net') != os.environ['PARENT_NETNS']
result = {'case': case, 'passed': False, 'checks': {}}


def run(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=35)


def check(name, value):
    result['checks'][name] = bool(value)
    if not value:
        raise AssertionError(name)


def contains(path, marker):
    for _ in range(60):
        if path.is_file() and marker in path.read_text():
            return True
        time.sleep(.05)
    return False


try:
    dropped = case in ('syslog-owner', 'writable-log-parent')
    config = 'module(load="imuxsock")\n'
    if dropped:
        config += '$PrivDropToUser syslog\n$PrivDropToGroup syslog\n'
    config += '$IncludeConfig /etc/rsyslog.d/*.conf\n*.* /var/log/general.log\n'
    Path('/var/log/general.log').touch()
    if dropped:
        os.chown('/var/log/general.log', 104, 104)
    Path('/etc/rsyslog.conf').write_text(config)
    Path('/etc/logrotate.conf').write_text('include /etc/logrotate.d\n')
    Path('/var/lib/logrotate/status').write_text('logrotate state -- version 2\n')
    for name in ('rsyslog.d/10-nftables.conf', 'logrotate.d/nftables'):
        Path('/etc', name).write_text('# previous synthetic configuration\n')
    check('real_rsyslog_started', run('systemctl', 'restart', 'rsyslog.service').returncode == 0)
    refused = case in ('writable-log-parent', 'writable-ancestor', 'symlink-directory', 'validation-rollback', 'restart-rollback')
    if case == 'writable-log-parent':
        os.chown('/var/log', 0, 104)
        os.chmod('/var/log', 0o775)
    if case == 'writable-ancestor':
        os.chmod('/etc', 0o775)
    if case == 'symlink-directory':
        Path('/run/synthetic-target').mkdir()
        Path('/var/log/nftables').symlink_to('/run/synthetic-target')
    if case == 'validation-rollback':
        Path('/etc/rsyslog.d/99-invalid.conf').write_text('this is invalid RainerScript\n')
    if case == 'restart-rollback':
        Path('/run/fail-restart').touch()
    if case == 'history-rotation':
        Path('/var/log/nftables').mkdir()
        Path('/var/log/nftables/old-custom.log').write_text('synthetic history\n')
    installed = run('bash', '/source/install-nft-logging.sh', '--profile', 'main')
    result['installer_exit'] = installed.returncode
    if refused:
        check('unsafe_or_failed_install_refused', installed.returncode != 0)
        if case.startswith('writable-'):
            check('permission_check_reached', 'доступен для посторонней записи' in installed.stderr)
        for name in ('rsyslog.d/10-nftables.conf', 'logrotate.d/nftables'):
            check('previous_' + name, Path('/etc', name).read_text() == '# previous synthetic configuration\n')
        if case == 'restart-rollback':
            check('previous_daemon_restarted', run('systemctl', 'is-active', '--quiet', 'rsyslog.service').returncode == 0)
    else:
        check('installer_success', installed.returncode == 0)
        logs = Path('/var/log/nftables')
        check('eight_private_logs', len(list(logs.glob('*.log'))) == 8 and all(p.stat().st_mode & 0o777 == 0o640 for p in logs.glob('*.log')))
        check('service_record_written', contains(logs/'service.log', 'NFTABLES-SETUP:'))
        if dropped:
            check('unprivileged_writer', all(p.stat().st_uid == 104 for p in logs.glob('*.log')))
        before = (logs/'service.log').read_text()
        check('repeat_install_success', run('bash', '/source/install-nft-logging.sh', '--profile', 'main').returncode == 0)
        check('repeat_preserves_records', (logs/'service.log').read_text().startswith(before))
        if case == 'history-rotation':
            check('legacy_preserved', any(p.read_text() == 'synthetic history\n' for p in (logs/'legacy').glob('*/old-custom.log')))
            check('real_rotation_success', run('logrotate', '--force', '/etc/logrotate.d/nftables').returncode == 0)
            check('archive_created', (logs/'archive/service.log.1').is_file())
            check('fresh_logger_success', run('logger', '--socket-errors=on', '-p', 'user.notice', '-t', 'nftables-setup', '--', 'NFTABLES-SETUP: after-rotation').returncode == 0)
            check('fresh_record_after_rotation', contains(logs/'service.log', 'after-rotation'))
    result['passed'] = True
except Exception as error:
    result['error'] = type(error).__name__ + ': ' + str(error)
finally:
    pidfile = Path('/run/rsyslog.pid')
    if pidfile.is_file():
        try:
            os.kill(int(pidfile.read_text()), signal.SIGTERM)
        except (ProcessLookupError, ValueError):
            pass
    print(json.dumps(result, ensure_ascii=False))
sys.exit(0 if result['passed'] else 1)
