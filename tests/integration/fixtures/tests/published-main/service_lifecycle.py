#!/usr/bin/env python3
"""Actual daemon crash/off/start in the explicitly owned full CI stand."""
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path('/opt/vpnbot-hosted-ci/stand')
OUT = ROOT / 'results/service-lifecycle'
SERVICES = [
    ('ad', 'adguard-audit', 'adguard', '/opt/adguardhome/AdGuardHome'),
    ('ss', 'shadowsocks-audit', 'ssserver', '/usr/bin/ssserver'),
    ('proxy', 'proxy-audit', 'sslocal', '/usr/bin/sslocal'),
    ('np', 'naive-audit', 'naive', '/usr/local/bin/caddy'),
    ('dnstt', 'dnstt-audit', 'dnstt', '/usr/local/bin/dnstt-server'),
    ('tt', 'trusttunnel-audit', 'trusttunnel', '/usr/local/libexec/trusttunnel_endpoint'),
    ('ss', 'shadowsocks-audit', 'ck-server', '/usr/bin/ck-server'),
    ('ss', 'shadowsocks-audit', 'simple-tls', '/usr/bin/simple-tls'),
    ('ss', 'shadowsocks-audit', 'ssserver-v2ray', '/usr/bin/ssserver'),
]
rows = []
os.umask(0o077)
if not (ROOT / 'bot/scripts/service_supervisor.sh').is_file():
    raise SystemExit('owned CI stand missing')
OUT.mkdir(parents=True, exist_ok=True)


def run(*args, timeout=70):
    return subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=timeout)


def check(name, passed):
    rows.append(dict(name=name, passed=bool(passed)))
    (OUT / 'results.json').write_text(json.dumps(rows, indent=2))
    print(('PASS ' if passed else 'FAIL ') + name, flush=True)


def status(container, name):
    return run('docker', 'exec', container, 'sh', '/service_supervisor.sh', 'status', name).returncode


def record(container, name):
    value = run('docker', 'exec', container, 'cat', '/run/vpnbot-services/' + name + '/pid')
    parts = value.stdout.split()
    return parts if value.returncode == 0 and len(parts) == 2 and all(p.isdigit() for p in parts) else []


def control(service, action, name):
    # Transport is the real Bot::ssh; output is only a checked marker/boolean.
    command = '/bin/sh /service_supervisor.sh ' + action + ' ' + name
    marker = 'VPNBOT_SERVICE_' + ('STOPPED' if action == 'stop' else 'READY') + ':' + name
    code = "require '/app/config.php'; require '/app/bot.php'; require '/app/i18n.php'; " \
        "$b=new Bot($c['key'],$i); $out=$b->ssh($argv[1],$argv[2],true); " \
        "echo json_encode(['ok'=>!$b->sshFailed && trim((string)$out)===$argv[3]]);"
    result = run('docker', 'exec', 'php-audit', 'php', '-r', code, command, service, marker, timeout=80)
    try:
        return result.returncode == 0 and json.loads(result.stdout).get('ok') is True
    except ValueError:
        return False


def mode(value):
    result = run('docker', 'exec', 'php-audit', 'php', '/tmp/audit-driver.php', 'ss-mode', value, timeout=150)
    result.check_returncode()


# Only protocol metadata is read; credentials/config bodies never enter output.
if status('shadowsocks-audit', 'ck-server') == 0:
    previous_mode = 'cloak'
elif status('shadowsocks-audit', 'simple-tls') == 0:
    previous_mode = 'simple-tls'
else:
    value = run('docker', 'exec', 'shadowsocks-audit', 'jq', '-r',
        'if (.plugin // "") == "" then "plain" else "v2ray" end', '/config.json')
    previous_mode = value.stdout.strip()
    if previous_mode not in ('plain', 'v2ray'):
        raise SystemExit('cannot identify initial SS mode')

try:
    for service, container, case_name, executable in SERVICES:
        name = 'ssserver' if case_name == 'ssserver-v2ray' else case_name
        label = run('docker', 'inspect', '--format', '{{ index .Config.Labels "com.docker.compose.service" }}', container)
        sources = run('docker', 'inspect', '--format', '{{range .Mounts}}{{println .Source}}{{end}}', container)
        if label.stdout.strip() != service or not any(line.startswith(str(ROOT / 'bot') + '/') for line in sources.stdout.splitlines()):
            raise RuntimeError('container does not belong to this CI stand')
        if case_name == 'ssserver-v2ray':
            mode('v2ray')
        elif name == 'ck-server':
            mode('cloak')
        elif name == 'simple-tls':
            mode('simple-tls')
        if status(container, name) != 0:
            check(case_name + '-healthy-control', False)
            continue
        before = record(container, name)
        check(case_name + '-healthy-control', bool(before))
        if not before:
            continue
        try:
            # Verify PID starttime and executable immediately before SIGKILL.
            script = 'p=$1; expected=$2; exe=$3; read -r stat < /proc/$p/stat || exit 1; ' \
                'actual=$(printf "%s\\n" "${stat##*) }" | awk \'{print $20}\'); ' \
                '[ "$actual" = "$expected" ] && [ "$(readlink /proc/$p/exe)" = "$exe" ] && kill -KILL "$p"'
            killed = run('docker', 'exec', container, 'sh', '-c', script, '--', *before, executable)
            check(case_name + '-owned-daemon-killed', killed.returncode == 0)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and (status(container, name) != 0 or record(container, name) == before):
                time.sleep(.3)
            check(case_name + '-crash-recovered', status(container, name) == 0 and record(container, name) != before)
            check(case_name + '-ssh-stop-confirmed', control(service, 'stop', name))
            time.sleep(2)
            check(case_name + '-intentional-off-retained', status(container, name) == 3 and not record(container, name))
            check(case_name + '-ssh-start-confirmed', control(service, 'start', name))
            after = record(container, name)
            check(case_name + '-start-idempotent', control(service, 'start', name) and record(container, name) == after)
            check(case_name + '-ssh-restart-confirmed', control(service, 'restart', name) and record(container, name) != after)
        finally:
            check(case_name + '-restored', control(service, 'start', name) and status(container, name) == 0)
finally:
    mode(previous_mode)

print(json.dumps({'passed': sum(r['passed'] for r in rows), 'total': len(rows)}))
raise SystemExit(0 if rows and all(r['passed'] for r in rows) else 1)
