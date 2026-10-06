"""MASQUE на настоящем ядре образа: матрица трафика, отказы, жизненный цикл.

Запуск: run.py <checkout> <образ masque> <образ php> <клиентский xray>.
Сценарии матрицы работают внутри контейнера проверяемого образа без сети;
адреса эхо-служб назначаются его loopback.
"""
from pathlib import Path
import json, shutil, subprocess, sys, time

LAB = Path(__file__).resolve().parent
SOURCE, IMAGE, PHP_IMAGE, CLIENT_XRAY = Path(sys.argv[1]).resolve(), sys.argv[2], sys.argv[3], str(Path(sys.argv[4]).resolve())
NAME = 'vpnbot-masque-native'


def run(*args, timeout=120):
    return subprocess.run(list(args), check=True, capture_output=True, text=True, timeout=timeout).stdout.strip()


for name in ('results', 'state', 'certs', 'source/scripts'):
    (LAB / name).mkdir(parents=True, exist_ok=True)
for name in ('masque_service.py', 'protocol_service.py'):
    shutil.copy2(SOURCE / 'scripts' / name, LAB / 'source/scripts' / name)
(LAB / 'xray-wrapper').chmod(0o755)
holder = run('docker', 'create', '--entrypoint', '/bin/true', IMAGE)
try:
    run('docker', 'cp', holder + ':/usr/local/bin/xray', str(LAB / 'xray-masque'))
finally:
    run('docker', 'rm', holder)
run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=masque.example.test',
    '-addext', 'subjectAltName=DNS:masque.example.test', '-keyout', str(LAB / 'certs/cert_private'),
    '-out', str(LAB / 'certs/cert_public'))
run('docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'php', '-v', f'{SOURCE}:/src:ro', '-v', f'{LAB}:/lab',
    PHP_IMAGE, '/lab/fixture.php')
rows = []


def case(name, command, result, timeout):
    print('START ' + name, flush=True)
    started = time.monotonic()
    with (LAB / (name + '.log')).open('w') as log:
        try:
            code = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            code = 'timeout'
    path = LAB / 'results' / result
    checks = json.loads(path.read_text()) if path.is_file() else {}
    row = {'case': name, 'exit': code, 'seconds': round(time.monotonic() - started, 1),
           'passed': sum(map(bool, checks.values())), 'total': len(checks)}
    rows.append(row)
    (LAB / 'results.json').write_text(json.dumps(rows, indent=2))
    print(json.dumps(row), flush=True)


try:
    run('docker', 'run', '-d', '--name', NAME, '--label', 'vpnbot.hosted-ci=true', '--network', 'none',
        '--sysctl', 'net.ipv6.conf.all.disable_ipv6=0', '--sysctl', 'net.ipv6.conf.lo.disable_ipv6=0',
        '--memory', '512m', '--pids-limit', '256', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
        '--init', '--entrypoint', 'sleep', '-v', f'{LAB}:/lab', '-v', f'{LAB}/state:/state',
        '-v', f'{LAB}/certs:/certs', '-v', f'{LAB}/xray-wrapper:/usr/local/bin/xray:ro',
        '-v', f'{CLIENT_XRAY}:/client-xray:ro', IMAGE, 'infinity')
    pid = run('docker', 'inspect', '--format', '{{.State.Pid}}', NAME)
    for address in ('198.51.100.23/32', '2001:db8::23/128', '10.10.0.27/32', '10.10.0.13/32'):
        run('nsenter', '-t', pid, '-n', 'ip', 'addr', 'add', address, 'dev', 'lo')
    case('native_matrix', ['docker', 'exec', NAME, 'python3', '/lab/native_matrix.py'], 'native.json', 600)
    # Каждый сценарий поднимает собственный супервизор на чистом состоянии.
    run('docker', 'exec', NAME, 'sh', '-c', 'rm -rf /state/* /lab/desired-current.json')
    case('native_extras', ['docker', 'exec', NAME, 'python3', '/lab/native_extras.py'], 'extras.json', 300)
finally:
    subprocess.run(['docker', 'rm', '-f', NAME], capture_output=True)
case('lifecycle', [sys.executable, str(LAB / 'lifecycle.py'), IMAGE, CLIENT_XRAY], 'lifecycle.json', 300)
raise SystemExit(1 if any(r['exit'] or not r['total'] or r['passed'] != r['total'] for r in rows) else 0)
