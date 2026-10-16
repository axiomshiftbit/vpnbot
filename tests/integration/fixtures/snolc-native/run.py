"""snolc на настоящем ядре образа: клиент из ZIP бота, трафик, отказы, учёт.

Запуск: run.py <checkout> <образ snolc> <образ php>.
Сервер — контейнер проверяемого образа с ограничениями из Compose. Клиент для
glibc из ZIP, который выдаёт код бота, запускается на самой VM. Цели трафика:
«публичная» сеть 198.51.100.0/24 (документационный диапазон, snolc его
пропускает) и приватная 10.77.99.0/24, куда snolc ходить не должен.
"""
from pathlib import Path
import json, shutil, subprocess, sys, time

LAB = Path(__file__).resolve().parent
SOURCE, IMAGE, PHP_IMAGE = Path(sys.argv[1]).resolve(), sys.argv[2], sys.argv[3]
SERVER, TARGET = 'vpnbot-snolc-native-server', 'vpnbot-snolc-native-target'
NETWORKS = {'vpnbot-snolc-public': '198.51.100.0/24', 'vpnbot-snolc-private': '10.77.99.0/24'}
# Число проверок matrix.py: выпавшая проверка не должна пройти незаметно.
CHECKS = 91


def run(*args, timeout=120):
    return subprocess.run(list(args), check=True, capture_output=True, text=True, timeout=timeout).stdout.strip()


def cleanup():
    for name in (SERVER, TARGET):
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
    for name in NETWORKS:
        subprocess.run(['docker', 'network', 'rm', name], capture_output=True)


cleanup()
for name in ('results', 'proto', 'exports', 'clients'):
    shutil.rmtree(LAB / name, ignore_errors=True)
    (LAB / name).mkdir(mode=0o700)
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
    for name, subnet in NETWORKS.items():
        run('docker', 'network', 'create', '--internal', '--subnet', subnet, '--label', 'vpnbot.hosted-ci=true', name)
    run('docker', 'run', '-d', '--name', TARGET, '--label', 'vpnbot.hosted-ci=true', '--network', 'vpnbot-snolc-public',
        '--ip', '198.51.100.2', '-v', f'{LAB}/target.py:/target.py:ro', '--entrypoint', 'python3', PHP_IMAGE, '/target.py')
    run('docker', 'network', 'connect', '--ip', '10.77.99.2', 'vpnbot-snolc-private', TARGET)
    # Тот же код бота создаёт состояние; адрес сервера — его «публичный» адрес.
    run('docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'php', '-v', f'{SOURCE}:/src:ro', '-v', f'{LAB}:/lab',
        PHP_IMAGE, '/lab/control.php', 'init', '198.51.100.3')
    (LAB / 'proto/snolc/runtime').mkdir(mode=0o700, exist_ok=True)
    # Как в docker-compose.yml: те же тома, ограничения и точка входа образа.
    run('docker', 'run', '-d', '--name', SERVER, '--label', 'vpnbot.hosted-ci=true', '--network', 'vpnbot-snolc-public',
        '--ip', '198.51.100.3', '-e', 'PROTOCOL_DESIRED=/config/desired.json',
        '-v', f'{LAB}/proto/snolc:/config:ro', '-v', f'{LAB}/proto/snolc/runtime:/state',
        '-v', f'{SOURCE}/scripts/protocol_service.py:/protocol_service.py:ro',
        '-v', f'{SOURCE}/scripts/snolc_service.py:/snolc_service.py:ro', '-v', f'{SOURCE}/app/snolc:/snolc:ro',
        '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--init',
        '--cpus', '1', '--memory', '256m', '--pids-limit', '128', IMAGE)
    run('docker', 'network', 'connect', '--ip', '10.77.99.3', 'vpnbot-snolc-private', SERVER)
    case('matrix', [sys.executable, str(LAB / 'matrix.py'), str(SOURCE), IMAGE, PHP_IMAGE], 'matrix.json', 1500)
finally:
    with (LAB / 'server-container.log').open('wb') as log:
        subprocess.run(['docker', 'logs', SERVER], stdout=log, stderr=log)
    cleanup()
raise SystemExit(1 if not rows or sum(r['total'] for r in rows) != CHECKS
                 or any(r['exit'] or r['passed'] != r['total'] for r in rows) else 0)
