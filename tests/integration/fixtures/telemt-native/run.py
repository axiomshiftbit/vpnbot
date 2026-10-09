"""Telemt на настоящем ядре: лимиты, квоты, настройки, конвейер, контейнер.

Запуск: run.py <checkout> <образ telemt> <образ php> <образ nginx>. Ядро и
nginx берутся из проверяемых образов; PHP-обвязка работает в контейнере проверяемого PHP-образа
с сетью хоста, потому что клиенты сценариев ходят на 127.0.0.1.
"""
from pathlib import Path
import json, os, subprocess, sys, time

HERE = Path(__file__).resolve().parent
SOURCE, TELEMT_IMAGE, PHP_IMAGE, NGINX_IMAGE = Path(sys.argv[1]).resolve(), sys.argv[2], sys.argv[3], sys.argv[4]
PHP = 'vpnbot-telemt-php85'  # имя зашито в сценариях
CASES = ['probe_product', 'probe_activity', 'probe_edges', 'probe_settings', 'probe_conveyor', 'probe_container', 'probe_extra', 'probe_nginx', 'probe_decoy']


def docker(*args):
    return subprocess.run(['docker', *args], check=True, capture_output=True, text=True).stdout.strip()


binary = HERE / 'bin/telemt'
binary.parent.mkdir(exist_ok=True)
holder = docker('create', '--entrypoint', '/bin/true', TELEMT_IMAGE)
try:
    docker('cp', holder + ':/usr/local/bin/telemt', str(binary))
finally:
    docker('rm', holder)
# Сценариям нужен nginx на адресах хоста: запускаем его из проверяемого образа
# с сетью хоста и теми же путями. docker run передаёт SIGTERM контейнеру.
nginx = HERE / 'bin/nginx'
nginx.write_text('#!/bin/sh\nexec docker run --rm --init --network host --label vpnbot.hosted-ci=true '
                 f'-v {HERE}:{HERE} -v {SOURCE}:{SOURCE}:ro --entrypoint nginx {NGINX_IMAGE} "$@"\n')
nginx.chmod(0o755)
version = docker('run', '--rm', '--network', 'none', '--entrypoint', 'cat', TELEMT_IMAGE, '/etc/telemt_version')
# Сайт-приманка бот принимает только по приватному адресу вне loopback: берём
# адрес моста docker0 — он есть на хосте и виден контейнеру с сетью хоста.
bridge = json.loads(subprocess.run(['ip', '-j', '-4', 'addr', 'show', 'docker0'], check=True, capture_output=True,
                                   text=True).stdout)[0]['addr_info'][0]['local']
env = os.environ | {'SOURCE_DIR': str(SOURCE), 'TELEMT_BINARY': str(binary), 'TELEMT_IMAGE': TELEMT_IMAGE,
                    'NGINX_BINARY': str(nginx), 'TELEMT_VERSION': version, 'DECOY_ORIGIN_IP': bridge}
rows = []
docker('run', '-d', '--name', PHP, '--label', 'vpnbot.hosted-ci=true', '--network', 'host',
       '-e', 'TELEMT_VERSION=' + version, '--add-host', 'decoy-origin.test:' + bridge,
       '--entrypoint', 'sleep', '-v', f'{SOURCE}:{SOURCE}:ro', '-v', f'{HERE}:{HERE}', PHP_IMAGE, 'infinity')
try:
    for name in CASES:
        print('START ' + name, flush=True)
        started = time.monotonic()
        with (HERE / (name + '.log')).open('w') as log:
            try:
                code = subprocess.run([sys.executable, str(HERE / (name + '.py'))], env=env, stdout=log,
                                      stderr=subprocess.STDOUT, timeout=900).returncode
            except subprocess.TimeoutExpired:
                code = 'timeout'
        result = HERE / (name.removeprefix('probe_') + '-results.json')
        checks = json.loads(result.read_text()) if result.is_file() else []
        row = {'case': name, 'exit': code, 'seconds': round(time.monotonic() - started, 1),
               'passed': sum(bool(c['ok']) for c in checks), 'total': len(checks)}
        rows.append(row)
        (HERE / 'results.json').write_text(json.dumps(rows, indent=2))
        print(json.dumps(row), flush=True)
finally:
    subprocess.run(['docker', 'rm', '-f', PHP], capture_output=True)
raise SystemExit(1 if any(r['exit'] or not r['total'] or r['passed'] != r['total'] for r in rows) else 0)
