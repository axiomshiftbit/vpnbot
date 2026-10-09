"""Hysteria на настоящем ядре образа: каждая настройка бота принимается ядром.

Запуск: run.py <checkout> <образ hysteria> <образ php>. Сервер и официальный
клиент берутся из проверяемого образа; клиент подключается по hy2://-ссылке,
которую выдаёт бот, и ходит через сервер к тестовому HTTP-серверу.
"""
from pathlib import Path
import json, re, subprocess, sys, time

LAB = Path(__file__).resolve().parent
SOURCE, IMAGE, PHP_IMAGE = Path(sys.argv[1]).resolve(), sys.argv[2], sys.argv[3]
NET, LABEL = 'vpnbot-hysteria-native', 'vpnbot.hosted-ci=true'
SERVER, CLIENT, TARGET = 'vpnbot-hysteria-native-server', 'vpnbot-hysteria-native-client', 'vpnbot-hysteria-native-target'
# Адреса вне диапазонов, которые защитный ACL бота закрывает от клиентов.
SUBNET, SERVER_IP, CLIENT_IP, TARGET_IP = '198.18.77.0/24', '198.18.77.2', '198.18.77.3', '198.18.77.9'
checks = []


def docker(*args, check=True, timeout=120):
    result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError('docker ' + args[0] + ' failed: ' + result.stderr[-300:])
    return (result.stdout + result.stderr).strip()


def check(name, ok, **details):
    checks.append({'name': name, 'ok': bool(ok), **details})
    print(name, 'OK' if ok else 'FAIL ' + json.dumps(details, ensure_ascii=False)[:600], flush=True)


def fetch(url, timeout=6):
    script = ('import urllib.request\np=urllib.request.ProxyHandler({"http":"http://127.0.0.1:8080"})\n'
              'try: print(urllib.request.build_opener(p).open("%s",timeout=%d).read().decode())\n'
              'except Exception as e: print("ERR",type(e).__name__)') % (url, timeout)
    return docker('exec', CLIENT, 'python3', '-c', script, check=False).splitlines()[-1:]


def start(server_yaml, client_yaml):
    docker('rm', '-f', SERVER, CLIENT, check=False)
    (LAB / 'server.yaml').write_text(server_yaml)
    (LAB / 'client.yaml').write_text(client_yaml)
    docker('run', '-d', '--name', SERVER, '--label', LABEL, '--network', NET, '--ip', SERVER_IP, '-v', f'{LAB}:/lab:ro',
           '-v', f'{LAB}/certs:/certs:ro', '--entrypoint', 'hysteria', IMAGE, 'server', '-c', '/lab/server.yaml')
    time.sleep(1.5)
    up = docker('inspect', '-f', '{{.State.Running}}', SERVER, check=False) == 'true'
    docker('run', '-d', '--name', CLIENT, '--label', LABEL, '--network', NET, '--ip', CLIENT_IP, '--add-host', 'hy.example.test:' + SERVER_IP,
           '-v', f'{LAB}:/lab:ro', '--entrypoint', 'hysteria', IMAGE, 'client', '-c', '/lab/client.yaml')
    end = time.monotonic() + 8
    connected = False
    while time.monotonic() < end and not connected:
        time.sleep(.5)
        connected = 'connected to server' in docker('logs', CLIENT, check=False)
    return up, connected


def client_yaml(link):
    return 'server: "%s"\nhttp:\n  listen: 127.0.0.1:8080\nsocks5:\n  listen: 127.0.0.1:1080\n' % link


code = 0
try:
    (LAB / 'certs').mkdir(exist_ok=True)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '2',
                    '-subj', '/CN=hy.example.test', '-addext', 'subjectAltName=DNS:hy.example.test',
                    '-keyout', str(LAB / 'certs/cert_private'), '-out', str(LAB / 'certs/cert_public')], check=True, capture_output=True)
    for name in ('cert_private', 'cert_public'):
        (LAB / 'certs' / name).chmod(0o644)
    version = docker('run', '--rm', '--network', 'none', '--entrypoint', 'hysteria', IMAGE, 'version')
    core = re.search(r'Version:\s*(v[0-9.]+)', version)
    pin = re.search(r'^HYSTERIA_VERSION=(\S+)$', (SOURCE / '.env').read_text(), re.M).group(1)
    check('image_core_matches_pinned_version', bool(core) and core.group(1) == pin, core=core and core.group(1), pin=pin)
    variants = json.loads(subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'php', '-e', 'HYSTERIA_CORE=' + pin,
                                          '-v', f'{SOURCE}:/src:ro', '-v', f'{LAB}:/lab:ro', PHP_IMAGE, '/lab/fixture.php'],
                                         check=True, capture_output=True, text=True, timeout=120).stdout)
    check('bot_generated_every_variant', all(variants.values()) and len(variants) == 12, names=list(variants))
    docker('network', 'rm', NET, check=False)
    docker('network', 'create', '--label', LABEL, '--subnet', SUBNET, NET)
    docker('rm', '-f', TARGET, check=False)
    docker('run', '-d', '--name', TARGET, '--label', LABEL, '--network', NET, '--ip', TARGET_IP, '--entrypoint', 'python3', IMAGE, '-c',
           'import http.server\nclass H(http.server.BaseHTTPRequestHandler):\n def do_GET(s):\n  b=b"target-ok"; s.send_response(200); '
           's.send_header("Content-Length",str(len(b))); s.end_headers(); s.wfile.write(b)\n def log_message(s,*a): pass\n'
           'http.server.HTTPServer(("0.0.0.0",80),H).serve_forever()')
    # Резолвер для проверки ACL: имя open.test ведёт на тестовый сервер, любое
    # другое — на адрес контейнера сборки, как сделал бы чужой домен.
    docker('exec', '-d', TARGET, 'python3', '-c',
           'import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("0.0.0.0",53))\n'
           'while True:\n d,a=s.recvfrom(512); q=d[12:]; n=q.index(0)+5; name=q[:n-4]\n'
           ' ip=bytes([198,18,77,9]) if name.startswith(b"\\x04open") else bytes([10,10,0,7])\n'
           ' t=q[n-4:n-2]\n'
           ' ans=b"\\xc0\\x0c\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x05\\x00\\x04"+ip if t==b"\\x00\\x01" else b""\n'
           ' s.sendto(d[:2]+b"\\x81\\x80\\x00\\x01"+(b"\\x00\\x01" if ans else b"\\x00\\x00")+b"\\x00\\x00\\x00\\x00"+q[:n]+ans,a)')
    for name, variant in variants.items():
        if not variant:
            continue
        up, connected = start(variant['yaml'], client_yaml(variant['link']))
        check(name + '_core_accepts_bot_configuration', up, log=docker('logs', SERVER, check=False)[-300:])
        check(name + '_client_connects_by_bot_link', connected, log=docker('logs', CLIENT, check=False)[-300:])
        check(name + '_traffic_passes', fetch('http://' + TARGET_IP + '/') == ['target-ok'])
        # Защитный ACL бота: адреса контейнеров сборки клиенту недоступны при любой настройке.
        check(name + '_private_network_stays_closed', fetch('http://10.10.0.7/', 4) != ['target-ok'] and fetch('http://127.0.0.1:22/', 4) != ['target-ok'])
    # Домен, который резолвится в адрес контейнера сборки, не обходит защитный ACL —
    # ни сам по себе, ни когда sniff подставляет имя из запроса вместо адреса.
    for name in ('default', 'sniff'):
        up, connected = start(variants[name]['yaml'].replace('10.10.0.5:53', TARGET_IP + ':53'), client_yaml(variants[name]['link']))
        check(name + '_resolver_reaches_public_name', up and connected and fetch('http://open.test/') == ['target-ok'])
        check(name + '_name_resolving_to_private_address_is_blocked', fetch('http://inner.test/', 5) != ['target-ok'])
    # Через SOCKS: HTTP-прокси клиента сам переписывает Host по адресу из запроса.
    script = ('import socket,struct\ns=socket.create_connection(("127.0.0.1",1080),5); s.settimeout(6)\n'
              's.sendall(b"\\x05\\x01\\x00"); s.recv(2)\n'
              's.sendall(b"\\x05\\x01\\x00\\x01"+socket.inet_aton("%s")+struct.pack(">H",80)); r=s.recv(10)\n'
              'd=b""\ntry:\n s.sendall(b"GET / HTTP/1.1\\r\\nHost: %%s\\r\\nConnection: close\\r\\n\\r\\n")\n'
              ' while True:\n  c=s.recv(4096)\n  if not c: break\n  d+=c\nexcept Exception: pass\n'
              'print(d.split(b"\\r\\n\\r\\n")[-1].decode() or "EMPTY")') % TARGET_IP
    by_host = lambda host: docker('exec', CLIENT, 'python3', '-c', script % host, check=False).splitlines()[-1:]
    check('sniff_takes_destination_from_request_host', by_host('open.test') == ['target-ok'], got=by_host('open.test'))
    check('sniffed_private_name_is_blocked', by_host('inner.test') != ['target-ok'], got=by_host('inner.test'))
    # Без sniff имя из запроса на адрес назначения не влияет.
    up, connected = start(variants['default']['yaml'].replace('10.10.0.5:53', TARGET_IP + ':53'), client_yaml(variants['default']['link']))
    check('without_sniff_request_host_is_ignored', up and connected and by_host('inner.test') == ['target-ok'], got=by_host('inner.test'))

    check('menu_switch_selects_gecko', variants['menu-switch-to-gecko']['type'] == 'gecko' and 'obfs=gecko' in variants['menu-switch-to-gecko']['link'])

    # Несовпадение обфускации или пароля — соединения нет.
    gecko, plain, salamander = variants['gecko'], variants['default'], variants['salamander']
    for name, server, link in [('gecko_server_rejects_salamander_client', gecko, salamander['link']),
                               ('gecko_server_rejects_client_without_obfs', gecko, plain['link']),
                               ('salamander_server_rejects_gecko_client', salamander, gecko['link']),
                               ('gecko_server_rejects_wrong_obfs_password', gecko, gecko['link'].replace('obfs-secret', 'other-secret')),
                               ('server_rejects_wrong_password', plain, plain['link'].replace('shared-pass', 'wrong-pass'))]:
        up, connected = start(server['yaml'], client_yaml(link))
        check(name, up and not connected and fetch('http://' + TARGET_IP + '/', 4) != ['target-ok'])
except Exception as error:  # noqa: BLE001 — итог сценария обязан попасть в results.json
    code = 1
    print('ERROR', type(error).__name__, str(error)[:400], flush=True)
finally:
    docker('rm', '-f', SERVER, CLIENT, TARGET, check=False)
    docker('network', 'rm', NET, check=False)
    for name in ('server.yaml', 'client.yaml'):
        (LAB / name).unlink(missing_ok=True)
rows = [{'case': 'tuning', 'exit': code, 'passed': sum(c['ok'] for c in checks), 'total': len(checks)}]
(LAB / 'tuning-results.json').write_text(json.dumps(checks, indent=2, ensure_ascii=False))
(LAB / 'results.json').write_text(json.dumps(rows, indent=2))
print(json.dumps(rows[0]), flush=True)
raise SystemExit(1 if code or not checks or any(not c['ok'] for c in checks) else 0)
