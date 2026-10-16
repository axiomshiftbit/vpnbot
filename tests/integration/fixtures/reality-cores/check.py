#!/usr/bin/env python3
"""Какие отпечатки uTLS принимает сервер REALITY каждого ядра.

check.py СЕРТИФИКАТ КЛЮЧ [--server-extra JSON] ЯДРО [ЯДРО…] -- ОТПЕЧАТОК…

Для каждого ядра: сервер REALITY с локальным сайтом-маской (TLS 1.3) и клиент
того же ядра с каждым отпечатком. Выход сервера — заглушка с HTTP-ответом:
код 403 через туннель возможен только после рукопожатия, которое сервер
признал своим. Внешняя сеть не нужна. Печатает JSON: ядро → отпечаток → bool.
--server-extra — поля realitySettings сервера, выданные кодом бота (requireMlkem).
"""
import json, os, re, socket, ssl, subprocess, sys, threading, time

CERT, KEY, CORES = sys.argv[1], sys.argv[2], sys.argv[3:]
FINGERPRINTS = sys.argv[sys.argv.index('--') + 1:] if '--' in sys.argv else []
if '--' in CORES:
    CORES = CORES[:CORES.index('--')]
EXTRA = {}
if CORES[:1] == ['--server-extra']:
    with open(CORES[1]) as stream:
        EXTRA = json.load(stream)
    CORES = CORES[2:]
UUID, SID, SNI = '11111111-1111-4111-8111-111111111111', 'abcd1234', 'mask.example.test'


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def wait_port(port):
    for _ in range(80):
        try:
            socket.create_connection(('127.0.0.1', port), timeout=0.2).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def mask(port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(CERT, KEY)
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', port))
    server.listen(64)

    def serve(conn):
        try:
            conn.settimeout(3)
            with context.wrap_socket(conn, server_side=True) as tls:
                tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nMASK')
        except (OSError, ssl.SSLError):
            pass
        finally:
            conn.close()

    while True:
        conn, _ = server.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


mask_port = free_port()
threading.Thread(target=mask, args=(mask_port,), daemon=True).start()
result = {}
for core in CORES:
    keys = subprocess.run([core, 'x25519'], capture_output=True, text=True).stdout
    private = re.search(r'Private ?[Kk]ey:\s*(\S+)', keys)
    public = re.search(r'(?:Password \(PublicKey\)|Public ?[Kk]ey|Password):\s*(\S+)', keys)
    version = subprocess.run([core, 'version'], capture_output=True, text=True).stdout.splitlines()[0]
    if not private or not public:
        result[os.path.basename(core)] = {'error': 'no keys', 'version': version}
        continue
    server_port = free_port()
    with open('/tmp/server.json', 'w') as f:
        json.dump({'log': {'loglevel': 'warning'}, 'inbounds': [{
            'listen': '127.0.0.1', 'port': server_port, 'protocol': 'vless',
            'settings': {'clients': [{'id': UUID, 'flow': 'xtls-rprx-vision'}], 'decryption': 'none'},
            'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {
                'dest': '127.0.0.1:%d' % mask_port, 'serverNames': [SNI], 'privateKey': private.group(1), 'shortIds': [SID], **EXTRA}}}],
            'outbounds': [{'protocol': 'blackhole', 'settings': {'response': {'type': 'http'}}}]}, f)
    server = subprocess.Popen([core, 'run', '-config', '/tmp/server.json'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    accepted = {}
    try:
        if not wait_port(server_port):
            result[os.path.basename(core)] = {'error': 'server did not start', 'version': version}
            continue
        for fingerprint in FINGERPRINTS:
            socks = free_port()
            with open('/tmp/client.json', 'w') as f:
                json.dump({'log': {'loglevel': 'warning'},
                           'inbounds': [{'listen': '127.0.0.1', 'port': socks, 'protocol': 'socks', 'settings': {'udp': False}}],
                           'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{'address': '127.0.0.1', 'port': server_port,
                                          'users': [{'id': UUID, 'flow': 'xtls-rprx-vision', 'encryption': 'none'}]}]},
                                          'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {
                                              'serverName': SNI, 'fingerprint': fingerprint, 'publicKey': public.group(1), 'shortId': SID}}}]}, f)
            client = subprocess.Popen([core, 'run', '-config', '/tmp/client.json'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ok = False
            try:
                if wait_port(socks):
                    # Три попытки: случайные отпечатки выбирают образец заново на каждое соединение.
                    for _ in range(3):
                        code = subprocess.run(['curl', '-s', '-o', '/dev/null', '-m', '4', '-w', '%{http_code}', '--socks5-hostname',
                                               '127.0.0.1:%d' % socks, 'http://through-reality.example.test/'], capture_output=True, text=True).stdout
                        if code == '403':
                            ok = True
                            break
            finally:
                client.kill()
                client.wait()
            accepted[fingerprint] = ok
        result[os.path.basename(core)] = {'version': version, 'accepted': accepted}
    finally:
        server.kill()
        server.wait()
print(json.dumps(result))
