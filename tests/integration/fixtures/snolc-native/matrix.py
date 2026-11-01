"""Матрица snolc: клиент из ZIP бота против контейнера проверяемого образа."""
from pathlib import Path
import concurrent.futures, contextlib, copy, hashlib, json, os, signal, socket, statistics, struct, subprocess, sys, threading, time, zipfile

LAB = Path(__file__).resolve().parent
SOURCE, IMAGE, PHP_IMAGE = sys.argv[1], sys.argv[2], sys.argv[3]
SERVER = 'vpnbot-snolc-native-server'
STATE = LAB / 'proto/snolc/runtime'
CLIENT = LAB / 'client'
PUBLIC, PRIVATE = '198.51.100.2', '10.77.99.2'
VERSION = b'snolc 0.0.4+vpnbot.5 wire 1'
TICK = os.sysconf('SC_CLK_TCK')
# Доля ядра в простое. До исправлений vpnbot.1/vpnbot.3 простой стоил 15–18 %
# и сервера, и клиента; после — около 1 %.
IDLE_LIMIT = 5
RESULTS = {}
PROCS = {}


def check(name, ok, detail=None):
    RESULTS[name] = bool(ok)
    (LAB / 'results/matrix.json').write_text(json.dumps(RESULTS, indent=2))
    # Замеры (CPU, задержка, скорость) печатаются и при успехе: по ним видно запас до порога.
    print(('PASS ' if ok else 'FAIL ') + name + ('' if detail is None else ' ' + json.dumps(detail)), flush=True)
    if not ok:
        raise RuntimeError(name)


def docker(*args, timeout=60):
    return subprocess.run(['docker', *args], check=True, capture_output=True, text=True, timeout=timeout).stdout


def control(*args):
    return json.loads(docker('run', '--rm', '--network', 'none', '--entrypoint', 'php', '-v', f'{SOURCE}:/src:ro',
                             '-v', f'{LAB}:/lab', PHP_IMAGE, '-d', 'error_reporting=32767', '/lab/control.php', *map(str, args)))


def status():
    try:
        return json.loads((STATE / 'status.json').read_text())
    except (OSError, ValueError):
        return {}


def applied(timeout=45):
    want = json.loads((LAB / 'proto/snolc/desired.json').read_text())['revision']
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        s = status()
        if (s.get('revision') or -1) >= want and s.get('phase') in ('running', 'idle', 'disabled') and time.time() - s.get('time', 0) < 10:
            return s
        time.sleep(.3)
    raise RuntimeError('apply_timeout: ' + json.dumps(status()))


def edit(uid, fields=None, action=''):
    control('user', uid, json.dumps(fields or {}), action)
    return applied()


def profile(uid):
    return json.loads((LAB / 'exports' / f'{uid}.json').read_text())


def wait_listener(port, proc):
    end = time.monotonic() + 15
    while time.monotonic() < end and proc.poll() is None:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.3) as sock:
                sock.sendall(b'\x05\x01\x00')
                if sock.recv(2) == b'\x05\x00':
                    return
        except OSError:
            pass
        time.sleep(.1)
    raise RuntimeError('client SOCKS listener not ready')


def start(name, value, port):
    root = LAB / 'clients' / f'{name}-{time.time_ns()}'
    root.mkdir(parents=True)
    (root / 'profile.json').write_text(json.dumps(value))
    (root / 'bin').symlink_to(CLIENT / 'runtime/bin', target_is_directory=True)
    (root / 'packages').symlink_to(CLIENT / 'runtime/packages', target_is_directory=True)
    log = (root / 'run.log').open('wb')
    proc = subprocess.Popen([sys.executable, str(CLIENT / 'client.py'), '--directory', str(root), '--profile', str(root / 'profile.json'),
                             '--socks-port', str(port)], stdout=log, stderr=log, start_new_session=True)
    PROCS[name] = (proc, log)
    wait_listener(port, proc)
    return port


def stop(name):
    item = PROCS.pop(name, None)
    if item:
        proc, log = item
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL); proc.wait()
        log.close()


def http(port=1085, host=PUBLIC, size=1024, timeout=None):
    timeout = timeout or (60 if size > 1024 * 1024 else 7)
    return subprocess.run(['curl', '--noproxy', '', '--socks5-hostname', f'127.0.0.1:{port}', '--max-time', str(timeout),
                           '-fsS', f'http://{host}:8082/bytes/{size}'], capture_output=True)


def good(port=1085, host=PUBLIC, size=1024):
    r = http(port, host, size)
    return r.returncode == 0 and r.stdout == b'S' * size


def recover(port=1085, seconds=40):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if good(port):
            return True
        time.sleep(1)
    return False


def denied(port=1085, host=PUBLIC, seconds=6):
    """Отказ, а не медленное соединение: все попытки за время окна неудачны."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if good(port, host):
            return False
        time.sleep(.5)
    return True


def rx(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError()
        data += chunk
    return data


@contextlib.contextmanager
def association(port=1085, host=PUBLIC, domain=False):
    """UDP ASSOCIATE: отдаёт функцию отправки одного кадра и сокет ответов."""
    with socket.create_connection(('127.0.0.1', port), timeout=5) as control_socket:
        control_socket.sendall(b'\x05\x01\x00')
        if rx(control_socket, 2) != b'\x05\x00':
            raise OSError('socks method rejected')
        control_socket.sendall(b'\x05\x03\x00\x01' + b'\0' * 6)
        head = rx(control_socket, 4)
        if head[1]:
            raise OSError('udp associate rejected')
        rx(control_socket, 4 if head[3] == 1 else 16)
        relay = struct.unpack('!H', rx(control_socket, 2))[0]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            # Пачка из 16 кадров по 64 КиБ больше буфера по умолчанию; поднять предел может только root.
            try:
                sock.setsockopt(socket.SOL_SOCKET, getattr(socket, 'SO_RCVBUFFORCE', 33), 8 * 1024 * 1024)
            except PermissionError:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
            sock.settimeout(10)
            target = (b'\x03' + bytes([len(host)]) + host.encode()) if domain else b'\x01' + socket.inet_aton(host)
            yield (lambda data: sock.sendto(b'\0\0\0' + target + struct.pack('!H', 9099) + data, ('127.0.0.1', relay))), sock


def udp(port=1085, host=PUBLIC, size=512, domain=False, count=1):
    try:
        with association(port, host, domain) as (send, sock):
            for _ in range(count):
                data = os.urandom(size)
                send(data)
                if not sock.recv(65535).endswith(data):
                    return False
            return True
    except (OSError, EOFError):
        return False


def udp_burst(count, size, port=1085):
    """Все кадры подряд без ожидания ответа, затем все ответы в любом порядке.

    Пачка идёт по уже открытому потоку: кадры, отправленные до открытия потока
    UDP на сервере, ядро 0.0.4 не доставляет. Мгновенную пачку больше очереди
    клиента (десятки датаграмм по 64 КиБ при туннеле ~13 Мбит/с) ядро
    отбрасывает — для UDP это допустимо, поэтому размеры пачек реалистичные.
    """
    try:
        with association(port) as (send, sock):
            warm = os.urandom(64)
            send(warm)
            if not sock.recv(65535).endswith(warm):
                return False
            sent = [os.urandom(size) for _ in range(count)]
            for data in sent:
                send(data)
            received = {sock.recv(65535)[-size:] for _ in range(count)}
            return received == set(sent)
    except (OSError, EOFError):
        return False


def check_burst(name, count, size):
    """Пачка без пауз — тот же UDP: клиентское ядро 0.0.4 изредка теряет кадр
    из очереди, хотя счётчики ядра Linux чисты (прогон 39712137062). Повторяем
    один раз: регрессия доставки (кадр застрял в буфере) провалит обе попытки,
    а повтор виден в журнале."""
    first = udp_burst(count, size)
    check(name, first or udp_burst(count, size), None if first else {'retried': True})


def socks_tcp(port, host, target_port):
    sock = socket.create_connection(('127.0.0.1', port), timeout=10)
    sock.sendall(b'\x05\x01\x00')
    if rx(sock, 2) != b'\x05\x00':
        raise OSError('socks method rejected')
    sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(host) + struct.pack('!H', target_port))
    head = rx(sock, 4)
    if head[1]:
        raise OSError('socks connect rejected')
    rx(sock, (4 if head[3] == 1 else 16) + 2)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def rtt_ms(count=50):
    """Медиана круга 32 байт по одному потоку: опрос ядра раз в 10 мс дал бы 10+ мс."""
    with socks_tcp(1085, PUBLIC, 8083) as sock:
        samples = []
        for _ in range(count):
            started = time.perf_counter()
            sock.sendall(b'r' * 32)
            if rx(sock, 32) != b'r' * 32:
                raise OSError('echo mismatch')
            samples.append((time.perf_counter() - started) * 1000)
    return round(statistics.median(samples), 2)


def hosts(name, address):
    """/etc/hosts контейнера сервера: проверка DNS на стороне сервера и подмены адреса."""
    path = Path(docker('inspect', '-f', '{{.HostsPath}}', SERVER).strip())
    lines = [line for line in path.read_text().splitlines() if name not in line]
    path.write_text('\n'.join(lines + [address + ' ' + name]) + '\n')


def server_ready(timeout=40):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if status().get('running') and time.time() - status().get('time', 0) < 10:
            return True
        time.sleep(.5)
    return False


def cpu_usec():
    stat = docker('exec', SERVER, 'cat', '/sys/fs/cgroup/cpu.stat')
    return int(next(line.split()[1] for line in stat.splitlines() if line.startswith('usage_usec')))


def proc_stat(pid):
    return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()


def client_core(name='main'):
    """PID ядра snolc, которое запустил client.py этого клиента (та же группа процессов)."""
    group = PROCS[name][0].pid
    for entry in Path('/proc').iterdir():
        try:
            if entry.name.isdigit() and int(proc_stat(entry.name)[2]) == group and os.readlink(entry / 'exe').endswith('/snolc'):
                return int(entry.name)
        except (OSError, ValueError, IndexError):
            pass
    raise RuntimeError('client core not found')


def server_core():
    """PID ядра сервера на хосте: процесс «snolc run» в контейнере."""
    for line in docker('top', SERVER, '-eo', 'pid,args').splitlines()[1:]:
        pid, args = line.split(None, 1)
        if '/snolc run ' in args:
            return int(pid)
    raise RuntimeError('server core not found')


def footprint(pid):
    rss = next(line for line in Path(f'/proc/{pid}/status').read_text().splitlines() if line.startswith('VmRSS:'))
    return {'fds': len(os.listdir(f'/proc/{pid}/fd')), 'rss_kib': int(rss.split()[1])}


def idle_load(client=None, seconds=10):
    """Доля ядра за окно простоя: весь контейнер сервера и ядро клиента."""
    time.sleep(3)  # ожидание ядра растёт до 10 мс только после паузы в передаче
    pid = client_core(client) if client else None
    cpu = lambda: (int(proc_stat(pid)[11]) + int(proc_stat(pid)[12])) / TICK if pid else 0
    server, own, started = cpu_usec(), cpu(), time.monotonic()
    time.sleep(seconds)
    span = time.monotonic() - started
    return {'server': round((cpu_usec() - server) / (span * 1e6) * 100, 2), 'client': round((cpu() - own) / span * 100, 2)}


def tunnel_events():
    """Подключения и обрывы туннелей в журнале ядра сервера."""
    text = (STATE / 'core.log').read_bytes()
    return {'established': text.count(b'state: "established"'), 'errors': text.count(b'ModuleError')}


def restarts(name='main'):
    """Сколько раз client.py перезапускал зависшее ядро."""
    return (Path(PROCS[name][1].name).read_bytes()).count('повторное подключение'.encode())


def upload(size=64 * 1024, port=1085):
    data = os.urandom(size)
    r = subprocess.run(['curl', '--noproxy', '', '--socks5-hostname', f'127.0.0.1:{port}', '--max-time', '30', '-fsS',
                        '--data-binary', '@-', f'http://{PUBLIC}:8082/upload'], input=data, capture_output=True)
    return r.returncode == 0 and r.stdout.decode() == hashlib.sha256(data).hexdigest()


def soak(seconds=60):
    stop_at = time.monotonic() + seconds
    failures, rounds = [], [0]
    lock = threading.Lock()

    def worker(port, kind):
        while time.monotonic() < stop_at:
            ok = good(port, size=256 * 1024) if kind == 'tcp' else udp(port, size=1200, count=4)
            with lock:
                rounds[0] += 1
                if not ok:
                    failures.append((port, kind))
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        for future in [pool.submit(worker, port, kind) for port in (1085, 1086) for kind in ('tcp', 'tcp', 'udp', 'udp')]:
            future.result()
    return rounds[0], failures


def main():
    a = control('read')['users'][0]
    applied()
    check('server-image-version', docker('exec', SERVER, '/opt/snolc/runtime/bin/snolc', '--version').strip().encode() == VERSION)
    check('server-running-with-active-user', server_ready())
    load = idle_load()
    check('idle-cpu-server-without-clients', load['server'] < IDLE_LIMIT, load)
    # ZIP выдаёт код бота (как кнопка в карточке и личная ссылка).
    control('zip', a)
    archive = LAB / 'exports' / f'{a}.zip'
    seed = json.loads((LAB / 'proto/snolc/desired.json').read_text())['settings']['server_seed']
    with zipfile.ZipFile(archive) as bundle:
        names = set(bundle.namelist())
        check('zip-contents', names == {'profile.json', 'client.py', 'snolc_config.py', 'releases.json',
                                         'module-options.json', 'README.txt', 'client-patches.zip'}, sorted(names))
        check('zip-has-no-server-seed', all(seed.encode() not in bundle.read(n) for n in names))
        bundle.extractall(CLIENT)
    check('zip-profile-matches-bot', json.loads((CLIENT / 'profile.json').read_text()) == profile(a))
    # Без сети: ZIP обязан содержать все модули и исправленное ядро (42c9d99).
    prepared = subprocess.run(['unshare', '--net', sys.executable, 'client.py', '--install', '--prepare'], cwd=CLIENT,
                              capture_output=True, text=True, timeout=60)
    check('client-install-offline-and-prepare', prepared.returncode == 0 and 'Конфигурация проверена.' in prepared.stdout,
          {'rc': prepared.returncode, 'out': prepared.stdout[-300:], 'err': prepared.stderr[-300:]})
    # Ядро и все модули клиента — сборка из исходников (client-patches.zip), не бинарники выпуска.
    with zipfile.ZipFile(CLIENT / 'client-patches.zip') as patches:
        installed = {'snolc': CLIENT / 'runtime/bin/snolc'} | {
            name: CLIENT / 'runtime/packages/store' / name[9:-3].replace('_', '-') / name
            for name in patches.namelist() if name.startswith('libsnolc_')}
        check('client-runs-only-source-built-components', len(installed) == 5
              and all(path.read_bytes() == patches.read(name) for name, path in installed.items()), sorted(installed))
    binary = (CLIENT / 'runtime/bin/snolc').read_bytes()
    check('client-is-glibc-build', b'/lib64/ld-linux-x86-64.so.2' in binary[:4096])
    check('client-version', subprocess.run([str(CLIENT / 'runtime/bin/snolc'), '--version'], capture_output=True).stdout.strip() == VERSION)

    start('main', profile(a), 1085)
    check('tcp-small', recover())
    check('udp-small', udp())
    load = idle_load('main')
    check('idle-cpu-connected-client', load['server'] < IDLE_LIMIT and load['client'] < IDLE_LIMIT, load)
    # Открытый, но молчащий поток и UDP-ассоциация: vpnbot.3 снижал опрос и в этом режиме.
    with socks_tcp(1085, PUBLIC, 8083) as held, association() as (send, sock):
        held.sendall(b'hold')
        send(b'hold')
        opened = rx(held, 4) == b'hold' and sock.recv(65535).endswith(b'hold')
        load = idle_load('main')
        held.sendall(b'more')
        opened = opened and rx(held, 4) == b'more'
    check('idle-cpu-open-tcp-and-udp', opened and load['server'] < IDLE_LIMIT and load['client'] < IDLE_LIMIT, load)
    rtt = rtt_ms()
    check('tcp-rtt-median-below-5ms', rtt < 5, {'ms': rtt})
    check('download-8MiB', good(size=8 * 1024 * 1024))
    started = time.monotonic()
    fetched = good(size=32 * 1024 * 1024)
    rate = round(32 * 8 * 1.048576 / (time.monotonic() - started), 1)
    # SSH + Noise в пользовательском режиме: 11–13 Мбит/с; регрессия ожидания
    # ядра (сентябрь 2026) давала 3,3–4,9 Мбит/с.
    check('download-32MiB-above-7-Mbit', fetched and rate > 7, {'mbit': rate})
    data = os.urandom(2 * 1024 * 1024)
    (LAB / 'upload.bin').write_bytes(data)
    r = subprocess.run(['curl', '--noproxy', '', '--socks5-hostname', '127.0.0.1:1085', '--max-time', '90', '-fsS',
                        '--data-binary', '@' + str(LAB / 'upload.bin'), f'http://{PUBLIC}:8082/upload'], capture_output=True)
    check('upload-2MiB-exact-hash', r.returncode == 0 and r.stdout.decode() == hashlib.sha256(data).hexdigest())
    for size in (1, 1200, 4096, 16384, 60000, 65000, 65497):
        check(f'udp-payload-{size}', udp(size=size))
    # Регрессия 0.0.4+vpnbot.1: последний UDP-кадр ждал в буфере другого трафика.
    check('udp-16-sequential-max-datagrams', udp(size=65497, count=16))
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        parallel = list(pool.map(lambda _: udp(size=60000, count=4), range(8)))
    check('udp-parallel-8x4x60000', all(parallel), parallel)
    check_burst('udp-burst-16x4096-no-loss', 16, 4096)
    check_burst('udp-burst-6x32768-no-loss', 6, 32768)
    check('udp-after-burst', udp())
    # Регрессия vpnbot.3: после TCP-нагрузки параллельные максимальные UDP-кадры
    # терялись при полной очереди устройства и обгоняли открытие потока.
    with concurrent.futures.ThreadPoolExecutor(12) as pool:
        loads = [pool.submit(good, size=4 * 1024 * 1024) for _ in range(4)]
        time.sleep(1)
        flows = list(pool.map(lambda _: udp(size=65497, count=4), range(8)))
        loaded = [future.result() for future in loads]
    check('udp-parallel-8x4x65497-under-tcp-load', all(flows) and all(loaded), {'udp': flows, 'tcp': loaded})
    with concurrent.futures.ThreadPoolExecutor(16) as pool:
        flows = list(pool.map(lambda _: good(size=64 * 1024), range(16)))
    check('tcp-16-parallel-flows', all(flows), flows)
    # Регрессия vpnbot.3: данные нового потока опережали команду открытия и рвали туннель.
    events = tunnel_events()
    with concurrent.futures.ThreadPoolExecutor(32) as pool:
        sent = list(pool.map(lambda _: upload(), range(32)))
    check('tcp-32-parallel-uploads-exact-hash', all(sent), sent)
    check('parallel-opens-keep-tunnel', tunnel_events() == events and restarts() == 0, [events, tunnel_events(), restarts()])

    # Приватные сети закрыты, хотя цель по приватному адресу доступна серверу.
    check('private-target-reachable-from-server', docker('exec', SERVER, 'python3', '-c',
          f'import socket;socket.create_connection(("{PRIVATE}",8082),3).close();print("ok")').strip() == 'ok')
    for host in (PRIVATE, '127.0.0.1', '169.254.169.254'):
        check('private-tcp-denied-' + host, http(host=host, timeout=4).returncode != 0)
    check('private-udp-denied', not udp(host=PRIVATE))
    hosts('public.snolc.test', PUBLIC)
    check('server-side-dns-tcp', good(host='public.snolc.test'))
    check('server-side-dns-udp', udp(host='public.snolc.test', domain=True))
    hosts('public.snolc.test', PRIVATE)
    check('dns-rebinding-private-tcp-denied', http(host='public.snolc.test', timeout=4).returncode != 0)
    check('dns-rebinding-private-udp-denied', not udp(host='public.snolc.test', domain=True))
    hosts('public.snolc.test', PUBLIC)
    check('public-dns-restored', good(host='public.snolc.test'))
    with socket.create_connection(('198.51.100.3', 24448), timeout=5) as probe:
        probe.sendall(os.urandom(4096))
    check('garbage-on-port-does-not-break-service', good())
    # Регрессии vpnbot.1: закрытые потоки и UDP после закрытия SOCKS5 не освобождались.
    # Лимит пользователя — 32 одновременных потока: утечка закрыла бы доступ.
    server_pid, client_pid = server_core(), client_core()
    before = [footprint(server_pid), footprint(client_pid)]
    # UDP — по 8 одновременно: закрытый поток UDP освобождается с задержкой, и 16
    # одновременных ассоциаций со сменой упираются в лимит 32 (замер 2026-10-16).
    with concurrent.futures.ThreadPoolExecutor(16) as pool:
        churn = list(pool.map(lambda _: good(size=4096), range(300)))
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        churn += list(pool.map(lambda _: udp(size=300), range(100)))
    check('churn-300-tcp-100-udp-within-flow-limit', all(churn), {'failed': churn.count(False)})
    time.sleep(5)
    after = [footprint(server_pid), footprint(client_pid)]
    check('server-fds-released-after-churn', after[0]['fds'] <= before[0]['fds'] + 8, [before[0], after[0]])
    check('client-fds-released-after-churn', after[1]['fds'] <= before[1]['fds'] + 8, [before[1], after[1]])
    check('server-memory-bounded-after-churn', after[0]['rss_kib'] < before[0]['rss_kib'] + 32768, [before[0], after[0]])
    check('new-flows-after-churn', good() and udp())
    stop('main')

    original = profile(a)
    for field in ('ssh_password', 'noise_public_key', 'ssh_public_key', 'credential'):
        bad = copy.deepcopy(original)
        if field == 'credential':
            bad[field] = 'ab' * 32
        elif field == 'ssh_public_key':
            key = original['server'][field]
            bad['server'][field] = key[:-4] + ('BBBB' if key.endswith('AAAA') else 'AAAA')
        else:
            bad['server'][field] = 'ab' * 32
        start('bad', bad, 1087)
        check('reject-wrong-' + field, denied(1087))
        stop('bad')
    start('main', original, 1085)
    check('correct-credentials-recover', recover())
    time.sleep(6)
    usage = json.loads((STATE / 'usage.json').read_text())['users'][a]
    check('per-user-byte-accounting', usage['upload'] > 2 * 1024 * 1024 and usage['download'] > 8 * 1024 * 1024, usage)

    edit(a, {'enabled': False})
    check('disable-closes-access', denied())
    check('disabled-udp-denied', not udp())
    check('disabled-profile-not-issued', not (LAB / 'exports' / f'{a}.json').exists())
    edit(a, {'enabled': True})
    check('enable-restores-unchanged-credentials', recover())
    edit(a, {}, 'rotate')
    check('rotation-rejects-old-credential', denied())
    stop('main')
    start('main', profile(a), 1085)
    check('rotated-credential-connects', recover())
    check('rotation-keeps-server-keys', profile(a)['server'] == original['server'])
    edit(a, {'expires': int(time.time()) + 4})
    time.sleep(5)
    check('native-expiration-enforced', denied())
    edit(a, {'expires': None})
    check('expiration-removed', recover())
    edit(a, {'quota': 131072}, 'reset')
    r = http(size=1024 * 1024)
    check('native-quota-interrupts-large-transfer', r.returncode != 0 and len(r.stdout) <= 131072, {'delivered': len(r.stdout)})
    check('exhausted-quota-rejects-tcp', denied())
    check('exhausted-quota-rejects-udp', not udp())
    docker('restart', '-t', '20', SERVER, timeout=60)
    applied()
    check('quota-survives-container-restart', denied())
    edit(a, {'quota': None}, 'reset')
    check('quota-reset-reopens-access', recover())
    # Регрессия vpnbot.3 (модули): остаток резерва меньше кадра пополнялся только
    # на контрольной точке, и параллельный UDP ждал больше 8 с.
    edit(a, {'quota': 16 * 1024 * 1024}, 'reset')

    def worst_wait(_):
        worst = 0
        try:
            with association() as (send, sock):
                for _ in range(6):
                    data, started = os.urandom(60000), time.monotonic()
                    send(data)
                    if not sock.recv(65535).endswith(data):
                        return None
                    worst = max(worst, round(time.monotonic() - started, 2))
        except (OSError, EOFError):
            return None
        return worst
    with concurrent.futures.ThreadPoolExecutor(4) as pool:
        waits = list(pool.map(worst_wait, range(4)))
    check('udp-large-datagrams-under-quota-not-starved', all(w is not None and w < 2.5 for w in waits), waits)
    edit(a, {'quota': 262144}, 'reset')
    with concurrent.futures.ThreadPoolExecutor(3) as pool:
        runs = list(pool.map(lambda _: http(size=1024 * 1024, timeout=20), range(3)))
    delivered = sum(len(r.stdout) for r in runs)
    check('concurrent-quota-3-transfers-bounded', all(r.returncode for r in runs) and delivered <= 262144, {'delivered': delivered})
    edit(a, {'quota': None}, 'reset')
    check('quota-cleared-after-concurrency', recover())

    control('configure', '{}', '0')
    applied()
    check('service-off-closes-port', denied())
    control('configure', '{}', '1')
    applied()
    check('service-on-keeps-credentials', recover())
    docker('restart', '-t', '20', SERVER, timeout=60)
    applied()
    check('client-recovers-after-server-restart', recover(seconds=60))
    # Сервер замер на 25 с (процессы заморожены, сеть контейнера жива): клиент не
    # должен остаться без туннеля. Сам запускатель проверяет snolc_service_test.
    docker('pause', SERVER)
    time.sleep(25)
    docker('unpause', SERVER)
    check('client-survives-server-stall-25s', recover(seconds=60), {'launcher_restarts': restarts()})

    b = control('add', 'Native B')['id']
    applied()
    start('second', profile(b), 1086)
    check('second-user-connects', recover(1086))
    rounds, failures = soak(60)
    check('soak-60s-two-users-mixed-tcp-udp', not failures and rounds > 40, {'rounds': rounds, 'failures': failures[:10]})
    edit(a, {'enabled': False})
    check('second-user-unaffected-by-first', recover(1086))
    check('first-user-still-denied', denied())
    edit(a, {'enabled': True})
    check('first-user-back', recover())

    pid = status()['pid']
    docker('exec', SERVER, 'python3', '-c', 'import json,os,signal;os.kill(json.load(open("/state/status.json"))["pid"],signal.SIGKILL)')
    end = time.monotonic() + 40
    while time.monotonic() < end and not (status().get('running') and status().get('pid') not in (None, pid)):
        time.sleep(.5)
    check('core-sigkill-detected-and-restarted', status().get('running') and status().get('pid') not in (None, pid), status())
    check('core-sigkill-recovery-tcp', recover())
    check('core-sigkill-recovery-udp', udp())

    # Резервная копия бота: восстановление переносит учёт в новую базу policy.
    time.sleep(6)
    before = json.loads((STATE / 'usage.json').read_text())['users'][a]
    control('snapshot')
    control('restore')
    applied()
    admin = json.loads((STATE / 'admin.json').read_text())
    check('restore-selects-new-ledger', admin['database'].startswith('policy-') and admin['database'] != 'policy.redb')
    check('restore-keeps-profile-working', recover())
    time.sleep(6)
    after = json.loads((STATE / 'usage.json').read_text())['users'][a]
    check('restore-keeps-usage', after['upload'] >= before['upload'] and after['download'] >= before['download'], [before, after])

    edit(b, {}, 'delete')
    check('deleted-user-denied', denied(1086))
    stop('second')

    # Простой после всей нагрузки: ни сервер, ни клиент не остаются в активном опросе.
    load = idle_load('main')
    print('idle cpu percent', load, flush=True)
    check('idle-cpu-after-load', load['server'] < IDLE_LIMIT and load['client'] < IDLE_LIMIT, load)
    inspection = json.loads(docker('inspect', SERVER))[0]
    check('no-oom-and-same-restrictions', not inspection['State']['OOMKilled'] and inspection['HostConfig']['ReadonlyRootfs']
          and inspection['HostConfig']['CapDrop'] == ['ALL'] and inspection['HostConfig']['Memory'] == 256 * 1024 * 1024)
    print('SUMMARY', sum(RESULTS.values()), len(RESULTS), flush=True)


if __name__ == '__main__':
    try:
        main()
    finally:
        for key in list(PROCS):
            stop(key)
