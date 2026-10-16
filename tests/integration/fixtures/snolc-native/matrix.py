"""Матрица snolc: клиент из ZIP бота против контейнера проверяемого образа."""
from pathlib import Path
import concurrent.futures, copy, hashlib, json, os, signal, socket, struct, subprocess, sys, threading, time, zipfile

LAB = Path(__file__).resolve().parent
SOURCE, IMAGE, PHP_IMAGE = sys.argv[1], sys.argv[2], sys.argv[3]
SERVER = 'vpnbot-snolc-native-server'
STATE = LAB / 'proto/snolc/runtime'
CLIENT = LAB / 'client'
PUBLIC, PRIVATE = '198.51.100.2', '10.77.99.2'
VERSION = b'snolc 0.0.4+vpnbot.3 wire 1'
RESULTS = {}
PROCS = {}


def check(name, ok, detail=None):
    RESULTS[name] = bool(ok)
    (LAB / 'results/matrix.json').write_text(json.dumps(RESULTS, indent=2))
    print(('PASS ' if ok else 'FAIL ') + name + ('' if ok or detail is None else ' ' + json.dumps(detail)), flush=True)
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


def udp(port=1085, host=PUBLIC, size=512, domain=False, count=1):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=5) as control_socket:
            control_socket.sendall(b'\x05\x01\x00')
            assert rx(control_socket, 2) == b'\x05\x00'
            control_socket.sendall(b'\x05\x03\x00\x01' + b'\0' * 6)
            head = rx(control_socket, 4)
            if head[1]:
                return False
            rx(control_socket, 4 if head[3] == 1 else 16)
            relay = struct.unpack('!H', rx(control_socket, 2))[0]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(10)
                target = (b'\x03' + bytes([len(host)]) + host.encode()) if domain else b'\x01' + socket.inet_aton(host)
                for _ in range(count):
                    data = os.urandom(size)
                    sock.sendto(b'\0\0\0' + target + struct.pack('!H', 9099) + data, ('127.0.0.1', relay))
                    if not sock.recv(65535).endswith(data):
                        return False
                return True
    except (OSError, EOFError, AssertionError):
        return False


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
    prepared = subprocess.run([sys.executable, 'client.py', '--install', '--prepare'], cwd=CLIENT, capture_output=True, text=True, timeout=60)
    check('client-install-and-prepare', prepared.returncode == 0 and 'Конфигурация проверена.' in prepared.stdout,
          {'rc': prepared.returncode, 'out': prepared.stdout[-300:], 'err': prepared.stderr[-300:]})
    binary = (CLIENT / 'runtime/bin/snolc').read_bytes()
    check('client-is-glibc-build', b'/lib64/ld-linux-x86-64.so.2' in binary[:4096])
    check('client-version', subprocess.run([str(CLIENT / 'runtime/bin/snolc'), '--version'], capture_output=True).stdout.strip() == VERSION)

    start('main', profile(a), 1085)
    check('tcp-small', recover())
    check('udp-small', udp())
    check('download-8MiB', good(size=8 * 1024 * 1024))
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
    with concurrent.futures.ThreadPoolExecutor(16) as pool:
        flows = list(pool.map(lambda _: good(size=64 * 1024), range(16)))
    check('tcp-16-parallel-flows', all(flows), flows)

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

    control('configure', '{}', '0')
    applied()
    check('service-off-closes-port', denied())
    control('configure', '{}', '1')
    applied()
    check('service-on-keeps-credentials', recover())

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

    # Простой с подключённым клиентом: исправление vpnbot.3 снижало опрос ядра.
    time.sleep(3)
    first, started = cpu_usec(), time.monotonic()
    time.sleep(10)
    load = (cpu_usec() - first) / ((time.monotonic() - started) * 1e6) * 100
    print('idle cpu percent', round(load, 1), flush=True)
    check('idle-cpu-below-60-percent-of-core', load < 60, {'percent': round(load, 1)})
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
