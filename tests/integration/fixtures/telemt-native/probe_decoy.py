"""Свой сайт-приманка WEB на настоящем ядре: http_upstream по адресу и по имени.

Первая часть — само ядро: что telemt принимает, что отвергает и когда не
стартует вовсе. На этих фактах стоит код бота (порт 8080, срок разрешения
имени, поздняя проба после старта). Вторая часть — бот: его проверки адреса,
его конфигурация и его откат на встроенную страницу, на том же ядре.
"""
from pathlib import Path
import http.client, http.server, ipaddress, json, os, socket, subprocess, sys, threading, time
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'support'))
import probe_limits as p
p.ROOT = HERE / 'decoy-cases'; p.ROOT.mkdir(exist_ok=True)
SOURCE = Path(os.environ['SOURCE_DIR']); p.BINARY = Path(os.environ['TELEMT_BINARY'])
BRIDGE = os.environ['DECOY_ORIGIN_IP']
NAMES = tuple(int(x) for x in os.environ['TELEMT_VERSION'].lstrip('vV').split('-')[0].split('.')[:3]) >= (3, 5, 14)
STATIC = '[web.vhosts.decoy]\nmode = "static_directory"\ndirectory = "{root}/decoy"\n'
results = []


def check(name, ok, **details):
    results.append({'name': name, 'ok': bool(ok), **details})
    (HERE / 'decoy-results.json').write_text(json.dumps(results, indent=2))
    print(name, 'OK' if ok else 'FAIL', json.dumps(details) if details else '', flush=True)
    if not ok:
        raise AssertionError(name)


class Origin:
    """Обычный сайт во внутренней сети: помнит, что именно ему передал telemt."""
    def __init__(self, address):
        seen = self.seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get('Host')))
                body = b'DECOY-ORIGIN ' + self.path.encode()
                self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass
        # localhost может разрешаться в ::1 и несколько адресов 127/8.
        # Ядро вправе выбрать любой: тестовый сайт должен слушать каждый.
        addresses = list(dict.fromkeys(row[4][0] for row in socket.getaddrinfo(
            address, 0, type=socket.SOCK_STREAM))) if address == 'localhost' else [address]
        self.servers, self.port = [], 0
        for host in addresses:
            if address == 'localhost':
                assert ipaddress.ip_address(host).is_loopback
            class Server(http.server.ThreadingHTTPServer):
                address_family = socket.AF_INET6 if ':' in host else socket.AF_INET
            server = Server((host, self.port), Handler)
            self.port = server.server_address[1]
            self.servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()

    def close(self):
        for server in self.servers:
            server.shutdown(); server.server_close()


def page(core, path='/'):
    """Запрос к WEB-хосту без секрета — то, что видит посторонний."""
    connection = http.client.HTTPConnection('127.0.0.1', core.w, timeout=6)
    try:
        connection.request('GET', path, headers={'Host': p.HOST, 'X-Forwarded-For': '198.51.100.77'})
        response = connection.getresponse()
        return response.status, response.read()
    except OSError:
        return 0, b''
    finally:
        connection.close()


def core(name, decoy, timeouts=''):
    """Ядро с заданной приманкой; {w} и {root} — его WEB-порт и каталог."""
    c = p.Core(name, limit=0, quota=None)
    old = STATIC.format(root=c.root)
    assert c.config.count(old) == 1 and c.config.count('[web.timeouts]\n') == 1
    decoy = decoy.replace('{w}', str(c.w)).replace('{root}', str(c.root))
    c.config = c.config.replace(old, '[web.vhosts.decoy]\n' + decoy + '\n').replace('[web.timeouts]\n', '[web.timeouts]\n' + timeouts)
    (c.root / 'telemt.toml').write_text(c.config)
    return c


def refuses(name, decoy, timeouts='', within=6):
    """Сколько секунд прожило ядро с такой приманкой; None — оно работает."""
    c = core(name, decoy, timeouts)
    log = (c.root / 'process.log').open('ab')
    started = time.monotonic()
    proc = subprocess.Popen([str(p.BINARY), 'run', '--data-path', str(c.root / 'data'), str(c.root / 'telemt.toml')],
                            cwd=c.root, stdout=log, stderr=log)
    try:
        proc.wait(within)
        return time.monotonic() - started
    except subprocess.TimeoutExpired:
        return None
    finally:
        if proc.poll() is None:
            proc.kill(); proc.wait()
        log.close(); c.dc.shutdown(); c.dc.server_close()


local = Origin('localhost')
try:
    # ── Ядро: адрес ──────────────────────────────────────────────────────────
    c = core('literal', f'mode = "http_upstream"\nupstream = "http://127.0.0.1:{local.port}"').start()
    try:
        status, body = page(c, '/catalog/item?id=7')
        check('literal_decoy_serves_origin', status == 200 and body == b'DECOY-ORIGIN /catalog/item?id=7', status=status)
        check('origin_receives_configured_authority', local.seen[-1] == ('/catalog/item?id=7', f'127.0.0.1:{local.port}'))
        check('proxy_traffic_unaffected', c.web().echo() == b'test-data' * 8 and c.native().echo() == b'test-data' * 8)
        check('secret_traffic_never_reaches_origin', len(local.seen) == 1)
    finally:
        c.close()
    # WEB-листенер слушает 0.0.0.0: любой адрес на его порту ядро считает петлёй.
    check('origin_on_web_listener_port_refused', refuses('overlap', 'mode = "http_upstream"\nupstream = "http://127.0.0.1:{w}"') is not None)
    check('public_literal_refused', refuses('public', 'mode = "http_upstream"\nupstream = "http://198.51.100.9:80"') is not None)
    check('name_without_opt_in_refused', refuses('name-plain', f'mode = "http_upstream"\nupstream = "http://localhost:{local.port}"') is not None)

    # ── Ядро: имя хоста (3.5.14+) ────────────────────────────────────────────
    if NAMES:
        c = core('name', f'mode = "http_upstream"\nupstream = "http://localhost:{local.port}"\nresolve = "startup"').start()
        try:
            status, body = page(c, '/by-name')
            check('named_decoy_serves_origin', status == 200 and body == b'DECOY-ORIGIN /by-name', status=status)
            check('origin_receives_configured_name', local.seen[-1] == ('/by-name', f'localhost:{local.port}'))
        finally:
            c.close()
        check('resolve_key_only_for_upstream',
              refuses('static-resolve', 'mode = "static_directory"\ndirectory = "{root}/decoy"\nresolve = "startup"') is not None)
        # Неразрешимое имя — не «приманка не работает», а «ядро не запустилось».
        # Срок задаёт decoy_resolve_secs; бот ставит 2 и смотрит процесс на 3-й секунде.
        lived = refuses('name-gone', 'mode = "http_upstream"\nupstream = "http://decoy-gone.invalid:81"\nresolve = "startup"',
                        'decoy_resolve_secs = 2\n')
        check('unresolvable_name_stops_whole_core', lived is not None, lived=lived)
        check('unresolvable_name_fails_within_resolve_window', lived is not None and lived < 3, lived=lived)
finally:
    local.close()

# ── Бот на том же ядре ───────────────────────────────────────────────────────
c = p.Core('bot', limit=0, quota=None)
cfg = {'source': str(SOURCE), 'binary': str(p.BINARY), 'n': c.n, 'w': c.w, 'a': c.a, 'dc': c.dc.server_address[1]}
(c.root / 'fixture.json').write_text(json.dumps(cfg))
pac = c.root / 'pac.json'
pac.write_text(json.dumps({'domain': 'audit.example', 'tw_domain': 'web', 'letsencrypt': 'letsencrypt', 'telemt_web': 1,
                           'telemt_web_negotiation': 'off', 'telemt_web_carrier': 'https', 'telemt_domain': 'localhost',
                           # beobachten включает API ядра: по нему сценарий видит готовность.
                           'telemt_mode': 'secure', 'telemt_beobachten': 1, 'telemt_users': {'alice': p.SECRET.hex(), 'bob': p.BOB.hex()}}))


def call(action, **kw):
    r = subprocess.run(['docker', 'exec', '-i', 'vpnbot-telemt-php85', 'php', '-d', 'error_reporting=32767',
                        str(HERE / 'native_bot.php'), str(SOURCE), str(c.root)],
                       input=json.dumps({'action': action, **kw}), text=True, capture_output=True, timeout=80)
    try:
        out = json.loads(r.stdout)
    except ValueError:
        raise RuntimeError('PHP harness failure: ' + r.stderr[:600])
    if not out['ok']:
        raise RuntimeError(out['error'])
    return out


def ready():
    try:
        return c.api('/v1/health')[0] == 200
    except OSError:
        return False


def saved():
    return json.loads(pac.read_text()).get('telemt_web_decoy')


def toml():
    return (c.root / 'generated.toml').read_text()


site = Origin(BRIDGE)
state = None
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location('state', SOURCE / 'scripts/telemt_state.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    state = module.TelemtState(c.root, 'http://127.0.0.1:' + str(c.a))
    call('start'); check('bot_default_configuration_starts', p.wait(ready, 10))
    check('bot_default_is_builtin_page', page(c) == (200, b'<!doctype html><title>Cover</title>Cover') and 'static_directory' in toml())

    # Отказы — до записи настройки и без перезапуска работающего ядра.
    pid = state.processes()
    closed = Origin(BRIDGE); dead = closed.port; closed.close()
    for label, value, error in [
        ('loopback', f'http://127.0.0.1:{site.port}', 'telemt web decoy not private'),
        ('stack_service', 'http://10.10.0.7:8090', 'telemt web decoy not private'),
        ('own_listener_port', f'http://{BRIDGE}:8080', 'telemt web decoy own port'),
        ('path', f'http://{BRIDGE}:{site.port}/admin', 'telemt web decoy bad url'),
        ('closed_port', f'http://{BRIDGE}:{dead}', 'telemt web decoy no answer'),
        ('name_to_loopback', f'http://localhost:{site.port}', 'telemt web decoy not private'),
        ('unresolvable_name', 'http://decoy-gone.invalid:81', 'telemt web decoy unresolved'),
    ]:
        if not NAMES and label.startswith(('name_', 'unresolvable')):
            error = 'telemt web decoy need version'
        check('bot_refuses_' + label, call('decoy', value=value)['error'] == error and saved() is None)
    check('refusals_do_not_restart_core', state.processes() == pid and page(c)[1].endswith(b'Cover'))

    out = call('decoy', value=f'http://{BRIDGE}:{site.port}')
    check('bot_accepts_private_address', out['error'] == '' and saved() == f'http://{BRIDGE}:{site.port}')
    check('bot_configuration_uses_upstream', 'mode = "http_upstream"' in toml() and 'resolve' not in toml() and p.wait(ready, 10))
    check('bot_address_decoy_serves_site', page(c, '/shop') == (200, b'DECOY-ORIGIN /shop'))
    check('bot_address_decoy_keeps_proxy', c.web().echo() == b'test-data' * 8 and c.native().echo() == b'test-data' * 8)
    for child in c.children:
        child.close()
    c.children = []

    if NAMES:
        out = call('decoy', value=f'http://decoy-origin.test:{site.port}')
        check('bot_accepts_host_name', out['error'] == '' and saved() == f'http://decoy-origin.test:{site.port}')
        check('bot_configuration_opts_into_resolution',
              'resolve = "startup"' in toml() and '[web.timeouts]\ndecoy_resolve_secs = 2\n' in toml() and p.wait(ready, 10))
        check('bot_name_decoy_serves_site', page(c, '/named') == (200, b'DECOY-ORIGIN /named')
              and site.seen[-1] == ('/named', f'decoy-origin.test:{site.port}'))
        # Имя перестало разрешаться (сайт убрали, а настройка осталась): бот
        # обязан заметить, что ядро погибло уже после старта, и вернуть страницу.
        data = json.loads(pac.read_text()); data['telemt_web_decoy'] = 'http://decoy-gone.invalid:81'; pac.write_text(json.dumps(data))
        call('start')
        check('bot_reverts_unresolvable_name', saved() is None and p.wait(ready, 10) and 'static_directory' in toml())
        check('bot_revert_restores_builtin_page', page(c)[1].endswith(b'Cover') and c.native().echo() == b'test-data' * 8)
        for child in c.children:
            child.close()
        c.children = []
        call('decoy', value=f'http://{BRIDGE}:{site.port}')

    # Сайт остановлен: приманка отвечает ошибкой, прокси продолжает работать.
    site.close(); site = None
    status, _ = page(c)
    check('dead_site_does_not_stop_proxy', status in (0, 502, 503, 504) and ready() and c.native().echo() == b'test-data' * 8, status=status)
    out = call('decoy', value='')
    check('bot_returns_builtin_page', out['error'] == '' and saved() is None and p.wait(ready, 10) and page(c)[1].endswith(b'Cover'))
finally:
    if site:
        site.close()
    for child in c.children:
        child.close()
    c.children = []
    if state is not None and state.processes():
        state.stop()
    c.close()
print('TOTAL', len(results), flush=True)
