#!/usr/bin/env python3
"""Веб-панель (app/panel) на живой установке: доступ, вход, CSRF, конвейер бота.

Панель слушает 127.0.0.1:8090 хоста стенда. Набор проверяет то, что модульные
тесты увидеть не могут: настоящий unit с двумя слушателями, источник запроса
после docker-proxy, лимит тела запроса, параллельные воркеры, opcache.
Состояние стенда (состав администраторов, pac.json, лента) возвращается.
"""
import concurrent.futures as cf
import http.client, json, os, pathlib, re, secrets, subprocess, time
from urllib.parse import urlencode

os.umask(0o077)
R = pathlib.Path('/opt/vpnbot-hosted-ci/stand'); O = R / 'results/panel'; O.mkdir(mode=0o700, exist_ok=True)
PHP = 'php-audit'
results = []


def run(*a, timeout=60): return subprocess.run(list(map(str, a)), capture_output=True, text=True, timeout=timeout)


def check(n, v):
    results.append({'name': n, 'passed': bool(v)}); (O / 'results.json').write_text(json.dumps(results, indent=2))
    print(('PASS ' if v else 'FAIL ') + n, flush=True)


def php(code): r = run('docker', 'exec', PHP, 'php', '-r', code); r.check_returncode(); return r.stdout


def req(method, path, body=None, headers=None, host='127.0.0.1:8090', timeout=120):
    c = http.client.HTTPConnection('127.0.0.1', 8090, timeout=timeout)
    h = {'Host': host}; h.update(headers or {})
    try:
        c.request(method, path, body=body, headers=h); r = c.getresponse(); data = r.read()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.headers.get_all('Set-Cookie') or [], data
    finally:
        c.close()


FORM = {'Content-Type': 'application/x-www-form-urlencoded'}


def login(password, admin=None):
    f = {'password': password}
    if admin is not None: f['admin'] = admin
    s, _, ck, d = req('POST', P + '/login', urlencode(f).encode(), dict(FORM, **{'X-Panel': '1'}))
    return s, next((x for x in ck if x.startswith('panel=')), ''), d


def post(cookie, action, fields, timeout=300):
    return req('POST', f'{P}/{action}', urlencode(fields).encode(), dict(FORM, **{'X-Panel': '1', 'Cookie': cookie}), timeout=timeout)


def feed(cookie):
    s, _, _, d = req('GET', P + '/state?since=0', headers={'Cookie': cookie})
    return s, (json.loads(d) if s == 200 else {})


def last_bot(cookie):
    ms = [m for m in feed(cookie)[1].get('messages', []) if not m.get('own') and not m.get('deleted')]
    return ms[-1] if ms else {}


def open_menu(cookie, section=None):
    post(cookie, 'reset', {}); post(cookie, 'text', {'text': '/menu', 'reply_to': 0})
    m = last_bot(cookie)
    if section:
        post(cookie, 'click', {'message_id': m.get('id', 0), 'data': '/menu ' + section}); m = last_bot(cookie)
    return m


def admins(): return json.loads(php('require "/app/config.php"; echo json_encode($c["admin"]);'))


def set_admins(php_list):
    php('$f="/app/config.php"; require $f; $c["admin"]=' + php_list + '; file_put_contents($f, "<?php\\n\\n\\$c = " . var_export($c, true) . ";\\n");')
    time.sleep(3)  # opcache.revalidate_freq=2: unit должен перечитать config.php


def pac(key): return json.loads(php(f'echo json_encode(json_decode(file_get_contents("/config/pac.json"),true)[{json.dumps(key)}] ?? null);'))


def multipart(fields, files):
    b, body = 'audit' + secrets.token_hex(6), b''
    for k, v in fields.items():
        body += f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
    for k, (name, data) in files.items():
        body += f'--{b}\r\nContent-Disposition: form-data; name="{k}"; filename="{name}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode() + data + b'\r\n'
    return body + f'--{b}--\r\n'.encode(), {'Content-Type': f'multipart/form-data; boundary={b}'}


def upload(cookie, name, data, field='file'):
    body, h = multipart({'reply_to': 0, 'caption': ''}, {field: (name, data)})
    try:
        s, _, _, d = req('POST', P + '/upload', body, dict(h, **{'X-Panel': '1', 'Cookie': cookie}))
        return s, d
    except (BrokenPipeError, ConnectionResetError):
        return None, b''


PASSWORD = 'audit-' + secrets.token_hex(12)
r = run('docker', 'exec', '-w', '/app', PHP, 'php', 'panel.php', 'passwd', PASSWORD); r.check_returncode()
P = re.search(r'http://127\.0\.0\.1:8090(/panel[0-9a-f]+)/', run('docker', 'exec', '-w', '/app', PHP, 'php', 'panel.php', 'url').stdout).group(1)
original_admins = admins(); original_browser = pac('adgbrowser')
php('@unlink("/config/panel/login_attempts.json");')
try:
    # ── источник запроса и имя в Host ─────────────────────────────────────────
    s, h, _, body = req('GET', P + '/')
    check('host-loopback-login-page', s == 200 and b'id="loginform"' in body and b'if ("0" === "1")' in body)
    check('page-security-headers', "frame-ancestors 'none'" in h.get('content-security-policy', '')
          and h.get('x-frame-options') == 'DENY' and h.get('cache-control') == 'no-store')
    s, h, _, _ = req('GET', P); check('no-slash-redirect', s == 302 and h.get('location') == P + '/')
    for host in ('evil.example', 'localhost.evil.example', 'evil.example:8090'):
        check('dns-rebinding-host-' + host.split(':')[0] + '-denied', req('GET', P + '/', host=host)[0] == 403)
    check('host-localhost-allowed', req('GET', P + '/', host='localhost:8090')[0] == 200)
    for name in ('xray-audit', 'wireguard-audit', 'service-audit'):
        for path in (P + '/', '/pac' + P[6:] + '?t=changelog'):
            r = run('docker', 'exec', name, 'curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '5', 'http://10.10.0.7:8090' + path)
            check(f'neighbour-{name}-{"panel" if path.startswith("/panel") else "listener"}-denied', r.stdout == '403')
    public = lambda path: run('curl', '-sk', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '8', '--resolve', 'vpnbot.test:443:127.0.0.1', 'https://vpnbot.test' + path).stdout
    check('public-443-panel-looks-like-unknown-path', public(P + '/') == public('/nonexistent-' + secrets.token_hex(4)) and public(P + '/') != '200')
    # Адреса PHP бота не принимают multipart/form-data (PHP2Shell); прочие запросы к ним проходят как раньше.
    changelog = '/pac' + pac('hashbot') + '?t=changelog'
    for name, path in (('pac', changelog), ('webapp', '/webapp/'), ('tlgrm', '/tlgrm')):
        check('public-443-multipart-rejected-' + name, public(path) != '415'
              and run('curl', '-sk', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '8', '--resolve', 'vpnbot.test:443:127.0.0.1',
                      '-F', 'a=b', 'https://vpnbot.test' + path).stdout == '415')
    check('public-443-pac-changelog-served', public(changelog) == '200')
    check('public-443-tlgrm-json-not-blocked', run('curl', '-sk', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '8', '--resolve', 'vpnbot.test:443:127.0.0.1',
                                                   '-H', 'Content-Type: application/json', '-d', '{}', 'https://vpnbot.test/tlgrm').stdout != '415')

    # ── CSRF, методы, доступ без входа ────────────────────────────────────────
    check('post-without-x-panel-rejected', req('POST', P + '/login', urlencode({'password': PASSWORD}).encode(), FORM)[0] == 400)
    for a in ('logout', 'reset', 'click', 'text', 'upload', 'tsave', 'dismiss'):
        s, h, _, _ = req('GET', f'{P}/{a}'); check(f'get-{a}-not-allowed', s == 405 and h.get('allow') == 'POST')
    for a in ('state', 'diag', 'file?id=x', 'editor?ty=xray', 'a/jsoneditor.min.js'):
        check(f'unauthenticated-{a.split("?")[0]}-401', req('GET', f'{P}/{a}')[0] == 401)

    # ── перебор пароля ────────────────────────────────────────────────────────
    with cf.ThreadPoolExecutor(12) as ex:
        codes = list(ex.map(lambda _: login('wrong-' + secrets.token_hex(8))[0], range(12)))
    check('parallel-guessing-limited-to-5', codes.count(403) <= 5 and codes.count(429) >= 7)
    check('right-password-during-lockout-429', login(PASSWORD)[0] == 429)
    php('@unlink("/config/panel/login_attempts.json");')

    # ── вход и кука ───────────────────────────────────────────────────────────
    s, ck, d = login(PASSWORD)
    check('login', s == 200 and json.loads(d).get('ok'))
    low = ck.lower()
    check('cookie-flags', 'httponly' in low and 'samesite=strict' in low and f'path={P.lower()}/' in low)
    C = ck.split(';')[0]
    check('page-after-login', b'if ("1" === "1")' in req('GET', P + '/', headers={'Cookie': C})[3])
    v = C.split('=', 1)[1].split('.')
    for label, forged in [('expiry', str(int(v[0]) + 3600) + '.' + v[1]), ('signature', v[0] + '.' + '0' * 64),
                          ('admin', v[0] + '.999.' + v[1])]:
        check(f'forged-cookie-{label}-401', req('GET', P + '/state', headers={'Cookie': 'panel=' + forged})[0] == 401)
    check('valid-cookie-foreign-host-403', req('GET', P + '/state', headers={'Cookie': C}, host='evil.example')[0] == 403)

    # ── обход путей ───────────────────────────────────────────────────────────
    for i, path in enumerate(('/file?id=../../app/config.php', '/file?id=..%2F..%2Fapp%2Fconfig.php', '/file?id[]=x',
                              '/a/../config.php', '/a/..%2F..%2Fconfig.php', '/a/x.php', '/editor?ty=../x', '/editor?ty[]=x')):
        s, _, _, body = req('GET', P + path, headers={'Cookie': C})
        check(f'traversal-{i}-refused', s in (403, 404) and b'<?php' not in body and b"'key'" not in body)
    s, h, _, _ = req('GET', P + '/a/jsoneditor.min.js', headers={'Cookie': C})
    check('editor-assets-served', s == 200 and h.get('content-type') == 'application/javascript')
    d = json.loads(req('GET', P + '/diag', headers={'Cookie': C})[3])
    check('diag-session-12h', 43000 < d['ttl'] <= 43200 and d['admin_count'] == len(original_admins))

    # ── конвейер бота ─────────────────────────────────────────────────────────
    menu = open_menu(C)
    check('menu-through-the-bot', len(menu.get('buttons', [])) > 5)
    sections = [b['cb'] for row in menu.get('buttons', []) for b in row if b.get('cb', '').startswith('/menu ')]
    bad = []
    for cb in sections:
        post(C, 'click', {'message_id': menu['id'], 'data': cb})
        s, st = feed(C)
        cur = next((m for m in st.get('messages', []) if m['id'] == menu['id']), {})
        if s != 200 or cur.get('deleted') or not cur.get('buttons') or ((st.get('toast') or {}).get('text', '').startswith('error')):
            bad.append(cb)
    check('every-main-menu-section-opens', sections and not bad)
    (O / 'menu-sections.json').write_text(json.dumps({'sections': sections, 'failed': bad}, indent=2))
    html = next((m['html'] for m in feed(C)[1]['messages'] if m['id'] == menu['id']), '')
    check('rendered-html-has-no-active-content', not re.search(r'<(script|img|iframe|svg)|\son\w+=|javascript:', html, re.I))

    # Два одновременных клика: бот обязан выполнить их по очереди, как в Telegram.
    lost = 0
    for _ in range(4):
        before = pac('adgbrowser')
        with cf.ThreadPoolExecutor(2) as ex:
            list(ex.map(lambda _: post(C, 'click', {'message_id': menu['id'], 'data': '/adguardChBr'}), range(2)))
        lost += bool(before) != bool(pac('adgbrowser'))
    check('parallel-clicks-serialized-no-lost-update', lost == 0)

    # ── загрузки ──────────────────────────────────────────────────────────────
    s, d = upload(C, '<img src=x onerror=alert(1)>.txt', b'hello')
    own = [m for m in feed(C)[1]['messages'] if m.get('own') and '📎' in (m.get('text') or '')]
    check('upload-name-escaped', s == 200 and own and '<img' not in own[-1]['html'])
    check('upload-9MiB-accepted', upload(C, 'nine.bin', b'0' * (9 * 1048576))[0] == 200)
    check('upload-over-limit-refused', upload(C, 'big.bin', b'0' * (25 * 1048576))[0] != 200)
    check('upload-array-field-400', upload(C, 'a.txt', b'x', 'file[]')[0] == 400)
    files = run('docker', 'exec', PHP, 'ls', '/config/panel/files').stdout.split()
    check('stored-names-sanitized', all(re.fullmatch(r'[0-9a-f]{16}_[\w.-]+', f) for f in files))
    for action, body in [('click', 'message_id=1&data[]=x'), ('text', 'text[]=x'), ('dismiss', 'message_id[]=1'),
                         ('tsave', 'name[]=x&type=xray&json=%7B%7D'), ('tload', 'ty[]=x')]:
        s = req('POST', f'{P}/{action}', body.encode(), dict(FORM, **{'X-Panel': '1', 'Cookie': C}))[0]
        check(f'array-in-{action}-no-500', s != 500)

    # ── редактор шаблонов ─────────────────────────────────────────────────────
    j = json.loads(post(C, 'tload', {'ty': 'xray'})[3])
    check('template-load-xray', j.get('status') and 'inbounds' in j.get('json', {}))
    check('template-save-type-traversal-refused', json.loads(post(C, 'tsave', {'name': 'origin', 'type': '../app/x', 'json': '{}'})[3]).get('status') is False)
    s, _, _, body = req('GET', P + '/editor?ty=sing&te=%3C%2Fscript%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E', headers={'Cookie': C})
    check('editor-name-cannot-close-script', s == 200 and b'</script><script>alert(1)' not in body)

    # ── пароль из панели ──────────────────────────────────────────────────────
    m = open_menu(C, 'config')
    s, _, ck, _ = post(C, 'click', {'message_id': m['id'], 'data': '/panelGenPswd'})
    fresh = next((x.split(';')[0] for x in ck if x.startswith('panel=')), '')
    check('generated-password-old-cookie-revoked', req('GET', P + '/state', headers={'Cookie': C})[0] == 401)
    check('generated-password-keeps-own-session', bool(fresh) and feed(fresh)[0] == 200)
    texts = [x.get('text') or '' for x in feed(fresh)[1].get('messages', [])] if fresh else []
    gen = next((g.group(1) for t in texts for g in [re.search(r'<code>([0-9a-f]{32})</code>', t)] if g), None)
    check('generated-password-shown-in-feed', bool(gen))
    check('generated-password-logs-in', bool(gen) and login(gen)[0] == 200)
    check('display-copy-key-not-stored-beside', run('docker', 'exec', PHP, 'test', '-e', '/config/panel/password-display.key').returncode != 0)
    C = fresh or C
    run('docker', 'exec', '-w', '/app', PHP, 'php', 'panel.php', 'passwd', PASSWORD).check_returncode()
    check('cli-password-change-ends-sessions', req('GET', P + '/state', headers={'Cookie': C})[0] == 401)
    s, ck, _ = login(PASSWORD); C = ck.split(';')[0]

    # ── несколько администраторов ─────────────────────────────────────────────
    owner = int(original_admins[0])
    set_admins(f'[{owner}, 222222]')
    check('multi-admin-login-requires-choice', login(PASSWORD)[0] == 400)
    s, ck2, _ = login(PASSWORD, 222222); C2 = ck2.split(';')[0]
    check('multi-admin-second-admin-login', s == 200)
    lit = re.search(rb'JSON\.parse\("(.*?)"\)', req('GET', P + '/')[3])
    check('multi-admin-list-on-login-page', lit and lit.group(1) == f'[{owner},222222]'.encode())
    m = open_menu(C2, 'config')
    check('second-admin-no-add-admin-button', '/addadmin' not in json.dumps(m))
    post(C2, 'click', {'message_id': m['id'], 'data': '/addadmin'})
    check('second-admin-add-admin-refused', 'only the owner' in json.dumps(feed(C2)[1], ensure_ascii=False))
    post(C2, 'click', {'message_id': m['id'], 'data': f'/deladmin {owner}'})
    check('second-admin-cannot-remove-owner', admins() == [owner, 222222])
    s, ck1, _ = login(PASSWORD, owner); C1 = ck1.split(';')[0]
    m = open_menu(C1, 'config')
    post(C1, 'click', {'message_id': m['id'], 'data': '/deladmin 222222'})
    check('panel-as-owner-cannot-change-admins', admins() == [owner, 222222])
    v = C2.split('=', 1)[1].split('.')
    check('admin-id-swap-in-cookie-401', req('GET', P + '/state', headers={'Cookie': f'panel={v[0]}.{owner}.{v[2]}'})[0] == 401)
    set_admins(f"['{owner}', '222222']")  # так их хранили старые версии addAdmin()
    lit = re.search(rb'JSON\.parse\("(.*?)"\)', req('GET', P + '/')[3])
    check('legacy-string-ids-login-page', lit and b'&quot;' not in lit.group(1))
    check('legacy-string-ids-login', login(PASSWORD, 222222)[0] == 200)
    set_admins(json.dumps(original_admins))
    s, ck, _ = login(PASSWORD); C = ck.split(';')[0]
    s, _, ck, _ = post(C, 'logout', {})
    check('logout-clears-cookie', s == 200 and any(x.startswith('panel=') and 'max-age=0' in x.lower() for x in ck))
    check('logout-revokes-copied-cookie', req('GET', P + '/state', headers={'Cookie': C})[0] == 401)
    check('revoked-list-private', run('docker', 'exec', PHP, 'stat', '-c', '%a', '/config/panel/revoked.json').stdout.strip() == '600')
finally:
    if admins() != original_admins: set_admins(json.dumps(original_admins))
    if bool(pac('adgbrowser')) != bool(original_browser):
        php('$f="/config/pac.json";$c=json_decode(file_get_contents($f),true);$c["adgbrowser"]=' + ('1' if original_browser else '0') + ';file_put_contents($f,json_encode($c,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));')
    php('@unlink("/config/panel/login_attempts.json"); @unlink("/config/panel/revoked.json"); foreach (glob("/config/panel/files/*") ?: [] as $f) @unlink($f); @unlink("/config/panel/state.json");')
print(json.dumps({'passed': sum(x['passed'] for x in results), 'total': len(results)}))
raise SystemExit(0 if all(x['passed'] for x in results) else 1)
