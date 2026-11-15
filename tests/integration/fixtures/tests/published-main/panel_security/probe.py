#!/usr/bin/env python3
"""WEB-03/04 на настоящих loopback HTTP/TLS listeners Unit, только own container."""
from contextlib import contextmanager
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import ssl
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler, HTTPSHandler, HTTPCookieProcessor, ProxyHandler

PREFIX = '/panelauditfixturev1'
PASSWORD = 'SyntheticPanelPassword-2026'
MAX_BODY = 4 * 1024 * 1024

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(url, context, *, cookie=None, jar=None, data=None):
    handlers = [ProxyHandler({}), NoRedirect(), HTTPSHandler(context=context)]
    if jar is not None:
        handlers.append(HTTPCookieProcessor(jar))
    opener = build_opener(*handlers)
    headers = {}
    if cookie is not None:
        headers['Cookie'] = 'panel=' + cookie
    body = None
    if data is not None:
        body = urlencode(data).encode()
        headers['X-Panel'] = '1'
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    req = Request(url, data=body, headers=headers)
    try:
        response = opener.open(req, timeout=8)
    except HTTPError as error:
        response = error
    with response:
        payload = response.read(MAX_BODY + 1)
        if len(payload) > MAX_BODY:
            raise ValueError('response limit')
        return response.status, response.headers, payload


def decoded(payload):
    try:
        return json.loads(payload)
    except (ValueError, UnicodeDecodeError):
        return {}


def authenticated(response):
    code, _, body = response
    value = decoded(body)
    return code == 200 and value.get('ok') is True and isinstance(value.get('messages'), list)


def assert_control(condition):
    if not condition:
        raise RuntimeError('positive-control-failed')


def safe_error(error):
    trace = []
    cursor = error.__traceback__
    while cursor is not None:
        if Path(cursor.tb_frame.f_code.co_filename).resolve() == Path(__file__).resolve():
            trace.append({'function': cursor.tb_frame.f_code.co_name, 'line': cursor.tb_lineno})
        cursor = cursor.tb_next
    # Только координаты собственного кода. Сообщение исключения может содержать URL.
    return {'exception_class': type(error).__name__, 'driver_trace': trace[-4:]}


@contextmanager
def lab():
    root = Path('/scratch')
    assert_control(os.environ.get('PANEL_TEST_ISOLATED') == 'owned-unit-panel-v1')
    root.mkdir(exist_ok=True)
    (root / '.synthetic-only').touch()
    env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
           'PANEL_TEST_ISOLATED': 'owned-unit-panel-v1', 'PANEL_TEST_SOURCE': '/source',
           'PANEL_TEST_ROOT': str(root), 'PANEL_DIR': str(root / 'panel')}
    initialized = subprocess.run(['php', '/probe/router.php', 'init'], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=20)
    cookies = json.loads(initialized.stdout)
    cert, key, bundle = [root / name for name in ('cert.pem', 'key.pem', 'bundle.pem')]
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
        '-keyout', str(key), '-out', str(cert)], check=True, timeout=30,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Only a newly generated synthetic private key is combined inside the own container.
    bundle.write_bytes(cert.read_bytes() + key.read_bytes())
    context = ssl.create_default_context(cafile=str(cert))
    control = root / 'control.sock'
    # Unit не создаёт statedir сам: без него хранилище сертификатов недоступно (500).
    (root / 'unit-state').mkdir(mode=0o700, exist_ok=True)
    unit = subprocess.Popen(['unitd', '--no-daemon', '--user', 'root', '--group', 'root', '--control', 'unix:' + str(control),
        '--pid', str(root / 'unit.pid'), '--statedir', str(root / 'unit-state'), '--log', '/dev/null'],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while not control.exists():
            if unit.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('unit-control-unavailable')
            time.sleep(.05)
        def put(path, data):
            call = subprocess.run(['curl', '-sS', '--max-time', '10', '--fail', '--unix-socket',
                str(control), '-X', 'PUT', '--data-binary', '@-', 'http://localhost/' + path],
                input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
            assert_control(call.returncode == 0 and 'success' in json.loads(call.stdout))
        put('certificates/synthetic', bundle.read_bytes())
        config = {'listeners': {'127.0.0.1:18090': {'pass': 'applications/panel'},
            '127.0.0.1:18443': {'pass': 'applications/panel', 'tls': {'certificate': 'synthetic'}}},
            'applications': {'panel': {'type': 'php', 'root': '/probe', 'script': 'router.php',
                'user': 'root', 'processes': 1, 'environment': env,
                'options': {'admin': {'display_errors': '0', 'log_errors': '0'}}}}}
        put('config', json.dumps(config).encode())
        running = {'http': 'http://127.0.0.1:18090', 'https': 'https://127.0.0.1:18443',
                   'context': context, 'cookies': cookies}
        assert_control(request(running['https'] + '/__audit/health', context)[0] == 200)
        yield running
    finally:
        unit.terminate()
        try:
            unit.wait(timeout=5)
        except subprocess.TimeoutExpired:
            unit.kill(); unit.wait(timeout=5)
        # The container is removed by the outer runner, including Unit certificate storage.
        for path in (key, bundle):
            path.unlink(missing_ok=True)


def web03(lab):
    context = lab['context']
    base = lab['https']
    # Положительный контроль парсера: LF/CRLF дошли через настоящий Unit TLS и PHP parser.
    lf = request(base + '/__audit/health', context, cookie='synthetic%0A')
    crlf = request(base + '/__audit/health', context, cookie='synthetic%0D%0A')
    parser_ok = lf[1].get('X-Audit-Cookie-LF') == '1' and crlf[1].get('X-Audit-Cookie-CRLF') == '1'
    assert_control(parser_ok)
    jar = CookieJar()
    login = request(base + PREFIX + '/login', context, jar=jar, data={'password': PASSWORD})
    assert_control(login[0] == 200 and decoded(login[2]).get('ok') is True)
    assert_control(authenticated(request(base + PREFIX + '/state', context, jar=jar)))
    modern = next(cookie.value for cookie in jar if cookie.name == 'panel')
    assert_control(request(base + PREFIX + '/state', context, cookie=modern + '%0A')[0] == 401)
    variants = []
    for name in ('legacy_two', 'legacy_three'):
        cookie = lab['cookies'][name]
        before = request(base + PREFIX + '/state', context, cookie=cookie)
        if before[0] == 401:
            # Удаление поддержки legacy — допустимое исправление, при рабочем modern.
            suffixes = [request(base + PREFIX + '/state', context, cookie=cookie + suffix)[0]
                        for suffix in ('%0A', '%0D%0A')]
            assert_control(all(code == 401 for code in suffixes))
            variants.append({'format': name, 'retired': True, 'before': 401,
                'lf_after': suffixes[0], 'crlf_after': suffixes[1], 'bypass': False})
            continue
        assert_control(authenticated(before))
        logged_out = request(base + PREFIX + '/logout', context, cookie=cookie, data={})
        assert_control(logged_out[0] == 200 and decoded(logged_out[2]).get('ok') is True)
        original = request(base + PREFIX + '/state', context, cookie=cookie)
        assert_control(original[0] == 401)
        lf_after = request(base + PREFIX + '/state', context, cookie=cookie + '%0A')
        crlf_after = request(base + PREFIX + '/state', context, cookie=cookie + '%0D%0A')
        assert_control(lf_after[1].get('X-Audit-Cookie-LF') == '1')
        assert_control(crlf_after[1].get('X-Audit-Cookie-CRLF') == '1')
        assert_control(lf_after[0] in (200, 401) and crlf_after[0] in (200, 401))
        variants.append({'format': name, 'retired': False, 'before': before[0],
            'original_after_logout': original[0], 'lf_after': lf_after[0],
            'crlf_after': crlf_after[0], 'bypass': authenticated(lf_after) or authenticated(crlf_after)})
    return {'id': 'WEB-03', 'status': 'FAIL' if any(item['bypass'] for item in variants) else 'PASS',
        'controls': {'modern_login_and_state': True, 'modern_lf_rejected': True,
            'percent_encoded_lf_parsed': parser_ok}, 'variants': variants}


def web04(lab):
    context = lab['context']
    base = lab['https']
    login_page = request(base + PREFIX + '/', context)
    assert_control(login_page[0] == 200 and b'<html' in login_page[2].lower()
        and b'{{AUTH}}' not in login_page[2])
    jar = CookieJar()
    login = request(base + PREFIX + '/login', context, jar=jar, data={'password': PASSWORD})
    assert_control(login[0] == 200 and decoded(login[2]).get('ok') is True)
    secure = next(cookie for cookie in jar if cookie.name == 'panel').secure
    assert_control(secure)
    page = request(base + PREFIX + '/', context, jar=jar)
    assert_control(page[0] == 200 and b'<html' in page[2].lower())
    state = request(base + PREFIX + '/state', context, jar=jar)
    assert_control(authenticated(state))
    links = [button['url'] for message in decoded(state[2])['messages']
        for row in message.get('buttons', []) for button in row
        if button.get('webapp') and 'url' in button]
    assert_control(len(links) == 1)
    link = urljoin(base + PREFIX + '/', links[0])
    parsed = urlsplit(link)
    assert_control(parsed.hostname == '127.0.0.1' and parsed.port == urlsplit(base).port
        and parsed.path == PREFIX + '/editor')
    # Положительный контроль настоящего editor()/tload() по корректному HTTPS.
    correct_editor = base + parsed.path + ('?' + parsed.query if parsed.query else '')
    good = request(correct_editor, context, jar=jar)
    assert_control(good[0] == 200 and b'id="jsoneditor"' in good[2])
    loaded = request(base + PREFIX + '/tload', context, jar=jar,
        data={'ty': 'sing', 'te': 'audit_template'})
    assert_control(loaded[0] == 200 and decoded(loaded[2]).get('status') is True
        and decoded(loaded[2]).get('json', {}).get('fixture') is True)
    # Запрос по фактически выданной ссылке. На baseline это plain HTTP к TLS-порту.
    cookie_request = Request(link)
    jar.add_cookie_header(cookie_request)
    cookie_sent = cookie_request.has_header('Cookie')
    follow_status = None
    follow_error = False
    followed_editor = False
    try:
        follow = request(link, context, jar=jar)
        follow_status = follow[0]
        followed_editor = follow[0] == 200 and b'id="jsoneditor"' in follow[2]
    except (URLError, OSError):
        follow_error = True
    # Контроль штатного HTTP-входа: Secure не ставится, авторизация работает.
    http_jar = CookieJar()
    http_login = request(lab['http'] + PREFIX + '/login', context, jar=http_jar, data={'password': PASSWORD})
    assert_control(http_login[0] == 200 and decoded(http_login[2]).get('ok') is True)
    assert_control(not next(cookie for cookie in http_jar if cookie.name == 'panel').secure)
    assert_control(authenticated(request(lab['http'] + PREFIX + '/state', context, jar=http_jar)))
    downgrade = parsed.scheme == 'http'
    if not downgrade:
        assert_control(parsed.scheme == 'https' and followed_editor)
    return {'id': 'WEB-04', 'status': 'FAIL' if downgrade else 'PASS',
        'controls': {'https_login_page': True, 'https_authenticated_page': True,
            'secure_cookie_issued': secure, 'real_https_editor': True,
            'real_https_tload': True, 'plain_http_login_and_state': True},
        'issued_link_scheme': parsed.scheme, 'actual_link_follow_http_status': follow_status,
        'actual_link_follow_transport_error': follow_error, 'actual_link_editor_opened': followed_editor,
        'cookiejar_would_send_cookie_on_issued_link': cookie_sent}


def main():
    os.umask(0o077)
    report = {'suite': 'WEB-03-WEB-04', 'level': 'real-unit-http-tls',
              'browser_javascript_tested': False, 'cookie_values_logged': False, 'tests': []}
    try:
        with lab() as running:
            for identity, probe in [('WEB-03', web03), ('WEB-04', web04)]:
                try:
                    report['tests'].append(probe(running))
                except Exception as error:
                    report['tests'].append({'id': identity, 'status': 'ERROR', **safe_error(error)})
    except Exception as error:
        report['harness_error'] = safe_error(error)
    statuses = [test['status'] for test in report['tests']]
    report['status'] = 'ERROR' if 'harness_error' in report or len(statuses) != 2 or 'ERROR' in statuses else (
        'FAIL' if 'FAIL' in statuses else 'PASS')
    print(json.dumps(report, ensure_ascii=False))
    return {'PASS': 0, 'FAIL': 1, 'ERROR': 2}[report['status']]


if __name__ == '__main__':
    raise SystemExit(main())
