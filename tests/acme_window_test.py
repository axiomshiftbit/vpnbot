"""Служба хоста acme-window (scripts/acme_window.py).

nft и docker подменены программами в PATH: состояние наборов nftables лежит в
JSON, docker exec записывает, было ли окно открыто в момент выпуска. Сертификаты
настоящие (openssl), имя localhost указывает на 127.0.0.1 — публичный адрес цели.
"""

import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('acme_window', ROOT / 'scripts/acme_window.py')
acme = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acme)

FAKE_NFT = r'''#!PYTHON
import json, os, re, sys
path = os.environ['FAKE_NFT_STATE']
st = json.load(open(path))
st['log'].append(sys.argv[1:])
def save():
    json.dump(st, open(path, 'w'))
def key(args):
    return args[1] + ' ' + args[2]
def apply(line):
    w = line.split()
    if w[:2] == ['flush', 'set']:
        if key(w[2:]) not in st['sets']:
            raise ValueError('no set')
        if not st.get('fail_flush'):
            st['sets'][key(w[2:])] = []
        return
    m = re.match(r'add element ip (\S+) (\S+) \{ (.+) timeout (\d+)s \}$', line)
    if m and m.group(1) + ' ' + m.group(2) in st['sets']:
        st['sets'][m.group(1) + ' ' + m.group(2)].append({'elem': m.group(3), 'timeout': int(m.group(4))})
        st['max_timeout'] = max(st.get('max_timeout', 0), int(m.group(4)))
        return
    raise ValueError('bad line ' + line)
a = sys.argv[1:]
json_out = a[:1] == ['-j']
if json_out:
    a = a[1:]
if a[:2] == ['list', 'set']:
    if st.get('fail_list'):
        save(); sys.stderr.write('Operation not permitted\n'); sys.exit(1)
    k = key(a[2:])
    if k not in st['sets']:
        save(); sys.stderr.write('Error: No such file or directory\n'); sys.exit(1)
    if json_out:
        s = {'name': a[4], 'table': a[3]}
        if st['sets'][k]:
            s['elem'] = [e['elem'] for e in st['sets'][k]]
        print(json.dumps({'nftables': [{'metainfo': {}}, {'set': s}]}))
    save(); sys.exit(0)
if a[:2] == ['-f', '-']:
    backup = json.dumps(st['sets'])
    lines = sys.stdin.read().splitlines()
    st['log'][-1] = ['-f', '-'] + lines
    try:
        for line in lines:
            if line.strip():
                apply(line.strip())
    except ValueError as e:
        st['sets'] = json.loads(backup)
        save(); sys.stderr.write(str(e) + '\n'); sys.exit(1)
    save(); sys.exit(0)
if a[:2] == ['flush', 'set']:
    try:
        apply(' '.join(a))
    except ValueError:
        save(); sys.exit(1)
    save(); sys.exit(0)
if a == ['list', 'ruleset']:
    print('\n'.join(st.get('ruleset', [])))
    save(); sys.exit(0)
save(); sys.exit(2)
'''

FAKE_DOCKER = r'''#!PYTHON
import hashlib, json, os, shutil, sys, time
sc_path = os.environ['FAKE_DOCKER']
sc = json.load(open(sc_path))
nft = json.load(open(os.environ['FAKE_NFT_STATE']))
a = sys.argv[1:]
def record(entry):
    sc['calls'].append(entry)
    # Родитель опрашивает calls, пока этот процесс пишет результат.
    # Обычный open('w') оставлял короткое окно с пустым JSON.
    temporary = sc_path + '.tmp'
    with open(temporary, 'w') as output:
        json.dump(sc, output)
    os.replace(temporary, sc_path)
def window():
    return sorted(e['elem'] for v in nft['sets'].values() for e in v)
if a[0] == 'ps':
    service = a[a.index('--filter') + 1].rsplit('=', 1)[1]
    print(sc['containers'].get(service, ''))
    sys.exit(0)
if a[0] == 'inspect':
    print(sc['ips'].get(a[-1], ''))
    sys.exit(0 if a[-1] in sc['ips'] else 1)
if a[0] == 'exec':
    container, cmd = a[1], a[2:]
    if cmd[:2] == ['php', '/app/acme_renew.php']:
        op = cmd[2]
        record({'op': op, 'args': cmd[3:], 'window': window()})
        if op == 'check':
            if sc['check'] != 0:
                sys.exit(sc['check'])
            print(json.dumps({'domains': sc['domains']}))
            sys.exit(0)
        if op == 'issue':
            if sc['issue'] == 'sleep':
                time.sleep(120)
            if sc['issue'] == 'fail':
                print('Challenge failed for domain localhost'); sys.exit(1)
            print(json.dumps({'issued_certificate': hashlib.sha256(open(sc['new_cert'], 'rb').read()).hexdigest() if sc.get('new_cert') else ''}))
            sys.exit(0)
        if op == 'reapply':
            fingerprint = hashlib.sha256(open(sc['cert_file'], 'rb').read()).hexdigest()
            if fingerprint != cmd[3]:
                print(json.dumps({'installed': False, 'stale': True})); sys.exit(4)
            print(json.dumps({'installed': True, 'certificate': fingerprint})); sys.exit(0)
        if op == 'install':
            def fingerprint():
                return hashlib.sha256(open(sc['cert_file'], 'rb').read()).hexdigest() if os.path.isfile(sc['cert_file']) else ''
            if len(cmd) > 5 and fingerprint() != cmd[5]:
                print(json.dumps({'stale': True, 'installed': False})); sys.exit(4)
            if sc['install'] == 'fail':
                print(json.dumps({'installed': False, 'certificate': fingerprint()}))
                sys.exit(1)
            if sc.get('new_cert'):
                shutil.copyfile(sc['new_cert'], sc['cert_file'])
            print(json.dumps({'installed': True, 'certificate': fingerprint()}))
            sys.exit(0)
        if op == 'notify':
            sys.exit(0)
    if container == 'nginx-ssl':
        record({'op': 'nginx-ssl', 'args': cmd, 'window': window()})
        if sc['issue'] == 'fail':
            sys.exit(1)
        if cmd[0] == 'sh' and 'certbot' in cmd[-1] and sc.get('new_cert'):
            shutil.copyfile(sc['new_cert'], sc['cert_file'])
        sys.exit(0)
sys.exit(3)
'''


def make_cert(path, days=90):
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                    '-keyout', str(path) + '.key', '-out', str(path), '-days', str(days), '-subj', '/CN=localhost',
                    '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)
    return acme.cert_info(str(path))


class Base(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.root = Path(d.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name, body in (('nft', FAKE_NFT), ('docker', FAKE_DOCKER)):
            f = self.bin / name
            f.write_text(body.replace('#!PYTHON', '#!' + sys.executable, 1))
            f.chmod(0o755)
        self.bot = self.root / 'bot'
        for sub in ('certs', 'acme/request', 'acme/state'):
            (self.bot / sub).mkdir(parents=True)
        self.state_dir = self.root / 'var'
        self.nft_state = self.root / 'nft.json'
        self.write_nft(sets={'filter acme_http_fwd': [], 'dockernat acme_http_redirect': []},
                       ruleset=['... ip daddr . tcp dport @acme_http_fwd accept', '... tcp dport @acme_http_redirect dnat'])
        self.cert = self.bot / 'certs/cert_public'
        self.new_cert = self.root / 'new.pem'
        make_cert(self.new_cert)
        self.videocert = self.root / 'video.pem'
        self.scenario = self.root / 'docker.json'
        self.write_docker()
        self.config = self.root / 'config.json'
        self.write_config([{'name': 'vpnbot', 'kind': 'vpnbot', 'upstream': '10.10.0.2:80'}])
        env = {'PATH': f'{self.bin}:{os.environ["PATH"]}', 'FAKE_NFT_STATE': str(self.nft_state),
               'FAKE_DOCKER': str(self.scenario)}
        # Имя localhost в тестовой среде есть и в A, и в AAAA (::1). Для службы оно
        # имя этого сервера: только A 127.0.0.1, как требует проверка DNS окна.
        resolve = acme.socket.getaddrinfo
        self.aaaa = {}
        def getaddrinfo(host, port, family=0, *args, **kwargs):
            if host == 'localhost' and family == acme.socket.AF_INET6:
                if host in self.aaaa:
                    return [(family, acme.socket.SOCK_STREAM, 6, '', (self.aaaa[host], port, 0, 0))]
                raise acme.socket.gaierror(acme.socket.EAI_NONAME, 'no AAAA')
            return resolve(host, port, family, *args, **kwargs)
        for p in (patch.dict(os.environ, env), patch.object(acme, 'CONFIG_PATH', str(self.config)),
                  patch.object(acme.socket, 'getaddrinfo', side_effect=getaddrinfo),
                  patch.object(acme, 'STATE_DIR', str(self.state_dir)),
                  patch.object(acme, 'served_serial', side_effect=lambda h, port, n: acme.cert_info(str(self.cert))['serial'])):
            p.start()
            self.addCleanup(p.stop)
        handlers = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
        self.addCleanup(lambda: [signal.signal(s, h) for s, h in handlers.items()])

    # ── окружение ──

    def write_nft(self, **kw):
        st = {'log': [], 'sets': {}, 'ruleset': []}
        st.update(kw)
        self.nft_state.write_text(json.dumps(st))

    def nft(self):
        return json.loads(self.nft_state.read_text())

    def write_docker(self, **kw):
        sc = {'containers': {'ng': 'nginx-1', 'php': 'php-1'},
              'ips': {'nginx-1': '10.10.0.2 10.10.1.2', 'nginx-ssl': '10.10.2.5'},
              'check': 0, 'domains': ['localhost'], 'issue': 'ok', 'install': 'ok',
              'new_cert': str(self.new_cert), 'cert_file': str(self.root / 'bot/certs/cert_public'), 'calls': []}
        sc.update(kw)
        self.scenario.write_text(json.dumps(sc))

    def calls(self, op=None):
        calls = json.loads(self.scenario.read_text())['calls']
        return [c for c in calls if op is None or c['op'] == op]

    def write_config(self, targets, **kw):
        cfg = {'public_ip': '127.0.0.1', 'bot_dir': str(self.bot), 'targets': targets}
        cfg.update(kw)
        self.config.write_text(json.dumps(cfg))
        self.config.chmod(0o600)

    def state(self):
        return json.loads((self.state_dir / 'state.json').read_text())['targets']

    def shared(self, name):
        return json.loads((self.bot / 'acme/state' / (name + '.json')).read_text())

    def adds(self):
        return [line for c in self.nft()['log'] if c[:2] == ['-f', '-'] for line in c[2:] if line.startswith('add ')]

    def open_sets(self):
        return {k: v for k, v in self.nft()['sets'].items() if v}

    def due_cert(self):
        # Сертификат на 90 дней: при now() на 80-м дне он уже к продлению.
        info = make_cert(self.cert)
        return info, info['not_before'] + 80 * 86400


class AcmeWindowTests(Base):
    # ── плановый запуск ──

    def test_not_due_opens_nothing(self):
        make_cert(self.cert)
        self.assertEqual(acme.main(['run']), 0)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.adds(), [], 'окно не открывалось')
        self.assertEqual(self.open_sets(), {})
        shared = self.shared('vpnbot')
        self.assertTrue(shared['auto'])
        self.assertGreater(shared['due_at'], time.time())
        self.assertEqual(oct((self.bot / 'acme/state/vpnbot.json').stat().st_mode & 0o777), '0o644')
        agent = json.loads((self.bot / 'acme/state/agent.json').read_text())
        self.assertEqual(agent['targets'], ['vpnbot'])

    def test_install_keeps_domain_from_preflight_when_settings_change(self):
        cfg = acme.load_config()
        target = acme.Target(cfg, cfg['targets'][0])
        self.assertEqual(target.preflight(), ['localhost'])
        self.write_docker(domains=['changed.example.org'])
        target.install()
        args = self.calls('install')[0]['args']
        self.assertEqual(args[0], 'localhost')
        self.assertEqual(json.loads(args[1]), ['localhost'],
                         'установка проверяет имена начатого выпуска, а не новые настройки')

    def test_due_renews_inside_window_and_closes_it(self):
        info, when = self.due_cert()
        with patch.object(acme, 'now', return_value=when):
            self.assertEqual(acme.main(['run']), 0)
        ops = [c['op'] for c in self.calls()]
        self.assertEqual(ops, ['check', 'issue', 'install', 'notify'])
        issue = self.calls('issue')[0]
        self.assertEqual(issue['window'], ['10.10.0.2 . 80'], 'выпуск должен идти при открытом окне')
        self.assertEqual(self.calls('install')[0]['window'], [], 'установка — уже при закрытом окне')
        self.assertEqual(self.calls('notify')[0]['args'], ['vpnbot', 'ok'])
        self.assertEqual(self.open_sets(), {})
        self.assertLessEqual(self.nft()['max_timeout'], acme.WINDOW_SECONDS)
        ts = self.state()['vpnbot']
        self.assertEqual((ts['last_result'], ts['failures'], len(ts['issued'])), ('ok', 0, 1))
        self.assertNotEqual(acme.cert_info(str(self.cert))['serial'], info['serial'])

    def test_missing_certificate_is_due_now(self):
        self.assertEqual(acme.main(['run']), 0)
        self.assertEqual([c['op'] for c in self.calls()], ['check', 'issue', 'install', 'notify'])

    def test_failure_closes_window_and_backs_off(self):
        _, when = self.due_cert()
        self.write_docker(issue='fail')
        with patch.object(acme, 'now', return_value=when):
            acme.main(['run'])
        self.assertEqual(self.open_sets(), {})
        ts = self.state()['vpnbot']
        self.assertEqual((ts['last_result'], ts['failures']), ('fail_issue', 1))
        self.assertIn('Challenge failed', ts['last_detail'])
        self.assertEqual(self.calls('notify')[0]['args'], ['vpnbot', 'fail_issue'])
        self.assertEqual(self.shared('vpnbot')['next_attempt'], when + acme.BACKOFF[0])
        # До конца паузы новых попыток нет, после — есть.
        for shift, attempts in ((acme.BACKOFF[0] - 60, 1), (acme.BACKOFF[0] + 60, 2)):
            with patch.object(acme, 'now', return_value=when + shift):
                acme.main(['run'])
            self.assertEqual(len(self.calls('issue')), attempts)
        # О второй неудаче подряд в течение суток не пишем.
        self.assertEqual(len(self.calls('notify')), 1)
        self.assertEqual(self.state()['vpnbot']['failures'], 2)

    def test_backoff_grows_and_urgent_caps_it(self):
        info = make_cert(self.cert)
        ts = acme.target_state({'targets': {}}, 'x', True)
        base = info['not_before'] + 80 * 86400
        ts.update(last_attempt=base, failures=3)
        with patch.object(acme, 'now', return_value=base):
            self.assertEqual(acme.next_attempt(ts, info), base + acme.BACKOFF[2])
            ts['failures'] = 9
            self.assertEqual(acme.next_attempt(ts, info), base + acme.BACKOFF[-1])
        late = info['not_after'] - 3 * 86400
        ts['last_attempt'] = late
        with patch.object(acme, 'now', return_value=late):
            self.assertEqual(acme.next_attempt(ts, info), late + acme.URGENT_BACKOFF)
        ts['auto'] = False
        self.assertEqual(acme.next_attempt(ts, info), 0)

    def test_due_is_two_thirds_of_lifetime(self):
        info = make_cert(self.cert)
        lifetime = info['not_after'] - info['not_before']
        self.assertEqual(acme.due_at(info), int(info['not_after'] - lifetime / 3))
        self.assertEqual(acme.due_at(None), 0)
        # Даты openssl — UTC; разбор не должен зависеть от часового пояса и DST.
        expected = int(datetime(2026, 12, 20, 14, 47, 30, tzinfo=timezone.utc).timestamp())
        for tz in ('UTC', 'Europe/Moscow', 'America/New_York'):
            with patch.dict(os.environ, {'TZ': tz}):
                time.tzset()
                self.assertEqual(acme.parse_date('Dec 20 14:47:30 2026 GMT'), expected)
        time.tzset()
        self.assertEqual(acme.parse_date('Jun  2 01:02:03 2027 GMT'),
                         int(datetime(2027, 6, 2, 1, 2, 3, tzinfo=timezone.utc).timestamp()))

    def test_unchanged_certificate_is_a_failure(self):
        _, when = self.due_cert()
        self.write_docker(new_cert='')
        with patch.object(acme, 'now', return_value=when):
            acme.main(['run'])
        self.assertEqual(self.state()['vpnbot']['last_result'], 'fail_verify')
        self.assertEqual(self.open_sets(), {})

    def test_served_old_certificate_is_reported(self):
        _, when = self.due_cert()
        served = patch.object(acme, 'served_serial', return_value='ABCDEF')
        with patch.object(acme, 'now', return_value=when), served as probe, \
                patch.object(acme, 'SERVED_PAUSES', (0, 0, 0)):
            acme.main(['run'])
        ts = self.state()['vpnbot']
        self.assertEqual(ts['last_result'], 'fail_served_old')
        self.assertEqual(ts['failures'], 1)
        self.assertTrue(ts['pending_install'])
        self.assertEqual(len(ts['issued']), 1)
        self.assertEqual(ts['last_success'], 0)
        self.assertEqual(acme.next_attempt(ts, acme.cert_info(str(self.cert))), when + acme.BACKOFF[0])
        self.assertEqual(probe.call_count, 3, 'nginx даётся время перечитать сертификат')

    def test_pending_retries_install_without_issue_or_window(self):
        _, when = self.due_cert()
        with patch.object(acme, 'now', return_value=when), patch.object(acme, 'served_serial', return_value='OLD'), \
                patch.object(acme, 'SERVED_PAUSES', (0,)):
            acme.main(['run'])
        count = len(self.adds())
        with patch.object(acme, 'now', return_value=when + acme.BACKOFF[0]):
            acme.main(['run'])
        ts = self.state()['vpnbot']
        self.assertEqual(ts['last_result'], 'ok')
        self.assertIsNone(ts['pending_install'])
        self.assertEqual(len(self.calls('issue')), 1)
        self.assertEqual(len(self.calls('install')), 2)
        self.assertEqual(len(self.adds()), count)
        self.assertEqual(len(ts['issued']), 1)

    def test_pending_does_not_overwrite_same_name_restore(self):
        _, when = self.due_cert()
        with patch.object(acme, 'now', return_value=when), patch.object(acme, 'served_serial', return_value='OLD'), \
                patch.object(acme, 'SERVED_PAUSES', (0,)):
            acme.main(['run'])
        make_cert(self.cert)
        restored = self.cert.read_bytes()
        with patch.object(acme, 'now', return_value=when + acme.BACKOFF[0]):
            acme.main(['run'])
        ts = self.state()['vpnbot']
        self.assertEqual(ts['last_result'], 'fail_changed')
        self.assertIsNone(ts['pending_install'])
        self.assertEqual(len(self.calls('issue')), 1)
        self.assertEqual(len(self.calls('install')), 1)
        self.assertEqual(self.cert.read_bytes(), restored)

    def test_pending_does_not_apply_after_names_change(self):
        _, when = self.due_cert()
        with patch.object(acme, 'now', return_value=when), patch.object(acme, 'served_serial', return_value='OLD'), \
                patch.object(acme, 'SERVED_PAUSES', (0,)):
            acme.main(['run'])
        scenario = json.loads(self.scenario.read_text())
        scenario['domains'] = ['localhost', 'changed.example.test']
        self.scenario.write_text(json.dumps(scenario))
        with patch.object(acme, 'now', return_value=when + acme.BACKOFF[0]):
            acme.main(['run'])
        self.assertEqual(self.state()['vpnbot']['last_result'], 'fail_changed')
        self.assertEqual(len(self.calls('issue')), 1)
        self.assertEqual(len(self.calls('install')), 1)

    def test_legacy_served_old_reapplies_current_pair_without_ca(self):
        self.cert.write_bytes(self.new_cert.read_bytes())
        original = self.cert.read_bytes()
        when = acme.now()
        state = {'targets': {}}
        ts = acme.target_state(state, 'vpnbot', True)
        ts.update(last_result='ok_served_old', last_attempt=when - 60, last_success=when - 60,
                  issued=[when - 60] * acme.ISSUE_LIMIT[0])
        self.state_dir.mkdir(exist_ok=True)
        (self.state_dir / 'state.json').write_text(json.dumps(state))
        acme.main(['run'])
        self.assertEqual(self.state()['vpnbot']['last_result'], 'ok')
        self.assertEqual(len(self.calls('reapply')), 1)
        self.assertEqual(len(self.calls('issue')), 0)
        self.assertEqual(len(self.calls('install')), 0)
        self.assertEqual(self.adds(), [])
        self.assertEqual(self.cert.read_bytes(), original)

    def test_issue_checkpoint_survives_interrupted_install(self):
        _, when = self.due_cert()
        with patch.object(acme, 'now', return_value=when), \
                patch.object(acme.Target, 'install', side_effect=acme.Terminated()):
            self.assertNotEqual(acme.main(['run']), 0)
        ts = self.state()['vpnbot']
        self.assertTrue(ts['pending_install'])
        self.assertEqual(len(ts['issued']), 1)
        with patch.object(acme, 'now', return_value=when + 60):
            acme.main(['run'])
        self.assertEqual(self.state()['vpnbot']['last_result'], 'ok')
        self.assertEqual(len(self.calls('issue')), 1)

    def test_failed_install_still_counts_toward_issue_limit(self):
        _, when = self.due_cert()
        for install, result in (('fail', 'fail_install'), ('ok', 'fail_verify')):
            self.write_docker(install=install, new_cert='')
            (self.state_dir / 'state.json').unlink(missing_ok=True)
            with patch.object(acme, 'now', return_value=when):
                acme.main(['run'])
            ts = self.state()['vpnbot']
            self.assertEqual((ts['last_result'], ts['failures']), (result, 1))
            self.assertEqual(len(ts['issued']), 1, 'Let\'s Encrypt уже выдал сертификат: выпуск идёт в лимит')
        # Пробный выпуск в лимит не идёт.
        self.assertEqual(acme.main(['renew', 'vpnbot', '--dry-run']), 0)
        self.assertEqual(len(self.state()['vpnbot']['issued']), 1)

    def test_dns_mismatch_never_opens_window(self):
        self.write_docker(domains=['localhost', 'name.invalid'])
        acme.main(['run'])
        self.assertEqual([c['op'] for c in self.calls()], ['check', 'notify'])
        self.assertEqual(self.state()['vpnbot']['last_result'], 'fail_dns')
        self.assertEqual(self.adds(), [], 'окно не открывается до проверки DNS')

    def test_renewal_rejects_aaaa_like_setup(self):
        # Аудит 26.11.2026 (С25): окно только IPv4, а продление пропускало новую AAAA.
        self.aaaa['localhost'] = '2001:db8::1'
        acme.main(['run'])
        self.assertEqual([c['op'] for c in self.calls()], ['check', 'notify'])
        self.assertEqual(self.state()['vpnbot']['last_result'], 'fail_dns')
        self.assertEqual(self.adds(), [], 'окно не открывается, пока у имени есть AAAA')

    def test_renewal_rejects_extra_a_like_setup(self):
        real = acme.socket.getaddrinfo
        def extra(host, port, family=0, *args, **kwargs):
            answer = real(host, port, family, *args, **kwargs)
            if host == 'localhost' and family == acme.socket.AF_INET:
                answer = answer + [(family, acme.socket.SOCK_STREAM, 6, '', ('198.51.100.7', port))]
            return answer
        with patch.object(acme.socket, 'getaddrinfo', side_effect=extra):
            acme.main(['run'])
        self.assertEqual(self.state()['vpnbot']['last_result'], 'fail_dns')
        self.assertEqual(self.adds(), [], 'лишняя A-запись уводит проверку мимо окна')

    def test_not_letsencrypt_is_silent(self):
        self.write_docker(check=3)
        acme.main(['run'])
        self.assertEqual([c['op'] for c in self.calls()], ['check'])
        ts = self.state()['vpnbot']
        self.assertEqual((ts['last_result'], ts['failures'], ts['last_attempt']), ('not_letsencrypt', 0, 0))

    def test_nginx_moved_is_preflight_failure(self):
        self.write_docker(ips={'nginx-1': '10.10.0.99'})
        acme.main(['run'])
        self.assertEqual(self.state()['vpnbot']['last_result'], 'fail_preflight')
        self.assertEqual([c['op'] for c in self.calls()], ['notify'])

    def test_missing_set_refuses(self):
        self.write_nft(sets={})
        acme.main(['run'])
        self.assertEqual(self.state()['vpnbot']['last_result'], 'fail_window')
        self.assertEqual(self.calls('issue'), [])
        self.assertEqual(acme.main(['check']), 1)

    def test_window_that_cannot_close_is_reported(self):
        self.write_nft(sets={'filter acme_http_fwd': []}, fail_flush=True)
        acme.main(['run'])
        ts = self.state()['vpnbot']
        self.assertEqual(ts['last_result'], 'fail_window')
        self.assertIn('window still open', ts['last_detail'])
        # Элемент, который не удалось удалить, всё равно ограничен временем жизни.
        self.assertEqual(self.nft()['sets']['filter acme_http_fwd'][0]['timeout'], acme.WINDOW_SECONDS)

    def test_stale_window_is_closed_first(self):
        self.write_nft(sets={'filter acme_http_fwd': [{'elem': '10.10.0.2 . 80', 'timeout': 600}],
                             'dockernat acme_http_redirect': [{'elem': '80', 'timeout': 600}]})
        # Сертификата нет — выпуск нужен сразу; окно прерванного запуска должно
        # закрыться до первой же команды, а не после проверок перед выпуском.
        acme.main(['run'])
        self.assertEqual(self.calls()[0]['op'], 'check')
        self.assertEqual(self.calls()[0]['window'], [], 'остаток окна закрыт раньше всего остального')
        self.assertEqual(self.open_sets(), {})
        self.write_nft(sets={'filter acme_http_fwd': [{'elem': '10.10.0.2 . 80', 'timeout': 600}]})
        self.assertEqual(acme.main(['close-all', '--if-unlocked']), 0)
        self.assertEqual(self.open_sets(), {})

    def test_nft_read_failure_is_not_reported_as_missing_or_closed(self):
        self.write_nft(sets={'filter acme_http_fwd': [{'elem': '10.10.0.2 . 80', 'timeout': 600}],
                             'dockernat acme_http_redirect': [{'elem': '80', 'timeout': 600}]}, fail_list=True)
        self.assertEqual(acme.main(['close-all']), 1, 'ошибка проверки не означает успешное закрытие')
        self.assertEqual(self.open_sets(), {}, 'аварийная очистка выполняется даже при отказе чтения')

    def test_issue_failure_does_not_claim_failed_close_succeeded(self):
        self.write_nft(sets={'filter acme_http_fwd': []}, fail_flush=True)
        self.write_docker(issue='fail')
        with patch.object(acme, 'log') as messages:
            acme.main(['run'])
        self.assertTrue(self.open_sets())
        self.assertFalse(any('окно закрыто' in str(call.args[0]) for call in messages.call_args_list))

    def test_close_all_leaves_a_running_window_to_its_owner(self):
        self.write_nft(sets={'filter acme_http_fwd': [{'elem': '10.10.0.2 . 80', 'timeout': 600}]})
        fd = acme.take_lock(0)
        try:
            self.assertEqual(acme.main(['close-all', '--if-unlocked']), 0)
            self.assertEqual(len(self.open_sets()), 1)
        finally:
            os.close(fd)

    def test_explicit_close_fails_if_another_issue_owns_the_window(self):
        self.write_nft(sets={'filter acme_http_fwd': [{'elem': '10.10.0.2 . 80', 'timeout': 600}]})
        fd = acme.take_lock(0)
        try:
            with patch.object(acme, 'LOCK_WAIT', 0):
                self.assertEqual(acme.main(['close-all']), 75)
            self.assertEqual(len(self.open_sets()), 1, 'закрытие не подтверждено; выпуск ещё работает')
        finally:
            os.close(fd)

    # ── запросы бота ──

    def request(self, name):
        (self.bot / 'acme/request' / name).write_text('1\n')

    def test_manual_request_renews_before_due(self):
        make_cert(self.cert)
        self.request('req-renew-vpnbot')
        acme.main(['run'])
        self.assertEqual([c['op'] for c in self.calls()], ['check', 'issue', 'install', 'notify'])
        self.assertEqual(list((self.bot / 'acme/request').iterdir()), [])
        # Второй запрос в течение 10 минут отклоняется, о чём бот узнаёт.
        self.request('req-renew-vpnbot')
        acme.main(['run'])
        self.assertEqual(len(self.calls('issue')), 1)
        self.assertEqual(self.calls('notify')[-1]['args'], ['vpnbot', 'rate_limited'])
        self.assertEqual(self.state()['vpnbot']['last_result'], 'ok', 'отказ не затирает итог выпуска')
        self.assertGreater(self.shared('vpnbot')['last_rejected'], 0)

    def test_issue_limit_holds_for_manual_requests(self):
        make_cert(self.cert)
        self.state_dir.mkdir()
        t = time.time()
        (self.state_dir / 'state.json').write_text(json.dumps({'targets': {'vpnbot': {
            'issued': [t - 3600, t - 7200, t - 86400]}}}))
        self.request('req-renew-vpnbot')
        acme.main(['run'])
        self.assertEqual(self.calls('issue'), [])
        self.assertEqual(self.calls('notify')[-1]['args'], ['vpnbot', 'rate_limited'])

    def test_failed_validation_limit(self):
        _, when = self.due_cert()
        self.write_docker(issue='fail')
        for i in range(5):
            self.request('req-renew-vpnbot')
            with patch.object(acme, 'now', return_value=when + i * (acme.MANUAL_INTERVAL + 1)):
                acme.main(['run'])
        self.assertEqual(len(self.calls('issue')), acme.FAIL_LIMIT[0])

    def test_auto_toggle_and_junk_requests(self):
        _, when = self.due_cert()
        for name in ('req-auto-off-vpnbot', 'req-renew-unknown', 'req-..', 'req-renew-vpnbot-x', 'req-junk', 'other'):
            self.request(name)
        (self.bot / 'acme/request/req-dir').mkdir()
        with patch.object(acme, 'now', return_value=when):
            acme.main(['run'])
        self.assertEqual(self.calls(), [], 'автообновление выключено, запросы мусорные')
        self.assertFalse(self.state()['vpnbot']['auto'])
        self.assertFalse(self.shared('vpnbot')['auto'])
        self.assertEqual(self.shared('vpnbot')['next_attempt'], 0)
        left = sorted(p.name for p in (self.bot / 'acme/request').iterdir())
        self.assertEqual(left, ['other'], 'любой req-* удаляется, иначе .path запускал бы службу без конца')
        self.request('req-auto-on-vpnbot')
        with patch.object(acme, 'now', return_value=when):
            acme.main(['run'])
        self.assertTrue(self.state()['vpnbot']['auto'])
        self.assertEqual(len(self.calls('issue')), 1)

    def test_emergency_close_does_not_require_config(self):
        env = dict(os.environ, ACME_WINDOW_CONFIG=str(self.config), ACME_WINDOW_STATE=str(self.state_dir))
        for mode in ('missing', 'invalid-json', 'unsafe-permissions'):
            with self.subTest(mode=mode):
                self.write_config([{'name': 'vpnbot', 'kind': 'vpnbot', 'upstream': '10.10.0.2:80'}])
                if mode == 'missing':
                    self.config.unlink()
                elif mode == 'invalid-json':
                    self.config.write_text('{broken')
                else:
                    self.config.chmod(0o666)
                acme.nft_batch(['add element ip filter acme_http_fwd { 10.10.0.2 . 80 timeout 600s }',
                                'add element ip dockernat acme_http_redirect { 80 timeout 600s }'])
                result = subprocess.run([sys.executable, str(ROOT / 'scripts/acme_window.py'),
                                         'close-all', '--if-unlocked'], env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual({}, self.open_sets(), 'аварийное закрытие не зависит от настроек выпуска')

    def test_request_dir_symlink_is_ignored(self):
        os.rmdir(self.bot / 'acme/request')
        other = self.root / 'elsewhere'
        other.mkdir()
        (other / 'req-renew-vpnbot').write_text('1')
        os.symlink(other, self.bot / 'acme/request')
        make_cert(self.cert)
        acme.main(['run'])
        self.assertTrue((other / 'req-renew-vpnbot').exists())
        self.assertEqual(self.calls(), [])

    # ── видеобот: перенаправление порта 80 ──

    def video_config(self):
        make_cert(self.videocert)
        self.write_config([
            {'name': 'vpnbot', 'kind': 'vpnbot', 'upstream': '10.10.0.2:80'},
            {'name': 'videobot', 'kind': 'nginx-ssl', 'upstream': '10.10.2.5:80', 'redirect': True,
             'cert_file': str(self.videocert), 'verify_port': 1443, 'label': {'ru': 'видеобот', 'en': 'video bot'}},
        ])
        self.write_docker(cert_file=str(self.videocert))
        make_cert(self.cert)

    def test_video_bot_uses_redirect_and_project_script(self):
        self.video_config()
        self.request('req-renew-videobot')
        with patch.object(acme, 'served_serial', side_effect=lambda h, port, n: acme.cert_info(str(self.videocert))['serial']):
            acme.main(['run'])
        call = self.calls('nginx-ssl')[0]
        self.assertEqual(call['window'], ['10.10.2.5 . 80', '80'])
        self.assertIn('--force-renewal', call['args'][2])
        self.assertTrue(call['args'][2].endswith('&& /renew-certificate.sh'))
        self.assertEqual(self.calls('issue'), [], 'бот vpnbot не трогали')
        self.assertEqual(self.state()['videobot']['last_result'], 'ok')
        self.assertEqual(self.open_sets(), {})
        self.assertEqual(self.shared('videobot')['label']['ru'], 'видеобот')

    def test_video_bot_dry_run(self):
        self.video_config()
        self.assertEqual(acme.main(['renew', 'videobot', '--dry-run']), 0)
        call = self.calls('nginx-ssl')[0]
        self.assertEqual(call['args'], ['/renew-certificate.sh', '--dry-run'])
        ts = self.state()['videobot']
        self.assertEqual((ts['last_result'], ts['issued'], ts['last_attempt']), ('dry_run_ok', [], 0))
        self.assertEqual(self.calls('notify'), [], 'пробный выпуск без уведомления')

    def test_vpnbot_dry_run_passes_flag(self):
        self.assertEqual(acme.main(['renew', 'vpnbot', '--dry-run']), 0)
        self.assertEqual(self.calls('issue')[0]['args'], ['--dry-run'])
        self.assertEqual(self.calls('install'), [])

    # ── конфигурация ──

    def test_config_validation(self):
        bad = [
            [{'name': 'Bad', 'kind': 'vpnbot', 'upstream': '10.10.0.2:80'}],
            [{'name': 'a', 'kind': 'other', 'upstream': '10.10.0.2:80'}],
            [{'name': 'a', 'kind': 'vpnbot', 'upstream': 'nginx:80'}],
            [{'name': 'a', 'kind': 'nginx-ssl', 'upstream': '10.10.2.5:80'}],
            [{'name': 'a', 'kind': 'vpnbot', 'upstream': '10.10.0.2:80'}, {'name': 'a', 'kind': 'vpnbot', 'upstream': '10.10.0.2:80'}],
            [{'name': 'a', 'kind': 'nginx-ssl', 'upstream': '10.0.0.1:80', 'redirect': True, 'cert_file': 'x'},
             {'name': 'b', 'kind': 'nginx-ssl', 'upstream': '10.0.0.2:80', 'redirect': True, 'cert_file': 'x'}],
        ]
        for targets in bad:
            self.write_config(targets)
            with self.assertRaises((SystemExit, OSError, ValueError)):
                acme.load_config()
        self.write_config([{'name': 'vpnbot', 'kind': 'vpnbot', 'upstream': '10.10.0.2:80'}])
        self.config.chmod(0o666)
        with self.assertRaises(SystemExit):
            acme.load_config()

    def test_check_command(self):
        self.write_config([{'name': 'v', 'kind': 'nginx-ssl', 'upstream': '10.10.2.5:80', 'redirect': True,
                            'cert_file': str(self.videocert)}])
        self.assertEqual(acme.main(['check']), 0)
        self.write_nft(sets={'filter acme_http_fwd': [], 'dockernat acme_http_redirect': []},
                       ruleset=['... @acme_http_fwd accept'])
        self.assertEqual(acme.main(['check']), 1, 'правило перенаправления отсутствует')

    def test_corrupt_state_starts_clean(self):
        self.state_dir.mkdir()
        (self.state_dir / 'state.json').write_text('{broken')
        make_cert(self.cert)
        self.assertEqual(acme.main(['run']), 0)
        self.assertIn('vpnbot', self.state())


class AcmeWindowSignalTests(Base):
    """Отдельным процессом: сигнал и kill -9 посреди выпуска."""

    # The service process resolves localhost like the in-process tests: A only (no AAAA ::1).
    IPV4_ONLY = ('import runpy, socket, sys\n'
                 'real = socket.getaddrinfo\n'
                 'def only4(host, port, family=0, *a, **k):\n'
                 '    if host == "localhost" and family == socket.AF_INET6:\n'
                 '        raise socket.gaierror(socket.EAI_NONAME, "no AAAA")\n'
                 '    return real(host, port, family, *a, **k)\n'
                 'socket.getaddrinfo = only4\n'
                 'sys.argv = sys.argv[1:]\n'
                 'runpy.run_path(sys.argv[0], run_name="__main__")\n')

    def start(self):
        self.write_docker(issue='sleep')
        env = dict(os.environ, ACME_WINDOW_CONFIG=str(self.config), ACME_WINDOW_STATE=str(self.state_dir))
        p = subprocess.Popen([sys.executable, '-c', self.IPV4_ONLY, str(ROOT / 'scripts/acme_window.py'), 'run'], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        deadline = time.time() + 30
        while time.time() < deadline and not self.calls('issue'):
            time.sleep(0.1)
        self.assertTrue(self.calls('issue'), 'выпуск не начался')
        self.assertEqual(len(self.open_sets()), 1, 'во время выпуска окно открыто')
        return p, env

    def test_sigterm_closes_window(self):
        p, _ = self.start()
        p.send_signal(signal.SIGTERM)
        out, _ = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 143, out)
        self.assertEqual(self.open_sets(), {}, out)

    def test_kill9_is_cleaned_by_stop_post(self):
        p, env = self.start()
        p.kill()
        p.wait(timeout=30)
        p.stdout.close()
        sets = self.open_sets()
        self.assertEqual(sets['filter acme_http_fwd'][0]['timeout'], acme.WINDOW_SECONDS,
                         'после kill -9 окно держит только время жизни элемента')
        # ExecStopPost службы.
        subprocess.run([sys.executable, str(ROOT / 'scripts/acme_window.py'), 'close-all', '--if-unlocked'],
                       env=env, check=True, capture_output=True, timeout=30)
        self.assertEqual(self.open_sets(), {})


class AcmeWindowUnitFilesTests(unittest.TestCase):
    def test_units_and_installer(self):
        service = (ROOT / 'scripts/acme-window.service').read_text()
        self.assertIn('ExecStopPost=/usr/bin/python3 /usr/local/sbin/acme-window close-all --if-unlocked', service)
        # Сигнал по всей группе процессов убивает и ExecStopPost: тогда окно
        # закрывает отдельная служба, которую systemd запускает при отказе.
        self.assertIn('OnFailure=acme-window-close.service', service)
        close = (ROOT / 'scripts/acme-window-close.service').read_text()
        self.assertIn('ExecStart=/usr/bin/python3 /usr/local/sbin/acme-window close-all --if-unlocked', close)
        timeout = int(service.split('TimeoutStartSec=')[1].split('min')[0]) * 60
        self.assertGreater(timeout, acme.LOCK_WAIT + acme.ISSUE_TIMEOUT + acme.INSTALL_TIMEOUT + 120)
        self.assertLess(acme.ISSUE_TIMEOUT, acme.WINDOW_SECONDS)
        self.assertLess(acme.CERTBOT_TIMEOUT, acme.ISSUE_TIMEOUT)
        path = (ROOT / 'scripts/acme-window.path').read_text()
        self.assertIn('PathExistsGlob=__VPNBOT_PATH__/acme/request/req-*', path)
        installer = (ROOT / 'scripts/install_acme_window.sh').read_text()
        for unit in ('acme-window.service', 'acme-window-close.service', 'acme-window.timer', 'acme-window.path'):
            self.assertIn(unit, installer)
        self.assertIn('acme-window check', installer)
        subprocess.run(['sh', '-n', str(ROOT / 'scripts/install_acme_window.sh')], check=True)
        compose = (ROOT / 'docker-compose.yml').read_text()
        self.assertIn('- ./acme/request:/acme/request\n', compose)
        self.assertIn('- ./acme/state:/acme/state:ro\n', compose)
        self.assertIn('\n/acme/\n', (ROOT / '.gitignore').read_text())


class InstallerUninstallTests(unittest.TestCase):
    def test_active_issue_stopped_before_removing_agent(self):
        self.check_uninstall('loaded', False)

    def test_uninstall_absent_service_is_idempotent(self):
        self.check_uninstall('not-found', False)

    def test_failed_stop_keeps_agent_installed(self):
        self.check_uninstall('loaded', True)

    def test_failed_close_keeps_agent_installed(self):
        self.check_uninstall('loaded', False, fail_close=True)

    def check_uninstall(self, load_state, fail_stop, fail_close=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            units = root / 'units'
            units.mkdir()
            agent = root / 'agent'
            agent.write_text('import sys\nsys.exit(' + ('9' if fail_close else '0') + ')\n')
            agent.chmod(0o755)
            heartbeat = root / 'acme/state/agent.json'
            heartbeat.parent.mkdir(parents=True)
            heartbeat.write_text(json.dumps({'updated': int(time.time()), 'targets': ['vpnbot']}))
            state = root / 'running'
            if load_state == 'loaded':
                state.touch()
            systemctl = root / 'systemctl'
            systemctl.write_text('#!' + sys.executable + '\n' +
                'import os,sys\nfrom pathlib import Path\n' +
                'state=Path(os.environ["TEST_SERVICE_RUNNING"])\n' +
                'if sys.argv[1]=="show": print(os.environ["TEST_SERVICE_LOAD"])\n' +
                'if sys.argv[1]=="stop":\n' +
                ' if os.environ["TEST_STOP_FAIL"]=="1": sys.exit(1)\n' +
                ' state.unlink(missing_ok=True)\n')
            systemctl.chmod(0o755)
            installer = root / 'install.sh'
            installer.write_text((ROOT / 'scripts/install_acme_window.sh').read_text()
                .replace('/usr/local/sbin/acme-window', str(agent))
                .replace('/etc/systemd/system/', str(units) + '/'))
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                       TEST_SERVICE_RUNNING=str(state), TEST_SERVICE_LOAD=load_state,
                       TEST_STOP_FAIL=str(int(fail_stop)))
            result = subprocess.run(['sh', str(installer), '--uninstall'], env=env, cwd=root,
                                    capture_output=True, text=True, timeout=15)
            if fail_stop or fail_close:
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(agent.exists(), 'нельзя удалить агент, пока закрытие окна не подтверждено')
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(state.exists(), 'после удаления выпуск не должен открывать окно')
                self.assertFalse(agent.exists())
                self.assertFalse(heartbeat.exists(), 'бот должен сразу обнаружить удаление службы')


if __name__ == '__main__':
    unittest.main()
