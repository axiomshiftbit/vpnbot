#!/usr/bin/env python3
"""acme-window: продление сертификатов Let's Encrypt через временное окно HTTP-01.

Служба хоста для серверов, где порт 80 снаружи закрыт firewall. Когда сертификату
пора продлеваться (или администратор нажал кнопку в боте), служба на несколько
минут добавляет элемент в набор nftables, принудительно выпускает сертификат и
удаляет элемент. Правила, которые ссылаются на наборы, постоянно стоят в
/etc/nftables.conf; основные правила служба не меняет и не перечитывает.

Окно закрывается несколькими независимыми путями:
  1. явное удаление элементов с проверкой, что наборы пусты;
  2. finally и обработчики SIGTERM/SIGINT/SIGHUP;
  3. время жизни элемента в ядре (WINDOW_SECONDS) — даже после kill -9;
  4. ExecStopPost службы (close-all) после любого её завершения;
  5. каждый запуск сначала очищает наборы, оставшиеся от прерванного;
  6. после перезагрузки и nft -f /etc/nftables.conf наборы пусты.

Обмен с ботом — каталог <бот>/acme: request/ (бот пишет, служба забирает файлы
req-*) и state/ (пишет только служба, у бота только чтение).

  acme-window run                       плановый запуск: таймер и запросы бота
  acme-window renew ЦЕЛЬ [--dry-run]    выпуск сейчас из консоли
  acme-window status                    состояние целей
  acme-window check                     наборы и правила nftables на месте
  acme-window close-all [--if-unlocked] закрыть все окна
"""

import argparse
import calendar
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

VERSION = 1
CONFIG_PATH = os.environ.get('ACME_WINDOW_CONFIG', '/etc/acme-window/config.json')
STATE_DIR = os.environ.get('ACME_WINDOW_STATE', '/var/lib/acme-window')

FWD_SET = ('ip', 'filter', 'acme_http_fwd')
REDIRECT_SET = ('ip', 'dockernat', 'acme_http_redirect')
# Закрываются всегда оба набора, если они есть, даже если цель с redirect
# убрали из конфигурации после открытия окна.
ALL_SETS = (FWD_SET, REDIRECT_SET)

WINDOW_SECONDS = 600          # время жизни элемента окна в ядре
CERTBOT_TIMEOUT = 300         # certbot внутри контейнера
ISSUE_TIMEOUT = 480           # шаг выпуска целиком, с запасом меньше окна
INSTALL_TIMEOUT = 300
LOCK_WAIT = 1500              # на SERVER-B две цели делят порт 80 и идут по очереди
RENEW_FRACTION = 1 / 3        # продлевать, когда осталась треть срока
URGENT_SECONDS = 7 * 86400
BACKOFF = (3600, 7200, 14400, 21600)
URGENT_BACKOFF = 3600
# Let's Encrypt: не больше 5 сертификатов на одинаковый набор имён за 7 дней и
# 5 неудачных проверок имени в час. Свои пределы — с запасом.
ISSUE_LIMIT = (3, 7 * 86400)
FAIL_LIMIT = (3, 3600)
MANUAL_INTERVAL = 600
NOTIFY_REPEAT = 86400
NOTIFY_REPEAT_URGENT = 21600
SERVED_PAUSES = (0, 5, 10)   # nginx перечитывает сертификат не мгновенно

NAME_RE = re.compile(r'^[a-z0-9]{1,32}$')
REQUEST_RE = re.compile(r'^req-(renew|auto-on|auto-off|refresh)(?:-([a-z0-9]{1,32}))?$')
HOST_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$')
SERIAL_RE = re.compile(r'^[0-9A-F]+$')


class Fail(Exception):
    """Отказ попытки; code уходит боту, detail — короткое пояснение."""

    def __init__(self, code, detail=''):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail
        self.issued = False


class Terminated(BaseException):
    """Сигнал остановки: BaseException, чтобы его не перехватил except Fail."""


def log(message):
    print(message, flush=True)


def now():
    return int(time.time())


def run(cmd, timeout=60, input=None):
    try:
        p = subprocess.run(cmd, input=input, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, '', 'timeout after %d s' % timeout
    except FileNotFoundError:
        return 127, '', 'not found: ' + cmd[0]
    return p.returncode, p.stdout, p.stderr


def tail(text, limit=300):
    lines = [line.strip() for line in (text or '').splitlines() if line.strip()]
    return ' | '.join(lines[-3:])[-limit:]


# ── nftables ──────────────────────────────────────────────────────────────

def set_exists(spec):
    code, _, err = run(['nft', 'list', 'set', *spec], timeout=15)
    if code == 0:
        return True
    if code == 1 and 'No such file or directory' in err:
        return False
    raise Fail('fail_window', 'cannot inspect nft set %s: %s' % (spec[2], tail(err)))


def set_elements(spec):
    code, out, err = run(['nft', '-j', 'list', 'set', *spec], timeout=15)
    if code != 0:
        raise Fail('fail_window', 'nft list set %s: %s' % (spec[2], tail(err)))
    for item in json.loads(out).get('nftables', []):
        if 'set' in item:
            return item['set'].get('elem', [])
    return []


def nft_batch(lines):
    """Одна транзакция nft: либо применяется целиком, либо не применяется."""
    code, _, err = run(['nft', '-f', '-'], input='\n'.join(lines) + '\n', timeout=15)
    if code != 0:
        raise Fail('fail_window', 'nft: ' + tail(err))


def close_all(sets):
    """Удаляет все элементы окон; Fail, если после этого что-то осталось."""
    # Сначала закрываем, затем проверяем. Ошибка чтения nft не означает,
    # что набора нет, и не должна отменять попытку аварийного закрытия.
    try:
        nft_batch(['flush set ' + ' '.join(s) for s in sets])
    except Fail:
        # Необязательный redirect-набор может отсутствовать: тогда общая
        # транзакция откатится, но существующие наборы всё равно очистятся.
        for s in sets:
            run(['nft', 'flush', 'set', *s], timeout=15)
    present = [s for s in sets if set_exists(s)]
    left = [s for s in present if set_elements(s)]
    for s in left:
        # Запасной путь, если общая транзакция отказала.
        run(['nft', 'flush', 'set', *s], timeout=15)
    left = [s for s in left if set_elements(s)]
    if left:
        raise Fail('fail_window', 'window still open: ' + ', '.join(s[2] for s in left))


# ── конфигурация и состояние ──────────────────────────────────────────────

def load_config(path=None):
    path = path or CONFIG_PATH
    st = os.stat(path)
    if st.st_uid != os.geteuid() or st.st_mode & 0o022:
        raise SystemExit(path + ': владелец должен быть root, запись для группы и остальных запрещена')
    with open(path) as f:
        cfg = json.load(f)
    ipaddress.IPv4Address(cfg['public_ip'])
    cfg.setdefault('bot_dir', '/root/vpnbot')
    cfg['acme_dir'] = os.path.join(cfg['bot_dir'], 'acme')
    names = set()
    for t in cfg['targets']:
        name = t.get('name', '')
        if not NAME_RE.match(name) or name in names:
            raise SystemExit('неверное или повторное имя цели: %r' % name)
        names.add(name)
        if t.get('kind') not in ('vpnbot', 'nginx-ssl'):
            raise SystemExit('%s: неизвестный вид цели %r' % (name, t.get('kind')))
        ip, port = t['upstream'].rsplit(':', 1)
        ipaddress.IPv4Address(ip)
        t['upstream_ip'], t['upstream_port'] = ip, int(port)
        if not 0 < t['upstream_port'] < 65536:
            raise SystemExit(name + ': неверный порт upstream')
        t['verify_port'] = int(t.get('verify_port', 443))
        t['auto'] = bool(t.get('auto', True))
        t['redirect'] = bool(t.get('redirect', False))
        t.setdefault('label', {'ru': name, 'en': name})
        if t['kind'] == 'nginx-ssl':
            t.setdefault('container', 'nginx-ssl')
            if not t.get('cert_file'):
                raise SystemExit(name + ': для nginx-ssl нужен cert_file')
        else:
            t['cert_file'] = os.path.join(cfg['bot_dir'], 'certs', 'cert_public')
    if sum(t['redirect'] for t in cfg['targets']) > 1:
        raise SystemExit('перенаправление порта 80 допускается только для одной цели')
    return cfg


def windows_of(cfg):
    sets = [FWD_SET]
    if any(t['redirect'] for t in cfg['targets']):
        sets.append(REDIRECT_SET)
    return sets


def write_json(path, data, mode=0o600):
    """Атомарная запись: временный файл в том же каталоге и rename."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix='.tmp-')
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, ensure_ascii=False, indent=1, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def load_state():
    try:
        with open(os.path.join(STATE_DIR, 'state.json')) as f:
            state = json.load(f)
        if isinstance(state.get('targets'), dict):
            return state
    except FileNotFoundError:
        pass
    except ValueError:
        log('state.json повреждён: начинаю с пустого состояния')
    return {'targets': {}}


def target_state(state, name, default_auto):
    ts = state['targets'].setdefault(name, {})
    ts.setdefault('auto', default_auto)
    for key in ('issued', 'failed_at'):
        ts.setdefault(key, [])
    for key in ('failures', 'last_attempt', 'last_manual', 'last_notify', 'last_success', 'last_rejected'):
        ts.setdefault(key, 0)
    ts.setdefault('last_result', '')
    ts.setdefault('last_detail', '')
    ts.setdefault('pending_install', None)
    return ts


def recent(stamps, period):
    edge = now() - period
    return [s for s in stamps if s > edge]


# ── сертификаты ───────────────────────────────────────────────────────────

def parse_date(value):
    return calendar.timegm(time.strptime(value.replace(' GMT', '').strip(), '%b %d %H:%M:%S %Y'))


def cert_info(path):
    """Даты, серийный номер и имена; None, если файла нет или он не читается."""
    if not os.path.isfile(path):
        return None
    code, out, _ = run(['openssl', 'x509', '-in', path, '-noout', '-startdate', '-enddate',
                        '-serial', '-ext', 'subjectAltName'], timeout=15)
    if code != 0:
        return None
    info = {'names': []}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('notBefore='):
            info['not_before'] = parse_date(line.split('=', 1)[1])
        elif line.startswith('notAfter='):
            info['not_after'] = parse_date(line.split('=', 1)[1])
        elif line.startswith('serial='):
            info['serial'] = line.split('=', 1)[1].upper()
        elif line.startswith('DNS:'):
            info['names'] = [n.strip()[4:] for n in line.split(',') if n.strip().startswith('DNS:')]
    if 'not_after' not in info or 'serial' not in info:
        return None
    return info


def due_at(info):
    """Когда пора продлевать; 0 — сертификата нет, пора сейчас."""
    if not info:
        return 0
    start = info.get('not_before', info['not_after'] - 90 * 86400)
    return int(info['not_after'] - (info['not_after'] - start) * RENEW_FRACTION)


def certificate_fingerprint(path):
    try:
        with open(path, 'rb') as stream:
            digest = hashlib.sha256()
            for block in iter(lambda: stream.read(65536), b''):
                digest.update(block)
            return digest.hexdigest()
    except OSError:
        return ''


def served_serial(host, port, name):
    """Серийный номер сертификата, который сервер отдаёт по имени name."""
    try:
        p1 = subprocess.run(['openssl', 's_client', '-connect', '%s:%d' % (host, port), '-servername', name],
                            input='', capture_output=True, text=True, timeout=20)
        p2 = subprocess.run(['openssl', 'x509', '-noout', '-serial'], input=p1.stdout,
                            capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return ''
    serial = p2.stdout.strip().split('=', 1)[-1].upper() if p2.returncode == 0 else ''
    return serial if SERIAL_RE.match(serial) else ''


def check_dns(public_ip, names):
    """Все имена должны указывать на этот сервер, иначе проверка заведомо не пройдёт."""
    bad = []
    for n in names:
        try:
            addrs = {a[4][0] for a in socket.getaddrinfo(n, 80, socket.AF_INET, socket.SOCK_STREAM)}
        except OSError:
            addrs = set()
        if public_ip not in addrs:
            bad.append(n)
    if bad:
        raise Fail('fail_dns', 'not %s: %s' % (public_ip, ', '.join(bad[:5])))


# ── цели ──────────────────────────────────────────────────────────────────

def compose_container(cfg, service):
    code, out, err = run(['docker', 'ps', '--filter', 'label=com.docker.compose.service=' + service,
                          '--filter', 'label=com.docker.compose.project.working_dir=' + cfg['bot_dir'],
                          '--format', '{{.Names}}'], timeout=30)
    names = out.split()
    if code != 0 or len(names) != 1:
        raise Fail('fail_preflight', 'container %s: %s' % (service, tail(err) or '%d running' % len(names)))
    return names[0]


def container_ips(name):
    code, out, err = run(['docker', 'inspect', '-f',
                          '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}', name], timeout=30)
    if code != 0:
        raise Fail('fail_preflight', 'docker inspect %s: %s' % (name, tail(err)))
    return out.split()


class Target:
    def __init__(self, cfg, t):
        self.cfg, self.t = cfg, t
        self.php = None
        self.names = []
        self.expected_certificate = None
        self.issued_certificate = None
        self.installed_certificate = None
        self.reapply_installed = False

    def preflight(self):
        """Проверки до открытия окна; возвращает имена сертификата."""
        t = self.t
        if t['kind'] == 'vpnbot':
            nginx = compose_container(self.cfg, 'ng')
            if t['upstream_ip'] not in container_ips(nginx):
                raise Fail('fail_preflight', '%s is not at %s' % (nginx, t['upstream_ip']))
            self.php = compose_container(self.cfg, 'php')
            code, out, err = run(['docker', 'exec', self.php, 'php', '/app/acme_renew.php', 'check'], timeout=60)
            if code == 3:
                raise Fail('not_letsencrypt')
            if code != 0:
                raise Fail('fail_preflight', 'check: ' + tail(err or out))
            try:
                names = json.loads(out)['domains']
            except (ValueError, KeyError, TypeError):
                raise Fail('fail_preflight', 'check: bad answer')
        else:
            if t['upstream_ip'] not in container_ips(t['container']):
                raise Fail('fail_preflight', '%s is not at %s' % (t['container'], t['upstream_ip']))
            info = cert_info(t['cert_file'])
            names = info['names'] if info else []
        names = [n for n in names if isinstance(n, str) and HOST_RE.match(n)]
        if not names:
            raise Fail('fail_preflight', 'no domain names')
        self.names = names
        return names

    def issue(self, dry_run):
        t = self.t
        if t['kind'] == 'vpnbot':
            cmd = ['docker', 'exec', self.php, 'php', '/app/acme_renew.php', 'issue'] + (['--dry-run'] if dry_run else [])
        elif dry_run:
            cmd = ['docker', 'exec', t['container'], '/renew-certificate.sh', '--dry-run']
        else:
            # Штатный скрипт проекта продлевает только по сроку; выпуск здесь
            # принудительный, а установку и перезагрузку nginx делает скрипт.
            cmd = ['docker', 'exec', t['container'], 'sh', '-c',
                   'timeout -k 10 %d certbot renew --non-interactive --force-renewal --cert-name "$SSLIP_DOMAIN" '
                   '--webroot -w /var/www/certbot --no-random-sleep-on-renew && /renew-certificate.sh'
                   % CERTBOT_TIMEOUT]
        code, out, err = run(cmd, timeout=ISSUE_TIMEOUT)
        if code != 0:
            raise Fail('fail_issue', tail(err + '\n' + out))
        if t['kind'] == 'vpnbot' and not dry_run:
            try:
                self.issued_certificate = json.loads(out.splitlines()[-1])['issued_certificate']
            except (ValueError, IndexError, KeyError, TypeError):
                # Совместимость с предыдущим CLI; fingerprint активного файла
                # всё равно проверяется, receipt появится после обновления PHP.
                self.issued_certificate = None
        return tail(out)

    def install(self):
        if self.t['kind'] != 'vpnbot':
            code, _, _ = run(['docker', 'exec', self.t['container'], 'sh', '-c', 'nginx -t && nginx -s reload'], timeout=INSTALL_TIMEOUT)
            if code != 0:
                raise Fail('fail_install', 'nginx reload failed')
            self.installed_certificate = certificate_fingerprint(self.t['cert_file'])
            return
        # Все имена фиксируются до выпуска: восстановление могло сменить и
        # основной домен, и только алиасы. PHP сверит их под блокировкой бэкапа.
        args = [self.names[0], json.dumps(self.names)]
        if self.expected_certificate is not None:
            args.append(self.expected_certificate)
            if self.issued_certificate is not None:
                args.append(self.issued_certificate)
        command = ['reapply', self.expected_certificate] if self.reapply_installed else ['install', *args]
        code, out, err = run(['docker', 'exec', self.php, 'php', '/app/acme_renew.php', *command],
                             timeout=INSTALL_TIMEOUT)
        try:
            receipt = json.loads(out)
            if isinstance(receipt.get('certificate'), str):
                self.installed_certificate = receipt['certificate']
        except (ValueError, AttributeError):
            pass
        if code == 4:
            raise Fail('fail_changed', 'certificate generation changed')
        if code != 0:
            raise Fail('fail_install', 'certificate application failed')

    def open_lines(self):
        t = self.t
        lines = ['add element %s { %s . %d timeout %ds }' % (' '.join(FWD_SET), t['upstream_ip'],
                                                             t['upstream_port'], WINDOW_SECONDS)]
        if t['redirect']:
            lines.append('add element %s { 80 timeout %ds }' % (' '.join(REDIRECT_SET), WINDOW_SECONDS))
        return lines


def attempt(cfg, t, dry_run=False, pending=None, checkpoint=None):
    """Выпуск через окно. Возвращает (код, пояснение) или бросает Fail.

    К выходу из функции окно закрыто при любом исходе, включая сигнал."""
    target = Target(cfg, t)
    sets = ALL_SETS
    before = cert_info(t['cert_file'])
    before_fingerprint = certificate_fingerprint(t['cert_file'])
    names = target.preflight()
    if pending:
        if (sorted(names) != sorted(pending['names']) or pending['cert_file'] != t['cert_file']
                or pending['kind'] != t['kind'] or before_fingerprint != pending['certificate']):
            raise Fail('fail_changed', 'pending certificate generation changed')
        return apply_pending(cfg, t, target, pending, checkpoint)
    check_dns(cfg['public_ip'], names)
    for s in windows_of(cfg):
        if not set_exists(s):
            raise Fail('fail_window', 'nft set missing: ' + ' '.join(s))
    close_all(sets)
    try:
        nft_batch(target.open_lines())
        log('%s: окно открыто не дольше %d с' % (t['name'], WINDOW_SECONDS))
        if not set_elements(FWD_SET):
            raise Fail('fail_window', 'window did not open')
        detail = target.issue(dry_run)
        if not dry_run:
            pending = {'names': names, 'kind': t['kind'], 'cert_file': t['cert_file'],
                       'before_serial': before['serial'] if before else '',
                       'certificate': before_fingerprint if t['kind'] == 'vpnbot' else certificate_fingerprint(t['cert_file']),
                       'issued_certificate': target.issued_certificate}
            # Выпуск учтён до install: сбой/сигнал не запускает certbot повторно.
            if checkpoint:
                checkpoint(pending, True)
    except BaseException:
        # Отказ закрытия не должен подменить исходную причину (в том числе
        # сигнал остановки): элементы всё равно истекут по времени жизни.
        try:
            close_all(sets)
            log('%s: окно закрыто' % t['name'])
        except Fail as e:
            log('ВНИМАНИЕ: ' + e.detail)
        raise
    try:
        close_all(sets)
        log('%s: окно закрыто' % t['name'])
        if dry_run:
            return 'dry_run_ok', detail
        return apply_pending(cfg, t, target, pending, checkpoint)
    except Fail as e:
        # Let's Encrypt сертификат уже выдал: попытка идёт в лимит выпусков,
        # иначе повторы при сломанной установке исчерпали бы лимит Let's Encrypt.
        e.issued = not dry_run
        raise


def apply_pending(cfg, t, target, pending, checkpoint):
    """Только install/verify уже выпущенного сертификата; без certbot и окна."""
    target.expected_certificate = pending['certificate']
    target.issued_certificate = pending.get('issued_certificate')
    target.reapply_installed = pending.get('reapply_installed', False)
    try:
        target.install()
    finally:
        if target.installed_certificate is not None:
            pending['certificate'] = target.installed_certificate
            if checkpoint:
                checkpoint(pending, False)
    after = cert_info(t['cert_file'])
    if not after or after['serial'] == pending['before_serial']:
        raise Fail('fail_verify', 'certificate file did not change')
    for pause in SERVED_PAUSES:
        time.sleep(pause)
        serial = served_serial(cfg['public_ip'], t['verify_port'], pending['names'][0])
        if serial == after['serial']:
            return 'ok', ''
    raise Fail('fail_served_old', 'served certificate does not match installed file')


def next_attempt(ts, info):
    """Время следующей плановой попытки; 0 — автообновление выключено."""
    if not ts['auto']:
        return 0
    pending = bool(ts.get('pending_install')) or ts['last_result'] == 'ok_served_old'
    start = ts['last_attempt'] if pending else due_at(info)
    if ts['failures']:
        urgent = info is None or info['not_after'] - now() < URGENT_SECONDS
        delay = URGENT_BACKOFF if urgent else BACKOFF[min(ts['failures'], len(BACKOFF)) - 1]
        start = max(start, ts['last_attempt'] + delay)
    if pending:
        return start  # Лимиты CA относятся к выпуску, не к reload уже выпущенного.
    issued = recent(ts['issued'], ISSUE_LIMIT[1])
    if len(issued) >= ISSUE_LIMIT[0]:
        start = max(start, min(issued) + ISSUE_LIMIT[1])
    failed = recent(ts['failed_at'], FAIL_LIMIT[1])
    if len(failed) >= FAIL_LIMIT[0]:
        start = max(start, min(failed) + FAIL_LIMIT[1])
    return start


def limited(ts):
    return (len(recent(ts['issued'], ISSUE_LIMIT[1])) >= ISSUE_LIMIT[0]
            or len(recent(ts['failed_at'], FAIL_LIMIT[1])) >= FAIL_LIMIT[0])


class Runner:
    def __init__(self, cfg):
        self.cfg = cfg
        self.state = load_state()

    def ts(self, t):
        return target_state(self.state, t['name'], t['auto'])

    def save(self):
        write_json(os.path.join(STATE_DIR, 'state.json'), self.state)

    def share_dir(self, sub):
        d = os.path.join(self.cfg['acme_dir'], sub)
        return d if os.path.isdir(d) and not os.path.islink(d) else None

    def publish(self, t, busy=False):
        d = self.share_dir('state')
        if not d:
            return
        ts, info = self.ts(t), cert_info(t['cert_file'])
        write_json(os.path.join(d, t['name'] + '.json'), {
            'version': VERSION, 'name': t['name'], 'kind': t['kind'], 'label': t['label'],
            'auto': ts['auto'], 'updated': now(), 'busy': busy,
            'not_after': info['not_after'] if info else 0,
            'not_before': info.get('not_before', 0) if info else 0,
            'due_at': due_at(info), 'next_attempt': next_attempt(ts, info),
            'last_attempt': ts['last_attempt'], 'last_result': ts['last_result'],
            'last_detail': ts['last_detail'], 'last_success': ts['last_success'], 'failures': ts['failures'],
            'last_rejected': ts['last_rejected'],
        }, 0o644)

    def publish_agent(self):
        d = self.share_dir('state')
        if d:
            write_json(os.path.join(d, 'agent.json'), {
                'version': VERSION, 'updated': now(), 'targets': [t['name'] for t in self.cfg['targets']],
            }, 0o644)

    def notify(self, t, result, always=False):
        """Сообщение администраторам бота; о повторных неудачах — не чаще раза в сутки."""
        if result == 'not_letsencrypt' or result.startswith('dry_run'):
            return
        ts = self.ts(t)
        if not always and not result.startswith('ok'):
            info = cert_info(t['cert_file'])
            urgent = info is None or info['not_after'] - now() < URGENT_SECONDS
            repeat = NOTIFY_REPEAT_URGENT if urgent else NOTIFY_REPEAT
            if ts['failures'] > 1 and now() - ts['last_notify'] < repeat:
                return
        try:
            php = compose_container(self.cfg, 'php')
        except Fail as e:
            log('%s: уведомление не отправлено: %s' % (t['name'], e.detail))
            return
        code, out, err = run(['docker', 'exec', php, 'php', '/app/acme_renew.php', 'notify', t['name'], result],
                             timeout=60)
        if code == 0:
            ts['last_notify'] = now()
        else:
            log('%s: уведомление не отправлено: %s' % (t['name'], tail(err or out)))

    def take_requests(self):
        """Забирает запросы бота. Файл удаляется всегда, даже отклонённый запрос."""
        d = self.share_dir('request')
        manual = set()
        if not d:
            return manual
        by_name = {t['name']: t for t in self.cfg['targets']}
        for entry in sorted(os.listdir(d)):
            # Юнит .path срабатывает на любой req-*: неудалённый файл с чужим
            # именем запускал бы службу снова и снова.
            if not entry.startswith('req-'):
                continue
            path = os.path.join(d, entry)
            try:
                if os.path.isdir(path) and not os.path.islink(path):
                    shutil.rmtree(path)
                    continue
                os.unlink(path)
            except OSError:
                continue
            m = REQUEST_RE.match(entry)
            if not m:
                log('запрос %r: неизвестный формат, удалён' % entry)
                continue
            action, name = m.group(1), m.group(2)
            if action == 'refresh':
                continue
            if name not in by_name:
                log('запрос %s: неизвестная цель' % entry)
                continue
            if action == 'renew':
                manual.add(name)
            else:
                self.ts(by_name[name])['auto'] = action == 'auto-on'
                log('%s: автообновление %s' % (name, 'включено' if action == 'auto-on' else 'выключено'))
        return manual

    def pending(self):
        d = self.share_dir('request')
        return bool(d) and any(e.startswith('req-') for e in os.listdir(d))

    def one(self, t, manual=False, dry_run=False):
        """Попытка для цели, если она нужна. Возвращает код результата или None."""
        ts = self.ts(t)
        if not dry_run and not ts.get('pending_install') and ts['last_result'] == 'ok_served_old':
            info = cert_info(t['cert_file'])
            if info:
                ts['pending_install'] = {'names': info.get('names', []), 'kind': t['kind'], 'cert_file': t['cert_file'],
                    'before_serial': '', 'certificate': certificate_fingerprint(t['cert_file']), 'reapply_installed': True}
                self.save()
        if not dry_run:
            if (limited(ts) and not ts.get('pending_install')) or (manual and now() - ts['last_manual'] < MANUAL_INTERVAL):
                if not manual:
                    return None
                # Последний настоящий результат не затираем: отказ — отдельное поле.
                ts['last_rejected'] = now()
                self.save()
                self.publish(t)
                self.notify(t, 'rate_limited', always=True)
                self.save()
                return 'rate_limited'
            if not manual and (not ts['auto'] or now() < next_attempt(ts, cert_info(t['cert_file']))):
                return None
            if manual:
                ts['last_manual'] = now()
        self.publish(t, busy=True)
        started = now()
        issued = False
        recorded_issue = False
        pending = None if dry_run else ts.get('pending_install')
        def checkpoint(value, newly_issued):
            nonlocal recorded_issue
            ts['pending_install'] = value
            ts['last_attempt'] = started
            if newly_issued:
                recorded_issue = True
                ts['issued'] = recent(ts['issued'], ISSUE_LIMIT[1]) + [now()]
            self.save()
        try:
            result, detail = attempt(self.cfg, t, dry_run, pending, checkpoint)
            issued = result == 'ok' and not pending
        except Fail as e:
            result, detail, issued = e.code, e.detail, e.issued
        log(('%s: %s %s' % (t['name'], result, detail)).rstrip())
        if dry_run:
            ts['last_result'] = result if result == 'dry_run_ok' else 'dry_run_fail'
            ts['last_detail'] = detail
        elif result == 'not_letsencrypt':
            ts['last_result'], ts['last_detail'] = result, ''
            ts['pending_install'] = None
        else:
            ts['last_attempt'] = started
            ts['last_result'], ts['last_detail'] = result, detail
            if issued and not recorded_issue:
                ts['issued'] = recent(ts['issued'], ISSUE_LIMIT[1]) + [now()]
            if result == 'ok':
                ts['pending_install'] = None
                ts['failures'] = 0
                ts['last_success'] = now()
            else:
                if result == 'fail_changed':
                    ts['pending_install'] = None
                ts['failures'] += 1
                if result == 'fail_issue':
                    ts['failed_at'] = recent(ts['failed_at'], FAIL_LIMIT[1]) + [now()]
        self.save()
        self.publish(t)
        self.notify(t, result)
        self.save()
        return result

    def run(self):
        # Запрос, пришедший во время попытки, обрабатывается в этом же запуске.
        for _ in range(3):
            manual = self.take_requests()
            self.save()
            for t in self.cfg['targets']:
                self.one(t, t['name'] in manual)
                self.publish(t)
            self.save()
            self.publish_agent()
            if not self.pending():
                break


# ── точка входа ───────────────────────────────────────────────────────────

def take_lock(wait):
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(STATE_DIR, 'lock'), os.O_RDWR | os.O_CREAT, 0o600)
    deadline = time.monotonic() + wait
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            if time.monotonic() >= deadline:
                os.close(fd)
                return None
            time.sleep(1)


def on_signal(signum, frame):
    raise Terminated(signal.Signals(signum).name)


def check_nft(cfg):
    ok = True
    sets = windows_of(cfg)
    for s in sets:
        if set_exists(s):
            log('набор %s: есть, элементов %d' % (' '.join(s), len(set_elements(s))))
        else:
            log('набор %s: НЕТ' % ' '.join(s))
            ok = False
    code, out, _ = run(['nft', 'list', 'ruleset'], timeout=30)
    for s in sets:
        n = len(re.findall(r'@%s\b' % s[2], out)) if code == 0 else 0
        log('правил с @%s: %d' % (s[2], n))
        ok = ok and n > 0
    return ok


def main(argv=None):
    p = argparse.ArgumentParser(description="Временное окно HTTP-01 для Let's Encrypt")
    sub = p.add_subparsers(dest='cmd', required=True)
    sub.add_parser('run')
    r = sub.add_parser('renew')
    r.add_argument('target')
    r.add_argument('--dry-run', action='store_true')
    sub.add_parser('status')
    sub.add_parser('check')
    c = sub.add_parser('close-all')
    c.add_argument('--if-unlocked', action='store_true')
    a = p.parse_args(argv)

    # Аварийное закрытие используют ExecStopPost/OnFailure и удаление службы.
    # Оно должно работать и после удаления/повреждения настроек выпуска.
    cfg = None if a.cmd == 'close-all' else load_config()
    if a.cmd == 'check':
        return 0 if check_nft(cfg) else 1
    if a.cmd == 'status':
        state = load_state()
        for t in cfg['targets']:
            ts = target_state(state, t['name'], t['auto'])
            info = cert_info(t['cert_file'])
            log(json.dumps({'name': t['name'], 'auto': ts['auto'],
                            'not_after': info['not_after'] if info else 0, 'due_at': due_at(info),
                            'next_attempt': next_attempt(ts, info), 'last_result': ts['last_result'],
                            'last_detail': ts['last_detail'], 'failures': ts['failures']}, ensure_ascii=False))
        return 0

    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(s, on_signal)
    sets = ALL_SETS
    fd = take_lock(0 if a.cmd == 'close-all' and a.if_unlocked else LOCK_WAIT)
    if fd is None:
        if a.cmd == 'close-all' and a.if_unlocked:
            log('работает другой запуск: окно закроет он, а не успеет — время жизни элемента')
            return 0
        log('другой запуск не закончился за %d с' % LOCK_WAIT)
        return 75
    try:
        # Остаток прерванного запуска закрывается раньше всего остального.
        close_all(sets)
        if a.cmd == 'close-all':
            log('окна закрыты')
            return 0
        runner = Runner(cfg)
        if a.cmd == 'run':
            runner.run()
            return 0
        t = next((t for t in cfg['targets'] if t['name'] == a.target), None)
        if t is None:
            log('неизвестная цель: ' + a.target)
            return 2
        result = runner.one(t, manual=True, dry_run=a.dry_run)
        runner.publish_agent()
        return 0 if result and (result.startswith('ok') or result == 'dry_run_ok') else 1
    except Terminated as e:
        log('прервано сигналом ' + str(e))
        return 143
    except Fail as e:
        log('отказ: %s %s' % (e.code, e.detail))
        return 1
    finally:
        try:
            close_all(sets)
        except Fail as e:
            log('ВНИМАНИЕ: %s; элементы истекут сами не позже чем через %d с' % (e.detail, WINDOW_SECONDS))
        except Terminated:
            pass
        os.close(fd)


if __name__ == '__main__':
    sys.exit(main())
