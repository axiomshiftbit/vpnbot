#!/usr/bin/env python3
"""Универсальная установка acme-window вместе с VPN-ботом; основной firewall не меняет."""
import argparse
import contextlib
import fcntl
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

CONFIG = Path('/etc/acme-window/config.json')
AGENT = Path('/usr/local/sbin/acme-window')
STATE = Path('/var/lib/acme-window')
UNITS = ('acme-window.service', 'acme-window-close.service', 'acme-window.timer', 'acme-window.path')
TRIGGERS = UNITS[2:]
UNIT_DIR = Path('/etc/systemd/system')
SET = 'acme_http_fwd'
REDIRECT = 'acme_http_redirect'


class Refuse(Exception):
    pass


def require(ok, message):
    if not ok:
        raise Refuse(message)


def run(args, *, data=None, timeout=60, allowed=(0,)):
    # Не выводить stdout/stderr docker/php/certbot: там могут быть закрытые данные.
    try:
        result = subprocess.run(list(map(str, args)), input=data, text=True,
                                capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise Refuse('Не удалось выполнить проверку: ' + str(args[0])) from None
    require(result.returncode in allowed,
            'Команда завершилась ошибкой: %s (код %d)' % (args[0], result.returncode))
    return result


def trusted(path, directory=False):
    """Проверяем владельца и весь путь, не открывая произвольные конфиги бота."""
    path = Path(path)
    require(path.is_absolute(), 'Нужен абсолютный путь')
    for part in (path, *path.parents):
        try:
            st = part.lstat()
        except FileNotFoundError:
            raise Refuse('Не найден обязательный файл/каталог: ' + str(part)) from None
        require(not stat.S_ISLNK(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                'Небезопасные владелец/права или симлинк: ' + str(part))
    require(path.is_dir() if directory else path.is_file(), 'Неверный тип пути: ' + str(path))
    return path


def safe_destination(path):
    path = Path(path)
    ancestor = path
    while not ancestor.exists() and not ancestor.is_symlink():
        ancestor = ancestor.parent
    trusted(ancestor, directory=ancestor.is_dir())


def objects(document, kind):
    result = []
    for item in document.get('nftables', []):
        item = item.get('add', item)
        if kind in item:
            result.append(item[kind])
    return result


def chain_rules(document, table, chain):
    return [r for r in objects(document, 'rule')
            if (r['family'], r['table'], r['chain']) == ('ip', table, chain)]


def expressions(rule):
    return [e for e in rule['expr'] if 'counter' not in e]


def match(left, right, op='=='):
    return {'match': {'op': op, 'left': left, 'right': right}}


def payload(protocol, field):
    return {'payload': {'protocol': protocol, 'field': field}}


def nft_shape(document, profile='auto', allow_open=False):
    """Строгий контракт окна: обычный DNAT или DNAT с дополнительной целью redirect."""
    sets = {(s['family'], s['table'], s['name']): s for s in objects(document, 'set')}
    if profile == 'auto':
        profile = 'redirect' if ('ip', 'dockernat', REDIRECT) in sets else 'dnat'
    expected = [('filter', SET, ['ipv4_addr', 'inet_service'])]
    if profile == 'redirect':
        expected.append(('dockernat', REDIRECT, 'inet_service'))
    for table, name, types in expected:
        s = sets.get(('ip', table, name), {})
        require(s.get('type') == types and 'timeout' in s.get('flags', []) and
                1 <= s.get('size', 0) <= 64, 'Нет безопасного timeout-набора ' + name)
        require(allow_open or not s.get('elem'), 'Окно уже открыто; дождитесь завершения выпуска')
    chains = {(c['family'], c['table'], c['name']): c for c in objects(document, 'chain')}
    forward = chains.get(('ip', 'filter', 'forward'), {})
    require((forward.get('type'), forward.get('hook'), forward.get('prio'), forward.get('policy')) ==
            ('filter', 'forward', 0, 'drop'), 'Неожиданная базовая цепочка ip filter forward')
    rules = chain_rules(document, 'filter', 'forward')
    accepts = [r for r in rules if r.get('comment') == 'acme-window']
    require(len(accepts) == 1, 'Ожидается ровно одно правило accept с комментарием acme-window')
    expr = expressions(accepts[0])
    require(len(expr) == 7, 'Правило acme-window отличается от поддерживаемой структуры')
    try:
        wan, blacklist, public = (expr[n]['match']['right'] for n in (0, 2, 3))
        ipaddress.IPv4Address(public)
    except (KeyError, TypeError, ValueError):
        raise Refuse('Неверные адрес/ограничения правила acme-window') from None
    require(isinstance(wan, str) and re.fullmatch(r'[A-Za-z0-9_.:-]+', wan) and
            isinstance(blacklist, int) and blacklist > 0, 'Неверные WAN/blacklist')
    require(expr == [match({'meta': {'key': 'iifname'}}, wan),
                     match({'ct': {'key': 'status'}}, 'dnat', 'in'),
                     match({'meta': {'key': 'mark'}}, blacklist, '!='),
                     match({'ct': {'key': 'ip daddr', 'dir': 'original'}}, public),
                     match({'ct': {'key': 'proto-dst', 'dir': 'original'}}, 80),
                     match({'concat': [payload('ip', 'daddr'), payload('tcp', 'dport')]}, '@'+SET),
                     {'accept': None}], 'Окно не ограничено правильными WAN/DNAT/IPv4/TCP80/blacklist')
    upstream = redirect = None
    for name, priority in (('prerouting', -100), ('output', -100)):
        chain = chains.get(('ip', 'dockernat', name), {})
        require((chain.get('type'), chain.get('hook'), chain.get('prio')) == ('nat', name, priority),
                'Нет ожидаемой NAT-цепочки ' + name)
        nat = chain_rules(document, 'dockernat', name)
        direct = [(i, expressions(r)) for i, r in enumerate(nat) if expressions(r)[:2] ==
                  [match(payload('ip', 'daddr'), public), match(payload('tcp', 'dport'), 80)]]
        require(len(direct) == 1 and len(direct[0][1]) == 3, 'Неоднозначный DNAT TCP80: ' + name)
        target = direct[0][1][-1].get('dnat', {})
        require(target.get('port') == 80 and isinstance(target.get('addr'), str), 'Неверный HTTP upstream')
        ipaddress.IPv4Address(target['addr'])
        require(upstream is None or upstream == target['addr'], 'prerouting/output ведут на разные nginx')
        upstream = target['addr']
        if profile == 'redirect':
            redirected = [(i, expressions(r)) for i, r in enumerate(nat) if r.get('comment') == 'acme-window-redirect']
            require(len(redirected) == 1 and redirected[0][0] < direct[0][0],
                    'REDIRECT-профиль должен предшествовать обычному DNAT TCP80')
            r = redirected[0][1]
            require(len(r) == 3 and r[:2] == [match(payload('ip', 'daddr'), public),
                    match(payload('tcp', 'dport'), '@'+REDIRECT)] and r[-1].get('dnat', {}).get('port') == 80,
                    'Неверные ограничения REDIRECT-профиль')
            addr = r[-1]['dnat'].get('addr')
            ipaddress.IPv4Address(addr)
            require(redirect is None or redirect == addr, 'REDIRECT-профиль prerouting/output различаются')
            redirect = addr
    return {'public_ip': public, 'upstream': upstream + ':80', 'wan': wan, 'redirect_ip': redirect}


def inspect_firewall(path, profile, allow_open=False):
    trusted(path)
    queries = [('list', 'set', 'ip', 'filter', SET),
               ('list', 'chain', 'ip', 'filter', 'forward'),
               ('list', 'chain', 'ip', 'dockernat', 'prerouting'),
               ('list', 'chain', 'ip', 'dockernat', 'output')]
    if profile == 'auto':
        found = subprocess.run(['nft', '-j', 'list', 'set', 'ip', 'dockernat', REDIRECT],
                               capture_output=True, timeout=15)
        profile = 'redirect' if found.returncode == 0 else 'dnat'
    if profile == 'redirect':
        queries.append(('list', 'set', 'ip', 'dockernat', REDIRECT))
    # Не выгружаем огромные GeoIP-карты: нужны только наборы окна и 3 цепочки.
    live = {'nftables': []}
    for query in queries:
        live['nftables'].extend(json.loads(run(['nft', '-j', *query]).stdout)['nftables'])
    # Постоянный файл загружается целиком ТОЛЬКО в отдельном network namespace.
    code = """import json,subprocess,sys
subprocess.run(['nft','-f',sys.argv[1]],check=True,stdout=subprocess.DEVNULL)
result=[]
for query in json.loads(sys.argv[2]):
    p=subprocess.run(['nft','-j',*query],check=True,capture_output=True,text=True)
    result.extend(json.loads(p.stdout)['nftables'])
print(json.dumps({'nftables':result}))
"""
    disk = json.loads(run(['unshare', '--net', '--', sys.executable, '-c', code,
                           path, json.dumps(queries)], timeout=120).stdout)
    shape = nft_shape(live, profile, allow_open=allow_open)
    require(shape == nft_shape(disk, profile), 'Правила окна в ядре и файле различаются')
    for table, chain in (('filter', 'forward'), ('dockernat', 'prerouting'), ('dockernat', 'output')):
        require([expressions(r) for r in chain_rules(live, table, chain)] ==
                [expressions(r) for r in chain_rules(disk, table, chain)],
                'Цепочка %s/%s в ядре отличается от файла; согласуйте firewall до установки' % (table, chain))
    addresses = json.loads(run(['ip', '-j', '-4', 'addr', 'show', 'dev', shape['wan']]).stdout)
    local = {a['local'] for iface in addresses for a in iface.get('addr_info', [])}
    require(shape['public_ip'] in local, 'PUBLIC_IP правил не назначен WAN-интерфейсу этого сервера')
    print('[OK] Правила окна, timeout-наборы, DNAT и постоянный конфиг согласованы')
    return shape


def container(bot, service):
    names = run(['docker', 'ps', '--filter', 'label=com.docker.compose.service='+service,
                 '--filter', 'label=com.docker.compose.project.working_dir='+str(bot), '--format', '{{.Names}}']).stdout.split()
    require(len(names) == 1, 'Нужен ровно один работающий контейнер '+service+' данного бота')
    return names[0]


def check_bot(bot, shape):
    for name in ('acme_renew.php', 'BotAcme.php'):
        trusted(bot/'app'/name)
    for name in ('acme_window.py', *UNITS):
        trusted(bot/'scripts'/name)
    ng, php = container(bot, 'ng'), container(bot, 'php')
    ips = run(['docker', 'inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}', ng]).stdout.split()
    require(shape['upstream'].split(':')[0] in ips, 'DNAT TCP80 не ведёт в nginx выбранного бота')
    mounts = json.loads(run(['docker', 'inspect', '-f', '{{json .Mounts}}', php]).stdout)
    for destination, source, writable in (('/acme/request', bot/'acme/request', True), ('/acme/state', bot/'acme/state', False)):
        found = [m for m in mounts if m['Destination'] == destination]
        require(len(found) == 1 and found[0]['Source'] == str(source) and found[0]['RW'] == writable,
                'Неверное монтирование '+destination+'; обновите/пересоздайте контейнеры бота')
    result = run(['docker', 'exec', php, 'php', '/app/acme_renew.php', 'check'], allowed=(0, 3))
    if result.returncode == 3:
        print('[INFO] Режим Let’s Encrypt ещё не выбран; после установки включите его в меню бота')
        return []
    names = json.loads(result.stdout).get('domains')
    require(isinstance(names, list) and names and all(isinstance(n, str) and
            re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', n) for n in names), 'Бот вернул неверный список доменов')
    # Не печатаем имена автоматически создаваемых поддоменов.
    print('[OK] Контейнеры и монтирования; доменов для проверки: %d' % len(names))
    return names


def dns_check(public, names):
    for name in names:
        try:
            ipv4 = {a[4][0] for a in socket.getaddrinfo(name, 80, socket.AF_INET, socket.SOCK_STREAM)}
            try:
                ipv6 = {a[4][0] for a in socket.getaddrinfo(name, 80, socket.AF_INET6, socket.SOCK_STREAM)}
            except socket.gaierror as error:
                if error.errno not in (socket.EAI_NONAME, socket.EAI_ADDRFAMILY, socket.EAI_NODATA):
                    raise
                ipv6 = set()
        except OSError:
            raise Refuse('Не удалось проверить DNS всех имён сертификата; проверьте резолвер и записи') from None
        require(ipv4 == {public}, 'Не все A-записи имён сертификата ведут только на этот сервер')
        require(not ipv6, 'Обнаружена AAAA: нынешнее окно только IPv4. Исправьте DNS перед HTTP-01')
    if names:
        print('[OK] A-записи согласованы; AAAA для имён сертификата отсутствуют')


def configuration(bot, shape):
    if CONFIG.exists() or CONFIG.is_symlink():
        trusted(CONFIG)
        cfg = json.loads(CONFIG.read_text())
        require(cfg.get('bot_dir', '/root/vpnbot') == str(bot) and cfg.get('public_ip') == shape['public_ip'],
                'Существующий config.json относится к другому адресу/боту; он оставлен без изменений')
        targets = cfg.get('targets', [])
        require(isinstance(targets, list) and 1 <= len(targets) <= 2 and
                all(isinstance(t, dict) and isinstance(t.get('name'), str) and
                    re.fullmatch(r'[a-z0-9]{1,32}', t['name']) for t in targets) and
                len({t['name'] for t in targets}) == len(targets), 'Неверные имена/число целей')
        own = [t for t in targets if t.get('name') == 'vpnbot']
        require(len(own) == 1 and own[0].get('kind') == 'vpnbot' and own[0].get('upstream') == shape['upstream']
                and not own[0].get('redirect'), 'Существующая цель vpnbot не совпадает с DNAT')
        for t in targets:
            require(all(k not in t or isinstance(t[k], bool) for k in ('auto', 'redirect')),
                    'Поля auto/redirect должны быть JSON true или false')
            if 'verify_port' in t:
                require(type(t['verify_port']) is int and 1 <= t['verify_port'] <= 65535, 'Неверный verify_port')
            if t is own[0]:
                continue
            require(t.get('kind') == 'nginx-ssl' and t.get('redirect') is True and shape['redirect_ip']
                    and t.get('upstream') == shape['redirect_ip']+':80',
                    'Дополнительная цель не совпадает с REDIRECT-профиль; config.json сохранён')
        return cfg
    return {'public_ip': shape['public_ip'], 'bot_dir': str(bot), 'targets':
            [{'name': 'vpnbot', 'kind': 'vpnbot', 'upstream': shape['upstream'],
              'label': {'ru': 'vpnbot', 'en': 'vpnbot'}}]}


@contextlib.contextmanager
def lock(path, wait=0):
    if path.parent == Path('/run/lock'):
        # Debian использует root:root 1777 для /run/lock. Sticky-bit не
        # позволяет удалить чужой root-owned lock; сам файл проверяем по fd.
        trusted(path.parent.parent, directory=True)
        st = path.parent.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and
                (not st.st_mode & 0o022 or st.st_mode & stat.S_ISVTX), 'Небезопасный /run/lock')
    else:
        safe_destination(path)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022
                and st.st_nlink == 1, 'Небезопасный lock-файл: '+str(path))
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise Refuse('Идёт другая установка/применение nftables/выпуск; повторите позже') from None
                time.sleep(0.2)
        yield
    finally:
        os.close(fd)


def agent_module(bot):
    spec = importlib.util.spec_from_file_location('acme_setup_agent', bot/'scripts/acme_window.py')
    module = importlib.util.module_from_spec(spec)
    # Не оставляем __pycache__ в каталоге установленного бота.
    sys.dont_write_bytecode = True
    spec.loader.exec_module(module)
    module.CONFIG_PATH = str(CONFIG)
    module.STATE_DIR = str(STATE)
    require(all(hasattr(module, n) for n in ('load_config', 'Runner', 'attempt', 'close_all', 'ALL_SETS')),
            'Обновите код ACME в VPN-боте')
    return module


def write(path, content, mode):
    path = Path(path)
    safe_destination(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='.acme-setup-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def unit_state(unit, property):
    return run(['systemctl', 'show', '-p', property, '--value', unit]).stdout.strip()


def installed_current(bot):
    if not CONFIG.exists() or not AGENT.exists():
        return False
    trusted(AGENT)
    if AGENT.read_bytes() != (bot/'scripts/acme_window.py').read_bytes():
        return False
    for unit in UNITS:
        path = UNIT_DIR/unit
        if not path.exists():
            return False
        trusted(path)
        if path.read_text() != (bot/'scripts'/unit).read_text().replace('__VPNBOT_PATH__', str(bot)):
            return False
        if unit_state(unit, 'DropInPaths') or unit_state(unit, 'LoadState') == 'masked':
            return False
    return all(unit_state(u, 'ActiveState') == 'active' and unit_state(u, 'UnitFileState') == 'enabled' for u in TRIGGERS)


def closed(module):
    module.close_all(module.ALL_SETS)
    require(not any(module.set_elements(s) for s in module.ALL_SETS if module.set_exists(s)),
            'Закрытие окна не подтверждено')


def dry_run(module, cfg, names):
    require(names, 'Сначала выберите домен и Let’s Encrypt в настройках бота')
    target = next(t for t in cfg['targets'] if t['name'] == 'vpnbot')
    print('[INFO] Настоящий пробный HTTP-01; действующий сертификат не заменяется', flush=True)
    try:
        # Без Runner.one: тест не отправляет Telegram-уведомления даже при ошибке.
        result, _ = module.attempt(cfg, target, dry_run=True)
        require(result == 'dry_run_ok', 'Пробный выпуск не подтверждён')
    except module.Fail as error:
        raise Refuse('Пробный выпуск не прошёл: '+error.code+'; проверьте DNS, доступность TCP80 и webroot') from None
    finally:
        closed(module)
    print('[OK] Пробный выпуск прошёл; окно закрыто')


def install(bot, cfg, module, names, test):
    require(unit_state(UNITS[0], 'ActiveState') not in ('active', 'activating', 'deactivating'),
            'Уже идёт выпуск сертификата; повторите после его завершения')
    for unit in UNITS:
        require(not unit_state(unit, 'DropInPaths') and unit_state(unit, 'LoadState') != 'masked',
                'Обнаружен override/маскирование '+unit+'; сначала проверьте его вручную')
    destinations = [CONFIG, AGENT, *(UNIT_DIR/u for u in UNITS), STATE/'state.json',
                    bot/'acme/state/agent.json', *(bot/'acme/state'/(t['name']+'.json') for t in cfg['targets'])]
    for path in destinations:
        safe_destination(path)
    for directory in (bot/'acme', bot/'acme/request', bot/'acme/state', STATE):
        safe_destination(directory)
        directory.mkdir(parents=True, mode=0o700 if directory.name in ('request', 'acme-window') else 0o755, exist_ok=True)
    enabled = {u: unit_state(u, 'UnitFileState') for u in TRIGGERS}
    active = {u: unit_state(u, 'ActiveState') == 'active' for u in TRIGGERS}
    require(all(v in ('', 'not-found', 'disabled', 'enabled') for v in enabled.values()),
            'Нестандартное состояние установки timer/path; сначала проверьте его вручную')
    root = Path('/var/backups/acme-window-setup')
    safe_destination(root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = Path(tempfile.mkdtemp(prefix='install-', dir=root))
    present = {}
    for i, path in enumerate(destinations):
        present[path] = path.exists()
        if path.exists():
            shutil.copy2(path, backup/str(i))
    write(backup/'manifest.json', (json.dumps({
        'files': [{'index': i, 'path': str(path), 'existed': present[path]}
                  for i, path in enumerate(destinations)],
        'enabled': enabled, 'active': active}, indent=2)+'\n').encode(), 0o600)
    # Снимки только файлов службы и её несекретной конфигурации, не ключей/конфигов VPN-бота.
    print('[INFO] Резервная копия установки: '+str(backup))
    try:
        run(['systemctl', 'stop', *TRIGGERS], allowed=(0, 5))
        closed(module)
        if not CONFIG.exists():
            write(CONFIG, (json.dumps(cfg, indent=2, ensure_ascii=False)+'\n').encode(), 0o600)
        write(AGENT, (bot/'scripts/acme_window.py').read_bytes(), 0o755)
        with tempfile.TemporaryDirectory(prefix='acme-units-') as temp:
            for unit in UNITS:
                rendered = (bot/'scripts'/unit).read_text().replace('__VPNBOT_PATH__', str(bot))
                require('__VPNBOT_PATH__' not in rendered, 'Не заменён путь в systemd unit')
                Path(temp, unit).write_text(rendered)
            run(['systemd-analyze', 'verify', *(Path(temp, u) for u in UNITS)])
            for unit in UNITS:
                write(UNIT_DIR/unit, Path(temp, unit).read_bytes(), 0o644)
        try:
            installed_cfg = module.load_config()
        except SystemExit:
            raise Refuse('Конфигурация не поддерживается текущей версией агента') from None
        if test:
            dry_run(module, installed_cfg, names)
        runner = module.Runner(installed_cfg)
        for target in installed_cfg['targets']:
            runner.publish(target)
        runner.save()
        runner.publish_agent()
        closed(module)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', *TRIGGERS])
        for unit in TRIGGERS:
            require(unit_state(unit, 'ActiveState') == 'active' and unit_state(unit, 'UnitFileState') == 'enabled',
                    'Триггер не включён: '+unit)
    except BaseException:
        try:
            # Даже при ошибке systemd всё равно пытаемся закрыть окно.
            try:
                run(['systemctl', 'stop', *TRIGGERS], allowed=(0, 5))
            finally:
                try:
                    run(['systemctl', 'stop', UNITS[0]], allowed=(0, 5))
                finally:
                    closed(module)
            for i, path in enumerate(destinations):
                if present[path]:
                    write(path, (backup/str(i)).read_bytes(), stat.S_IMODE((backup/str(i)).stat().st_mode))
                else:
                    path.unlink(missing_ok=True)
            run(['systemctl', 'daemon-reload'])
            for unit in TRIGGERS:
                if enabled[unit] == 'enabled':
                    run(['systemctl', 'enable', unit])
                else:
                    run(['systemctl', 'disable', unit], allowed=(0, 1, 5))
                if active[unit]:
                    run(['systemctl', 'start', unit])
        except BaseException:
            print('[ОШИБКА] Автоматический откат не завершён. Проверьте закрытие окна и службы; '
                  'резервная копия и manifest.json: '+str(backup), file=sys.stderr)
            raise
        print('[INFO] Прежняя установка восстановлена; окно закрыто', file=sys.stderr)
        raise
    print('[OK] Установлены агент, timer и path; состояние опубликовано для меню бота')


def interrupted(signum, frame):
    raise Refuse('Установка прервана сигналом')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'ensure', 'check', 'test'))
    parser.add_argument('--profile', default='auto', choices=('auto', 'dnat', 'redirect'))
    parser.add_argument('--bot-dir', type=Path, default=Path('/root/vpnbot'))
    parser.add_argument('--nft-config', type=Path, default=Path('/etc/nftables.conf'))
    parser.add_argument('--dry-run', action='store_true', help='проверить HTTP-01 в staging до включения службы')
    parser.add_argument('--wait-lock', type=int, default=0, help='ожидать занятые блокировки, секунд (0–120)')
    args = parser.parse_args()
    require(not args.dry_run or args.action == 'install', '--dry-run используется только с install; для отдельной проверки есть test')
    require(os.geteuid() == 0, 'Запустите от root')
    require(0 <= args.wait_lock <= 120, 'Ожидание блокировки должно быть 0–120 секунд')
    require(args.bot_dir.is_absolute() and re.fullmatch(r'/[A-Za-z0-9_./-]+', str(args.bot_dir)) and
            '..' not in args.bot_dir.parts, 'Путь бота должен быть абсолютным, без пробелов/спецсимволов/..')
    bot = trusted(args.bot_dir, directory=True)
    for name in ('nft', 'ip', 'docker', 'unshare', 'openssl', 'systemctl', 'systemd-analyze'):
        require(shutil.which(name), 'Не установлена обязательная команда: '+name)
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(sig, interrupted)
    # Один lock агента удерживается от preflight до окончания транзакции:
    # таймер/ручной выпуск не могут открыть окно между проверкой и записью.
    safe_destination(STATE)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with lock(Path('/run/lock/acme-window-setup.lock'), args.wait_lock), lock(Path('/run/lock/nft-docker-watch.lock'), args.wait_lock):
        shape = inspect_firewall(args.nft_config, args.profile, allow_open=args.action == 'ensure')
        names = check_bot(bot, shape)
        dns_check(shape['public_ip'], names)
        cfg = configuration(bot, shape)
        if args.action == 'check':
            print('[OK] Предварительная проверка завершена; конфигурация и правила не изменены')
            return
        if args.action == 'ensure' and installed_current(bot):
            print('[OK] ACME уже актуален; настройки и выполняющийся выпуск сохранены')
            return
        module = agent_module(bot)
        with lock(STATE/'lock', args.wait_lock):
            if args.action in ('install', 'ensure'):
                install(bot, cfg, module, names, args.dry_run)
            else:
                require(CONFIG.exists() and AGENT.exists(), 'Сначала выполните install')
                trusted(AGENT)
                require(AGENT.read_bytes() == (bot/'scripts/acme_window.py').read_bytes(),
                        'Установлен другой агент; повторите install после обновления бота')
                dry_run(module, module.load_config(), names)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Не печатаем исключения парсеров и содержимое входных файлов.
        print('[ОТКАЗ] '+(str(error) if isinstance(error, Refuse) else 'Ошибка структуры/доступа к файлам; установка не подтверждена'), file=sys.stderr)
        sys.exit(1)
