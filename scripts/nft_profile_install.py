#!/usr/bin/env python3
"""Профиль nftables из каталога nftables/ при первой установке.

Полный бот: если /etc/nftables.conf нет или это не профиль VPNBot, установщик
спрашивает внешний интерфейс (WAN), публичные IPv4/IPv6, порт SSH и адреса,
с которых разрешён SSH (они записываются в список my_server), проверяет
профиль в отдельном network namespace, сохраняет прежние правила и применяет
новые. Затем просит открыть НОВОЕ SSH-подключение и подтвердить доступ: без
подтверждения за 120 с отдельный сторожевой процесс возвращает прежние
правила, даже если оборвётся сам установщик. Только после подтверждения
Docker переводится на правила профиля (iptables/ip6tables/userland-proxy=false).

Нода: ставится шаблон noda.conf и списки; адреса, порты SSH и применение с
откатом выполняет установщик ноды (scripts/node_setup.py).

Без терминала значения берутся из окружения: VPNBOT_NFT_WAN, VPNBOT_NFT_PUBLIC4,
VPNBOT_NFT_PUBLIC6, VPNBOT_NFT_SSH_PORT, VPNBOT_NFT_ADMINS. Применение полного
профиля требует подтверждения в терминале; без него профиль не меняется.
Чужой /etc/nftables.conf без терминала заменяется только при VPNBOT_NFT_REPLACE=yes.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nft_host_setup as nft  # noqa: E402
import nft_node_sets as sets  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / 'nftables'
CONFIG = Path('/etc/nftables.conf')
LISTS = Path('/opt/maxmind/list')
BACKUPS = Path('/var/backups/vpnbot-nftables')
DAEMON = Path('/etc/docker/daemon.json')
DOCKER_SETTINGS = {'iptables': False, 'ip6tables': False, 'userland-proxy': False}
CONFIRM_SECONDS = 120
NODE_MARKER = '# VPNBOT_MANAGED_NODE_HOST'
# Проверяемый профиль загружается отсюда; /etc/nftables.conf меняется только после
# подтверждения, поэтому перезагрузка в окне проверки поднимает прежние правила.
CANDIDATE = Path('/etc/nftables.conf.vpnbot-candidate')
# Контейнеры ноды (scripts/node_runtime.py): только они не мешают установке ноды.
NODE_CONTAINERS = ('vpnbot-node-xray', 'vpnbot-node-cover', 'vpnbot-node-amnezia', 'vpnbot-node-warp', 'vpnbot-node-adguard')
NODE_LABEL = 'org.vpnbot.managed-node'


def run(args, data=None, check=True, timeout=120):
    result = subprocess.run(list(map(str, args)), input=data, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        # Вывод nft/docker может содержать адреса и конфигурацию: не печатаем.
        raise ValueError('Команда не выполнена: ' + str(args[0]))
    return result


def profile_state(path, mode):
    """'ok' — профиль VPNBot нужного режима; 'missing' — файла нет; 'foreign' — чужой файл."""
    if not path.exists():
        return 'missing'
    lines = path.read_text(errors='replace').splitlines()
    if not any(line.startswith('# VPNBot:') for line in lines[:5]):
        return 'foreign'
    if (NODE_MARKER in lines) != (mode == 'node'):
        raise ValueError('В /etc/nftables.conf профиль другого режима установки (бот/нода)')
    return 'ok'


def sshd_ports():
    result = run(['sshd', '-T'], check=False)
    return sorted({int(m) for m in re.findall(r'(?m)^port (\d+)$', result.stdout)}) or [22]


def client_address():
    for name in ('SSH_CONNECTION', 'SSH_CLIENT'):
        value = os.environ.get(name, '').split()
        if value:
            try:
                return str(ipaddress.ip_address(value[0]))
            except ValueError:
                pass
    return ''


def assigned(interface, family):
    result = run(['ip', '-j', 'address', 'show', 'dev', interface], check=False)
    if result.returncode:
        return []
    return [x['local'] for item in json.loads(result.stdout or '[]') for x in item.get('addr_info', [])
            if x.get('scope') == 'global' and x.get('family') == ('inet' if family == 4 else 'inet6')]


def ask(prompt, default, check, env, interactive):
    """Вопрос с значением по умолчанию; без терминала — переменная окружения."""
    if not interactive:
        value = os.environ.get(env, default)
        return check(value)
    while True:
        answer = input(f'{prompt} [{default}]: ' if default else f'{prompt}: ').strip() or default
        try:
            return check(answer)
        except ValueError as error:
            print('  ' + str(error))


def collect(interactive):
    try:
        found = nft.discover()
    except ValueError:
        found = dict(interface='', public4='', public6='', routers=[])

    def interface(value):
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', value) or run(['ip', 'link', 'show', 'dev', value], check=False).returncode:
            raise ValueError('Нет такого сетевого интерфейса')
        return value

    wan = ask('Внешний интерфейс (WAN)', found['interface'], interface, 'VPNBOT_NFT_WAN', interactive)

    def public4(value):
        ip = ipaddress.ip_address(value)
        if ip.version != 4 or not ip.is_global:
            raise ValueError('Нужен публичный IPv4')
        if str(ip) not in assigned(wan, 4):
            raise ValueError('Адрес не назначен интерфейсу ' + wan)
        return str(ip)

    def public6(value):
        if not value or value == '-':
            return ''
        ip = ipaddress.ip_address(value)
        if ip.version != 6 or not ip.is_global or str(ip) not in assigned(wan, 6):
            raise ValueError('Нужен публичный IPv6, назначенный интерфейсу ' + wan + ', или «-»')
        return str(ip)

    ip4 = ask('Публичный IPv4 сервера', found['public4'] if found['interface'] == wan else '', public4, 'VPNBOT_NFT_PUBLIC4', interactive)
    ip6 = ask('Публичный IPv6 сервера («-» — без IPv6)', (found['public6'] if found['interface'] == wan else '') or '-',
              public6, 'VPNBOT_NFT_PUBLIC6', interactive)
    ports = sshd_ports()

    def port(value):
        if not value.isdigit() or int(value) not in ports:
            raise ValueError('Укажите порт, на котором сейчас работает sshd: ' + ', '.join(map(str, ports)))
        return int(value)

    ssh = ask('Порт SSH', str(ports[0]), port, 'VPNBOT_NFT_SSH_PORT', interactive)

    def admins(value):
        result = []
        for item in value.replace(',', ' ').split():
            net = ipaddress.ip_network(item, strict=False)
            if net.version != 4 or net.prefixlen < 16:
                raise ValueError('Нужны адреса IPv4 или сети не шире /16')
            result.append(str(net))
        if not result:
            raise ValueError('Без адресов SSH-доступ к серверу будет закрыт')
        return sorted(set(result))

    hint = client_address()
    allowed = ask('Адреса, с которых разрешён SSH (через пробел)', hint if ':' not in hint else '', admins,
                  'VPNBOT_NFT_ADMINS', interactive)
    return dict(interface=wan, public4=ip4, public6=ip6, routers=found.get('routers', []) if found['interface'] == wan else [],
                sources6=[], ssh_port=ssh, admins=allowed)


def my_server(networks, mark='MY_SERVER'):
    elements = ',\n'.join(f'        {net} : ${mark}' for net in networks)
    return (f'# Адреса, с которых разрешены SSH и служебные подключения. Записаны установщиком.\n'
            f'map my_server {{\n    type ipv4_addr : mark\n    flags interval\n    elements = {{\n{elements}\n    }}\n}}\n')


def install_lists(admins=None):
    """Списки из nftables/list; существующие списки администратора не заменяются.

    Возвращает каталоги, созданные этим вызовом: откат установки удаляет их."""
    created = []
    for source in sorted((TEMPLATES / 'list').iterdir()):
        target = LISTS / source.name
        if target.exists():
            if source.name == 'my_server' and admins:
                # Действует сохранённый список, а не ответы этой попытки: показываем его.
                current = re.findall(r'(?m)^\s*([0-9][0-9./]*)\s*:', (target / 'geoip-ipv4.nft').read_text(errors='replace')) \
                    if (target / 'geoip-ipv4.nft').exists() else []
                print('[INFO] Список my_server уже есть и не изменяется. Действующие адреса SSH: '
                      + (', '.join(current) if current else 'нет') + '. Изменить: ' + str(target / 'geoip-ipv4.nft'))
            continue
        target.mkdir(parents=True, mode=0o755)
        created.append(target)
        for item in source.iterdir():
            shutil.copyfile(item, target / item.name)
            os.chmod(target / item.name, 0o644)
        if source.name == 'my_server' and admins:
            sets.atomic(target / 'geoip-ipv4.nft', my_server(admins), 0o644)
    return created


def drop_lists(created):
    """Откат: списки этой попытки, иначе следующая попытка унаследовала бы её адреса."""
    for target in created:
        shutil.rmtree(target, ignore_errors=True)


def render_full(values):
    text = nft.render((TEMPLATES / 'nftables.conf').read_text(), values, 'full')
    text, n = re.subn(r'(?m)^(define SSH_PORT\s*=\s*)\d+', lambda m: m[1] + str(values['ssh_port']), text)
    if n != 1:
        raise ValueError('В шаблоне нет определения SSH_PORT')
    busy = ssh_dnat_conflicts(text, values['ssh_port'])
    if busy:
        # Входящий IPv4 на этот порт уйдёт в контейнер до цепочки input: SSH станет недоступен.
        raise ValueError('Порт SSH ' + str(values['ssh_port']) + ' уже занят входом VPN (DNAT TCP): ' + ', '.join(busy)
                         + '. Перенесите sshd на другой порт или измените этот вход в nftables/nftables.conf')
    return text


def ssh_dnat_conflicts(text, port):
    """Имена входов, которые DNAT-ят TCP-порт SSH на публичном IPv4 (правила без комментария)."""
    defines = {m[1]: m[2] for m in re.finditer(r'(?m)^define\s+([A-Z0-9_]+)\s*=\s*([^#\n]+?)\s*(?:#.*)?$', text)}

    def ports(value, depth=0):
        result = set()
        for item in re.split(r'[\s,{}]+', value.strip()):
            if not item:
                continue
            if item.startswith('$') and depth < 4:
                result |= ports(defines.get(item[1:], ''), depth + 1)
            elif re.fullmatch(r'\d+-\d+', item):
                low, high = map(int, item.split('-'))
                result |= set(range(low, high + 1)) if high - low < 65536 else set()
            elif item.isdigit():
                result.add(int(item))
        return result

    names = []
    for line in text.splitlines():
        rule = line.split('#', 1)[0]
        match = re.search(r'\btcp dport (\$[A-Z0-9_]+|\d+|\{[^}]*\})', rule)
        if 'dnat to' in rule and 'ip daddr $PUBLIC_IP' in rule and match and port in ports(match[1]):
            names.append(match[1].lstrip('$'))
    return sorted(set(names))


def restore(directory):
    """Вернуть правила и файл, сохранённые до применения."""
    try:
        CANDIDATE.unlink(missing_ok=True)
        dump = directory / 'ruleset.nft'
        # Flush и загрузка выполняются одной транзакцией ядра. При отказе
        # действующий фильтр остаётся на месте; отдельный flush недопустим.
        if run(['nft', '-f', '-'], 'flush ruleset\n' + dump.read_text(), check=False).returncode:
            raise ValueError('Не удалось загрузить прежние правила nftables')
        previous = directory / 'nftables.conf'
        if previous.exists():
            sets.atomic(CONFIG, previous.read_text(), 0o600)
        else:
            CONFIG.unlink(missing_ok=True)
        (directory / 'rolled-back').write_text('1\n')
        (directory / 'rollback-failed').unlink(missing_ok=True)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        try:
            (directory / 'rollback-failed').write_text('1\n')
        except OSError:
            pass
        raise ValueError('Откат nftables не завершён; фильтр не сбрасывался. '
                         'Требуется проверка сохранённых правил и файла конфигурации.') from error


def watchdog(directory, seconds):
    """Отдельный процесс: без подтверждения через seconds возвращает прежние правила."""
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    time.sleep(seconds)
    if not (directory / 'confirmed').exists() and not (directory / 'rolled-back').exists():
        restore(directory)


def confirmed(seconds, stream=sys.stdin):
    print(f'\nПравила применены. Откройте НОВОЕ SSH-подключение к серверу (не закрывая это) и, если вход\n'
          f'прошёл, введите здесь yes в течение {seconds} с. Иначе прежние правила вернутся автоматически.')
    deadline = time.monotonic() + seconds
    while (left := deadline - time.monotonic()) > 0:
        print('Подтверждение: ', end='', flush=True)
        ready, _, _ = select.select([stream], [], [], left)
        if not ready:
            break
        if stream.readline().strip().lower() in ('yes', 'да'):
            return True
    return False


def docker_rules(settings=DOCKER_SETTINGS):
    """Docker не создаёт свои цепочки: сеть контейнеров обслуживает профиль."""
    value = json.loads(DAEMON.read_text()) if DAEMON.exists() else {}
    if not isinstance(value, dict):
        raise ValueError('/etc/docker/daemon.json не JSON-объект')
    if all(value.get(k) is v for k, v in settings.items()):
        return False
    # daemon.json может хранить, например, реквизиты прокси: права не расширяются,
    # новый файл и копия доступны только root.
    mode = 0o600
    if DAEMON.exists():
        mode = DAEMON.stat().st_mode & 0o600
        backup = DAEMON.with_name(DAEMON.name + '.before-vpnbot')
        if not backup.exists():
            sets.atomic(backup, DAEMON.read_text(), 0o600)
    DAEMON.parent.mkdir(mode=0o755, exist_ok=True)
    sets.atomic(DAEMON, json.dumps(value | settings, indent=2, sort_keys=True) + '\n', mode)
    run(['systemctl', 'restart', 'docker.service'], timeout=180)
    return True


def foreign_containers():
    """Работающие контейнеры не этой ноды: их сеть не должна меняться установщиком ноды."""
    if not shutil.which('docker'):
        return False
    listed = run(['docker', 'ps', '--format', '{{.Names}}'], check=False)
    if listed.returncode:
        # Без ответа демона неизвестно, что запущено: ничего не меняем.
        raise ValueError('Docker не ответил; установка ноды не меняет Docker и nftables без проверки контейнеров')
    for name in listed.stdout.split():
        if name not in NODE_CONTAINERS:
            return True
        label = run(['docker', 'inspect', '--format', '{{index .Config.Labels "' + NODE_LABEL + '"}}', name], check=False)
        if label.returncode or label.stdout.strip() != '1':
            return True
    return False


def install_full(interactive):
    if not interactive:
        print('[INFO] nftables: нет терминала для подтверждения SSH-доступа — профиль не установлен. '
              'Запустите scripts/nft_profile_install.py --mode full из SSH-сессии.')
        return False
    values = collect(True)
    created = install_lists(values['admins'])
    try:
        text = render_full(values)
        nft.compile_rules(text)  # проверка в отдельном network namespace
    except BaseException:
        drop_lists(created)
        raise
    directory = BACKUPS / time.strftime('%Y%m%d-%H%M%S')
    directory.mkdir(parents=True, mode=0o700)
    (directory / 'ruleset.nft').write_text(run(['nft', 'list', 'ruleset']).stdout)
    if CONFIG.exists():
        shutil.copyfile(CONFIG, directory / 'nftables.conf')
    guard = subprocess.Popen([sys.executable, '-I', __file__, '--watchdog', str(directory), '--after', str(CONFIRM_SECONDS)],
                             start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    ok = False
    try:
        sets.atomic(CANDIDATE, text, 0o600)
        run(['nft', '-f', str(CANDIDATE)])
        ok = confirmed(CONFIRM_SECONDS - 5)
        if ok:
            # Загрузочный файл меняется только после подтверждённого входа.
            sets.atomic(CONFIG, text, 0o600)
            CANDIDATE.unlink(missing_ok=True)
    except BaseException:
        ok = False
        raise
    finally:
        if ok:
            (directory / 'confirmed').write_text('1\n')
            guard.terminate()
        else:
            if not (directory / 'rolled-back').exists():
                restore(directory)
                guard.terminate()
            drop_lists(created)
    if not ok:
        print('[INFO] Подтверждения нет: прежние правила восстановлены, профиль не установлен.')
        return False
    run(['systemctl', 'enable', 'nftables.service'], check=False)
    docker_rules()
    print('[OK] Профиль nftables установлен; прежние правила сохранены в ' + str(directory))
    return True


def install_node():
    """Шаблон для установщика ноды: адреса и применение — в node_setup.py.

    Docker здесь не перезапускается: его настраивает node_setup.py после своей
    проверки хоста. До записи файлов отказ оставляет сервер нетронутым."""
    if foreign_containers():
        print('[ОТКАЗ] nftables: на сервере работают другие контейнеры. Установка ноды не меняет их сеть, '
              '/etc/nftables.conf и Docker; сначала подготовьте перенос существующей установки.', file=sys.stderr)
        return False
    install_lists()
    if CONFIG.exists():
        backup = CONFIG.with_name(CONFIG.name + '.before-vpnbot')
        if not backup.exists():
            shutil.copyfile(CONFIG, backup)
    sets.atomic(CONFIG, (TEMPLATES / 'noda.conf').read_text(), 0o600)
    print('[OK] Шаблон nftables ноды записан в /etc/nftables.conf; адреса задаст установщик ноды')
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('full', 'node'))
    parser.add_argument('--watchdog', type=Path)
    parser.add_argument('--after', type=int, default=CONFIRM_SECONDS)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('Требуется root')
    if args.watchdog:
        return watchdog(args.watchdog, args.after)
    if not args.mode:
        parser.error('--mode full|node')
    state = profile_state(CONFIG, args.mode)
    if state == 'ok':
        print('[OK] /etc/nftables.conf уже содержит профиль VPNBot — адреса согласует установщик')
        return True
    interactive = sys.stdin.isatty()
    if not interactive and state == 'foreign' and os.environ.get('VPNBOT_NFT_REPLACE', '').strip().lower() not in ('yes', 'да'):
        # Без терминала чужой профиль не заменяется молча: нужен явный выбор.
        print('[INFO] nftables: /etc/nftables.conf не профиль VPNBot и оставлен без изменений. '
              'Чтобы заменить его профилем из nftables/ (прежний сохранится), задайте VPNBOT_NFT_REPLACE=yes.')
        return False
    if interactive and state == 'foreign':
        answer = input('/etc/nftables.conf не профиль VPNBot. Заменить профилем из nftables/ (прежний сохранится)? [y/N]: ')
        if answer.strip().lower() not in ('y', 'yes', 'д', 'да'):
            if args.mode == 'node':
                print('[INFO] nftables: профиль ноды не установлен по выбору администратора')
                return False
            # Свой профиль администратора — тоже защита хоста; Docker не трогаем.
            print('[INFO] nftables: оставлен собственный /etc/nftables.conf; /etc/docker/daemon.json не менялся')
            try:
                value = json.loads(DAEMON.read_text()) if DAEMON.exists() else {}
            except ValueError:
                value = None
            if not isinstance(value, dict) or any(value.get(k) is not v for k, v in DOCKER_SETTINGS.items()):
                print('[INFO] Docker сам управляет iptables и NAT. Если ваш профиль рассчитан на Docker без своих правил, '
                      'задайте в daemon.json iptables, ip6tables и userland-proxy = false и перезапустите Docker.')
            return True
    return install_node() if args.mode == 'node' else install_full(interactive)


if __name__ == '__main__':
    try:
        sys.exit(0 if main() is not False else 2)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('[ОТКАЗ] nftables: ' + (str(error) if isinstance(error, ValueError) else 'операция не выполнена'), file=sys.stderr)
        sys.exit(1)
