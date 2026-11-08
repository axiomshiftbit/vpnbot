#!/usr/bin/env python3
"""Public enrollment document and installation of the minimal node host."""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import pwd
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import image_bundle
import node_config as config
import node_install as install
import node_state as state
import nft_host_setup
import node_host
from node_runtime import Runtime, command, CONTAINER, COVER_CONTAINER, AWG_CONTAINER, LABEL

ROOT = Path('/var/lib/vpnbot-node')


def verify_firewall(backend, path=Path('/etc/nftables.conf')):
    """Read back service, persistent configuration and live rules; never reload."""
    fd = os.open('/run/lock/nft-docker-watch.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        expected = []
        if path.exists():
            reply = command(['systemctl', 'show', 'nftables.service', '--property=LoadState,ActiveState,SubState,Result,UnitFileState'])
            status = dict(line.split('=', 1) for line in reply.stdout.decode().splitlines() if '=' in line)
            if status.get('LoadState') != 'loaded' or status.get('ActiveState') != 'active' \
                    or status.get('SubState') not in ('exited', 'running') or status.get('Result') != 'success' \
                    or status.get('UnitFileState') != 'enabled':
                raise ValueError('nftables service is not active and enabled')
            text = node_host.read_profile(path)
            expected.append(nft_host_setup.profile_rules(nft_host_setup.compile_rules(text), text))
        # Without a base profile the node's systemd service owns persistence.
        # Its guard must still match the disk file and the actual kernel rules.
        state.trusted(backend.guard)
        expected.append(nft_host_setup.compile_rules(backend.guard.read_text()))
        live = json.loads(command(['nft', '-j', 'list', 'ruleset']).stdout)
        for document in expected:
            tables = {(x['family'], x['name']) for x in nft_host_setup.objects(document, 'table')}
            for kind in ('table', 'chain', 'rule', 'set', 'map'):
                wanted = nft_host_setup.objects(document, kind)
                actual = [x for x in nft_host_setup.objects(live, kind)
                          if (x['family'], x['name'] if kind == 'table' else x['table']) in tables]
                # Dynamic meters contain live counters/expiring source entries.
                # Their definitions and the rules using them must still match.
                def stable(items):
                    values = [nft_host_setup.clean({k: v for k, v in x.items()
                            if not (k == 'elem' and 'dynamic' in x.get('flags', []))}) for x in items]
                    # Object/chain enumeration may change after an atomic delta;
                    # rule ordering within each chain remains significant.
                    return sorted(values, key=lambda x: (x['family'], x.get('table', ''), x.get('chain', x.get('name', ''))))
                if stable(wanted) != stable(actual):
                    raise ValueError('nftables live rules differ from persistent configuration')
    finally:
        os.close(fd)


def replace_controller(public_key):
    """Local root handover: replace SSH authorization, retain all node state."""
    key = install.public_key(public_key)
    store = state.Store(ROOT)
    descriptor = os.open(ROOT/'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        job = store.read('job.json') or {}
        if not store.current() or store.pending() or job.get('state') in ('queued', 'running'):
            raise ValueError('Нода не установлена или изменение ещё не завершено')
        host = config.deployment(state.decode((install.ETC/'deployment.json').read_bytes(), state.MAX_DEPLOYMENT_BYTES))
        install.install_ssh(key, host['sources'])
    finally:
        os.close(descriptor)


def upgrade_code(source):
    """Refresh node code and units in place, then rebuild the node guard with that code.

    State, keys and settings stay as they are. The node lock excludes a running
    job or renewal, so no ACME window can be open while the guard is replaced."""
    store = state.Store(ROOT)
    descriptor = os.open(ROOT/'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        job = store.read('job.json') or {}
        if not store.current() or store.pending() or job.get('state') in ('queued', 'running'):
            raise ValueError('Нода не установлена или изменение ещё не завершено')
        install.install_code(source)
        host = config.deployment(state.decode((install.ETC/'deployment.json').read_bytes(), state.MAX_DEPLOYMENT_BYTES))
        Runtime(store, host).load_firewall()
        nft_host_setup.configure(host=host, mode='node')
        verify_firewall(Runtime(store, host))
    finally:
        os.close(descriptor)


def enrollment(value):
    if not isinstance(value, dict) or set(value) != {'schema', 'controller_key', 'deployment', 'options'} \
            or type(value['schema']) is not int or value['schema'] != 1:
        raise ValueError('Некорректный файл подключения ноды')
    host = value['deployment']
    if not isinstance(host, dict) or set(host) - {'ssh_networks'} != {
            'public4', 'public6', 'sources', 'admins', 'routers', 'ssh_ports', 'interface'}:
        raise ValueError('Некорректные параметры сети')
    # Account IDs are assigned locally, never supplied by a remote controller.
    host = config.deployment(host | {'uid': 59999, 'gid': 59999, 'cover_uid': 59998})
    for field in ('uid', 'gid', 'cover_uid'):
        del host[field]
    options = config.settings(value['options'])
    for family in (options['family'], options.get('connect_family', 4)):
        if not host['public'+str(family)]:
            raise ValueError('Для выбранного семейства отсутствует публичный адрес')
    return dict(schema=1, controller_key=install.public_key(value['controller_key']), deployment=host, options=options)


def preflight(value):
    host = value['deployment']
    active = command(['docker', 'ps', '--format', '{{json .}}']).stdout.decode().splitlines()
    for line in active:
        name = json.loads(line)['Names']
        if name not in (CONTAINER, COVER_CONTAINER, AWG_CONTAINER):
            raise ValueError('На сервере работают другие контейнеры. Сначала подготовьте перенос существующей установки')
        owned = command(['docker', 'inspect', '--format', '{{index .Config.Labels "'+LABEL+'"}}', name]).stdout.strip()
        if owned != b'1':
            raise ValueError('Имя контейнера уже занято другой установкой')
    addresses = json.loads(command(['ip', '-j', 'address', 'show', 'dev', host['interface']]).stdout)
    local = {entry['local'] for interface in addresses for entry in interface.get('addr_info', [])
             if 'tentative' not in entry.get('flags', []) and 'dadfailed' not in entry.get('flags', [])}
    if any(address not in local for address in (host['public4'], host['public6']) if address):
        raise ValueError('Публичные адреса должны быть назначены указанному интерфейсу')
    actual_ports = {int(line.split()[1]) for line in command(['sshd', '-T']).stdout.decode().splitlines()
                    if line.startswith('port ')}
    if actual_ports != set(host['ssh_ports']):
        raise ValueError('Порты SSH должны совпадать с действующей конфигурацией sshd')
    connection = os.environ.get('SSH_CONNECTION', '').split()
    if connection:
        source = ipaddress.ip_address(connection[0])
        allowed = source in {ipaddress.ip_address(ip) for ip in host['admins']+host['sources']}
        allowed = allowed or any(source in ipaddress.ip_network(net) for net in host['ssh_networks'])
        if not allowed:
            raise ValueError('Текущий адрес администратора отсутствует в разрешённом списке SSH')
    if not (ROOT/'current.json').exists():
        for port in (443, 8443, 9443, 9444, 8080):
            if command(['ss', '-H', '-ltn', 'sport = :'+str(port)]).stdout.strip():
                raise ValueError('Необходимый порт уже занят: '+str(port))


def setup(value, source, channel='latest', bundle=None):
    value = enrollment(value)
    preflight(value)
    store = state.Store(ROOT)
    descriptor = os.open(ROOT/'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous = store.current()
        if previous:
            raise ValueError('Нода уже установлена. Изменяйте настройки через основной бот')
        account = install.accounts()
        host = config.deployment(value['deployment'] | {'uid': account.pw_uid, 'gid': account.pw_gid,
                                 'cover_uid': pwd.getpwnam(install.COVER).pw_uid, 'awg_uid': pwd.getpwnam(install.AWG).pw_uid})
        install.install_code(source)
        state.atomic(install.ETC/'deployment.json', state.encode(host, state.MAX_DEPLOYMENT_BYTES))
        release = ROOT/'release.json'
        if bundle:
            manifest = image_bundle.read(bundle)
            state.atomic(release, state.encode(manifest))
        else:
            image_bundle.fetch(channel, release)
            manifest = image_bundle.read(release)
        backend = Runtime(store, host)
        images = {'xr': manifest['images']['xr']}
        if value['options'].get('cover'):
            images['ng'] = manifest['images']['ng']
        for image in images.values():
            backend.pull(image)
        node = dict(schema=1, options=value['options'], identity=backend.identity(images['xr']),
                    peers=[], images=images, tls={})
        backend.ensure_keys(node)
        existing = command(['nft', 'list', 'table', 'inet', 'vpnbot_node'], required=False).returncode == 0
        if existing:
            raise ValueError('Найдены действующие правила ноды без её состояния; требуется восстановление')
        state.trusted(backend.guard)
        previous_guard = backend.guard.read_bytes() if backend.guard.exists() else None
        previous_ssh = None
        try:
            # ACME is closed by default. Only certificate() creates a timed
            # TCP/80 element; SSH and VPN retain their source restrictions.
            rules = config.firewall(node['options'], backend.routed_host())
            command(['nft', '-c', '-f', '-'], data=rules.encode())
            command(['nft', '-f', '-'], data=rules.encode())
            # The UID/source guard is active before adapting the base profile.
            # Both layers then use the validated enrollment addresses/SSH ports.
            nft_host_setup.configure(host=host, mode='node')
            if config.needs_certificate(node['options']):
                node['tls'] = backend.certificate(node['options']['domain'], node['options'].get('domain_aliases', []))
            generation = store.create(node)
            backend.validate(generation)
            previous_ssh = install.install_ssh(value['controller_key'], host['sources'])
            backend.apply(generation)
            store.activate(generation)
            command(['systemctl', 'enable', 'vpnbot-node.service', 'vpnbot-node-watch.timer', 'vpnbot-node-renew.timer'])
            # The boot service takes the same lock in its own process. State
            # and SSH policy are complete before handing control to systemd.
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            command(['systemctl', 'start', 'vpnbot-node.service', 'vpnbot-node-watch.timer', 'vpnbot-node-renew.timer'])
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            verify_firewall(backend)
        except Exception:
            # A failure after starting systemd must not leave timers reviving
            # a partially installed node. ExecStop needs the same state lock.
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            command(['systemctl', 'disable', '--now', 'vpnbot-node-watch.timer',
                     'vpnbot-node-renew.timer', 'vpnbot-node.service'], required=False)
            command(['systemctl', 'stop', 'vpnbot-node-worker.service',
                     'vpnbot-node-watch.service', 'vpnbot-node-renew.service'], required=False)
            # If Docker cannot stop the node, retain its restrictive guard
            # and state for recovery instead of exposing a running container.
            backend.stop()
            if previous_guard is None:
                backend.guard.unlink(missing_ok=True)
            else:
                state.atomic(backend.guard, previous_guard)
            command(['nft', 'delete', 'table', 'inet', 'vpnbot_node'], required=False)
            (store.root/'current.json').unlink(missing_ok=True)
            if previous_ssh is not None:
                install.restore_ssh(previous_ssh)
            raise
        public = Path('/etc/ssh/ssh_host_ed25519_key.pub')
        fingerprint = command(['ssh-keygen', '-l', '-E', 'sha256', '-f', public]).stdout.decode().split()[1]
        return {'installed': True, 'ssh_user': install.CONTROL, 'host_fingerprint': fingerprint,
                'host_key': install.public_key(public.read_text()),
                'public4': host['public4'], 'public6': host['public6']}
    finally:
        os.close(descriptor)


def prompt():
    def ask(label, default='', optional=False):
        answer = input(label+(' ['+default+']' if default else '')+': ').strip()
        return '' if optional and answer == '-' else answer or default

    print('Минимальная нода: Xray и, при выборе своего сайта, NGINX. Токен Telegram не требуется.')
    defaults = node_host.defaults()
    if not defaults.get('network_detected', True):
        print('WAN не определён автоматически. Проверьте сохранённые значения или введите сетевые параметры вручную.')
    print('В скобках — найденные настройки. Enter сохраняет их; новое значение заменяет.')
    print('Для отсутствующего семейства IP или удаления необязательного списка введите «-».')
    print('Введите публичный SSH-ключ, созданный в разделе «Ноды» основного бота.')
    key = ask('Публичный ключ ssh-ed25519')
    sources = ask('Публичные IPv4/IPv6 основного бота через пробел (доступ к VPN и SSH)', ' '.join(defaults['sources'])).split()
    print('Другие серверы без доступа к SSH добавляйте в настройках ноды: «Серверы для VPN (без SSH)».')
    admins = ask('Публичные IPv4/IPv6 администратора только для SSH через пробел', ' '.join(defaults['admins'] or sources)).split()
    host = dict(public4=ask('Публичный IPv4 ноды («-» при отсутствии)', defaults['public4'], optional=True),
                public6=ask('Публичный IPv6 ноды («-» при отсутствии)', defaults['public6'], optional=True), sources=sources, admins=admins,
                interface=ask('Внешний интерфейс', defaults['interface']),
                ssh_ports=[int(x) for x in ask('Действующие порты SSH через пробел', ' '.join(map(str, defaults['ssh_ports']))).split()],
                routers=ask('Link-local IPv6 доверенных маршрутизаторов', ' '.join(defaults['routers']), optional=True).split())
    if defaults['ssh_networks']:
        host['ssh_networks'] = ask('Разрешённые подсети SSH из профиля', ' '.join(defaults['ssh_networks']), optional=True).split()
    transport = ask('Транспорт reality / ws / grpc / xhttp / trojan-grpc', 'reality')
    cover = ask('Заглушка с паролем на своём домене: да / нет', 'нет').lower() == 'да'
    domain = ask('Собственный домен, A/AAAA должны указывать на ноду') if cover or transport != 'reality' else ''
    mask = domain if cover else ask('Домен сайта для REALITY', 'www.microsoft.com')
    options = dict(transport=transport, core=ask('Ядро origin / origin2 / origin3 / fork', 'origin'),
                   family=int(ask('Семейство выхода в интернет: 4 / 6', '4')),
                   connect_family=int(ask('Семейство подключения к ноде: 4 / 6', '4')),
                   domain=domain, mask=mask, cover=cover)
    return enrollment(dict(schema=1, controller_key=key, deployment=host, options=options))


def failure_message(error):
    # Only reviewed constant messages may reach the terminal. Never print an
    # arbitrary exception: it can contain input, command output or a credential.
    public_errors = {
        'a public node address is required': 'Не задан публичный адрес ноды. Укажите IPv4 или IPv6.',
        'nftables service is not active and enabled': 'Служба nftables должна быть активна и включена в автозапуск. Проверьте её состояние и /etc/nftables.conf.',
        'nftables live rules differ from persistent configuration': 'Загруженные правила nftables не совпадают с сохранённой конфигурацией. Установка не подтверждена.',
        'Firewall command failed; details suppressed to protect configuration data': 'Не удалось проверить или применить nftables. Проверьте синтаксис профиля и состояние фаервола.',
        'Cannot discover public node address or SSH ports': 'Не удалось определить публичный адрес или действующие SSH-порты.',
        'Cannot inspect effective SSH ports': 'Не удалось прочитать действующие порты через sshd -T.',
        'Ambiguous WAN route': 'Не удалось однозначно определить внешний интерфейс.',
        'IPv4 and IPv6 use different WAN interfaces': 'IPv4 и IPv6 используют разные внешние интерфейсы.',
        'Default route has no stable assigned source': 'У внешнего маршрута нет стабильного назначенного IP-адреса.',
        'Invalid node address set type': 'В /etc/nftables.conf неверно объявлен набор адресов ноды: проверьте type и elements.',
        'Invalid node address set elements': 'В /etc/nftables.conf неверно записаны elements набора адресов ноды.',
        'Missing or ambiguous node firewall declaration': 'В /etc/nftables.conf отсутствует или повторяется набор адресов ноды.',
        'Incomplete node firewall declaration': 'В /etc/nftables.conf не закрыто объявление набора адресов ноды.',
        'Unsafe node firewall profile path': 'Проверьте владельца, права и отсутствие симлинков у /etc/nftables.conf.',
        'Unsafe node firewall profile file': 'Для /etc/nftables.conf нужен обычный файл допустимого размера.',
    }
    for message in ('Для выбранного семейства отсутствует публичный адрес',
                    'Публичные адреса должны быть назначены указанному интерфейсу',
                    'Порты SSH должны совпадать с действующей конфигурацией sshd',
                    'Текущий адрес администратора отсутствует в разрешённом списке SSH'):
        public_errors[message] = message+'.'
    detail = public_errors.get(str(error)) if isinstance(error, ValueError) else None
    return 'Установка ноды не завершена. '+(detail or 'Проверьте публичные параметры, порты и доступ к реестру образов.')


def main():
    parser = argparse.ArgumentParser(description='Установка минимальной управляемой ноды VPNBot')
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument('--config', type=Path, help='JSON с публичными параметрами подключения')
    inputs.add_argument('--controller-key', type=Path, help='Заменить ключ основного бота публичным ключом из файла; прежний доступ SSH отзывается')
    inputs.add_argument('--upgrade-code', action='store_true', help='Обновить код установленной ноды из этой копии репозитория; настройки и ключи сохраняются')
    parser.add_argument('--bundle', type=Path, help='Проверенный опубликованный комплект образов')
    parser.add_argument('--channel', choices=('latest', 'dev'), default='latest')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('Запустите установку от root')
    os.umask(0o077)
    if args.controller_key:
        if args.bundle or args.controller_key.is_symlink() or not args.controller_key.is_file():
            raise ValueError('Для передачи управления нужен обычный файл публичного ключа')
        with args.controller_key.open('r') as stream:
            key = stream.read(257)
        if len(key) > 256:
            raise ValueError('Некорректный публичный ключ')
        replace_controller(key)
        print('Ключ управления заменён; прежний SSH-доступ отозван. Настройки ноды и её подключения сохранены.')
        return
    if args.upgrade_code:
        if args.bundle:
            raise ValueError('Обновление кода не меняет комплект образов')
        upgrade_code(Path(__file__).resolve().parent)
        print('Код ноды обновлён, правила ноды перестроены. Настройки и ключи сохранены.')
        return
    if args.config:
        with args.config.open('rb') as stream:
            value = state.decode(stream.read(state.MAX_DEPLOYMENT_BYTES+1), state.MAX_DEPLOYMENT_BYTES)
    else:
        value = prompt()
    result = setup(value, Path(__file__).resolve().parent, args.channel, args.bundle)
    print('Проверка nftables завершена: сохранённые и действующие правила ноды согласованы.')
    print('Нода установлена. Пользователь SSH: '+result['ssh_user'])
    print('Сверьте отпечаток ключа сервера при подключении основного бота: '+result['host_fingerprint'])
    print('Публичный ключ сервера для раздела «Ноды»: '+result['host_key'])


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Установка прервана.', file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        # No subprocess diagnostics or enrollment values: future requests may
        # contain private data. Validation details are tested separately.
        print(failure_message(error), file=sys.stderr)
        sys.exit(1)
