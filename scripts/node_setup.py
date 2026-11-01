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
from node_runtime import Runtime, command, CONTAINER, COVER_CONTAINER, AWG_CONTAINER, LABEL

ROOT = Path('/var/lib/vpnbot-node')


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
    def ask(label, default=''):
        return input(label+(' ['+default+']' if default else '')+': ').strip() or default

    print('Минимальная нода: Xray и, при выборе своего сайта, NGINX. Токен Telegram не требуется.')
    print('Введите публичный SSH-ключ, созданный в разделе «Ноды» основного бота.')
    key = ask('Публичный ключ ssh-ed25519')
    sources = ask('Публичные IPv4/IPv6 основного бота и других разрешённых VPN-серверов через пробел').split()
    admins = ask('Адреса администратора для SSH через пробел', ' '.join(sources)).split()
    host = dict(public4=ask('Публичный IPv4 ноды, пусто при отсутствии'),
                public6=ask('Публичный IPv6 ноды, пусто при отсутствии'), sources=sources, admins=admins,
                interface=ask('Внешний интерфейс', 'eth0'),
                ssh_ports=[int(x) for x in ask('Действующие порты SSH через пробел', '22').split()],
                routers=ask('Link-local IPv6 доверенных маршрутизаторов, можно оставить пустым').split())
    transport = ask('Транспорт reality / ws / grpc / xhttp', 'reality')
    cover = ask('Заглушка с паролем на своём домене: да / нет', 'нет').lower() == 'да'
    domain = ask('Собственный домен, A/AAAA должны указывать на ноду') if cover or transport != 'reality' else ''
    mask = domain if cover else ask('Домен сайта для REALITY', 'www.microsoft.com')
    options = dict(transport=transport, core=ask('Ядро origin / origin2 / origin3 / fork', 'origin'),
                   family=int(ask('Семейство выхода в интернет: 4 / 6', '4')),
                   connect_family=int(ask('Семейство подключения к ноде: 4 / 6', '4')),
                   domain=domain, mask=mask, cover=cover)
    return enrollment(dict(schema=1, controller_key=key, deployment=host, options=options))


def main():
    parser = argparse.ArgumentParser(description='Установка минимальной управляемой ноды VPNBot')
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument('--config', type=Path, help='JSON с публичными параметрами подключения')
    inputs.add_argument('--controller-key', type=Path, help='Заменить ключ основного бота публичным ключом из файла; прежний доступ SSH отзывается')
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
    if args.config:
        with args.config.open('rb') as stream:
            value = state.decode(stream.read(state.MAX_DEPLOYMENT_BYTES+1), state.MAX_DEPLOYMENT_BYTES)
    else:
        value = prompt()
    result = setup(value, Path(__file__).resolve().parent, args.channel, args.bundle)
    print('Нода установлена. Пользователь SSH: '+result['ssh_user'])
    print('Сверьте отпечаток ключа сервера при подключении основного бота: '+result['host_fingerprint'])
    print('Публичный ключ сервера для раздела «Ноды»: '+result['host_key'])


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Установка прервана.', file=sys.stderr)
        sys.exit(1)
    except Exception:
        # No subprocess diagnostics or enrollment values: future requests may
        # contain private data. Validation details are tested separately.
        print('Установка ноды не завершена. Проверьте публичные параметры, порты и доступ к реестру образов.', file=sys.stderr)
        sys.exit(1)
