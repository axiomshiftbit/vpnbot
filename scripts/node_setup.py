#!/usr/bin/env python3
"""Public enrollment document and installation of the minimal node host."""
import argparse
from datetime import datetime, timezone
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import image_bundle
import node_config as config
import node_install as install
import node_upgrade
import node_state as state
import nft_host_setup
import node_host
import node_adguard
from node_runtime import Runtime, command, HostOperationError, host_program, CONTAINER, COVER_CONTAINER, AWG_CONTAINER, WARP_CONTAINER, LABEL

ROOT = Path('/var/lib/vpnbot-node')
DOCKER_DAEMON = Path('/etc/docker/daemon.json')


DOCKER_SETTINGS = ('iptables', 'ip6tables', 'ip-forward')
# Written on installation: the required settings plus no userland proxy (node
# containers use the host network and publish no ports). Existing nodes are
# checked against DOCKER_SETTINGS only, so an upgrade never fails on it.
DOCKER_INSTALL = {name: False for name in DOCKER_SETTINGS} | {'userland-proxy': False}
FORWARDING = Path('/etc/sysctl.d/98-vpnbot-node-forwarding.conf')
LOG_PATH = Path('/var/log/vpnbot-node/setup.log')
STAGES = {
    'input': 'ввод и проверка параметров',
    'preflight': 'проверка адресов, SSH, портов и контейнеров',
    'state': 'проверка состояния и блокировки установки',
    'docker': 'настройка Docker без управления фаерволом',
    'forwarding': 'отключение маршрутизации IPv4/IPv6',
    'accounts': 'создание служебных пользователей',
    'code': 'установка кода и служб ноды',
    'bundle': 'проверка опубликованного комплекта образов',
    'pull': 'загрузка образов ноды',
    'identity': 'подготовка идентификаторов ноды',
    'firewall': 'проверка и применение защиты nftables',
    'certificate': 'проверка DNS и получение TLS-сертификата',
    'validate': 'проверка конфигурации Xray и сайта прикрытия',
    'ssh': 'настройка ограниченного SSH-доступа основного бота',
    'start': 'запуск контейнеров ноды',
    'services': 'включение и запуск служб ноды',
    'verify': 'итоговая проверка действующих правил фаервола',
    'rollback': 'откат незавершённой установки',
    'result': 'проверка публичного ключа сервера и завершение',
}
CURRENT_STAGE = 'input'
REPORT = None


def terminal(message):
    try:
        print(message, file=sys.stderr, flush=True)
    except OSError:
        # A disconnected terminal must not abort installation or its rollback.
        pass


class SetupLog:
    """Private append-only diagnostics: callers pass only reviewed safe text."""
    def __init__(self, path):
        state.trusted(path)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
                raise ValueError('unsafe setup log')
            os.fchmod(fd, 0o600)
            self.stream = os.fdopen(fd, 'a', encoding='utf-8')
        except BaseException:
            os.close(fd)
            raise

    def write(self, message):
        terminal(message)
        if self.stream is not None:
            try:
                stamp = datetime.now(timezone.utc).isoformat(timespec='seconds')
                self.stream.write(stamp+' pid='+str(os.getpid())+' '+message+'\n')
                self.stream.flush()
            except OSError:
                # A full log filesystem must not interrupt rollback or hide the
                # original failure. Further safe diagnostics stay on stderr.
                terminal('Не удалось записать журнал установки; сообщения доступны в терминале.')
                self.close()

    def close(self):
        if self.stream is not None:
            try:
                self.stream.close()
            except OSError:
                pass
            self.stream = None


def progress(name):
    global CURRENT_STAGE
    CURRENT_STAGE = name
    if REPORT:
        REPORT.write('Этап ['+name+']: '+STAGES[name]+'.')


def report_error(error):
    message = 'Ошибка на этапе ['+CURRENT_STAGE+'] ('+STAGES[CURRENT_STAGE]+'). '+failure_message(error)
    if REPORT:
        REPORT.write(message)
    else:
        terminal(message)


def docker_firewall_disabled(daemon=DOCKER_DAEMON, proc=Path('/proc')):
    """Only the nft profile and the node guard filter packets on a node.

    By default dockerd creates its own chains and tables (DOCKER*, nat,
    docker-bridges) after nftables.service on every boot and turns on IP
    forwarding. Node containers use the host network: Docker needs neither."""
    settings = {}
    if daemon.exists():
        try:
            value = state.decode(daemon.read_bytes(), 1024*1024)
        except (ValueError, OSError):
            value = None
        if not isinstance(value, dict):
            raise ValueError('Docker firewall management is enabled')
        settings = {name: value[name] for name in DOCKER_SETTINGS if name in value}
    # dockerd refuses a flag that conflicts with daemon.json; either source counts.
    for process in proc.glob('[0-9]*'):
        try:
            if (process/'comm').read_text().strip() != 'dockerd':
                continue
            arguments = (process/'cmdline').read_bytes().split(b'\0')
        except OSError:
            continue
        for name in DOCKER_SETTINGS:
            if ('--'+name+'=false').encode() in arguments:
                settings[name] = False
            elif ('--'+name).encode() in arguments or ('--'+name+'=true').encode() in arguments:
                settings[name] = True
    if any(settings.get(name) is not False for name in DOCKER_SETTINGS):
        raise ValueError('Docker firewall management is enabled')


def prepare_docker(daemon=DOCKER_DAEMON):
    """Fresh installation only: merge the node's Docker settings and restart it.

    Other daemon.json keys are kept; the previous file is saved next to it.
    preflight() has already refused foreign running containers."""
    try:
        docker_firewall_disabled(daemon)
        current = state.decode(daemon.read_bytes(), 1024*1024) if daemon.is_file() else {}
        if isinstance(current, dict) and all(current.get(k) is v for k, v in DOCKER_INSTALL.items()):
            return False
    except (ValueError, OSError):
        pass
    state.trusted(daemon)
    if daemon.exists():
        if daemon.is_symlink() or not daemon.is_file() or daemon.stat().st_nlink != 1:
            raise ValueError('Docker firewall management is enabled')
        original = daemon.read_bytes()
        try:
            value = state.decode(original, 1024*1024)
        except ValueError:
            value = None
        if not isinstance(value, dict):
            raise ValueError('Docker firewall management is enabled')
        backup = daemon.with_name(daemon.name+'.before-vpnbot-node')
        state.trusted(backup)
        if not backup.exists():
            state.atomic(backup, original, 0o600)
    else:
        daemon.parent.mkdir(mode=0o755, exist_ok=True)
        value = {}
    value.update(DOCKER_INSTALL)
    state.atomic(daemon, json.dumps(value, indent=2, sort_keys=True).encode()+b'\n', 0o644)
    command(['systemctl', 'restart', 'docker.service'], timeout=120)
    docker_firewall_disabled(daemon)
    return True


def disable_forwarding(proc=Path('/proc/sys')):
    """A node routes nothing; both forward chains drop, the kernel does not forward."""
    body = b'# VPNBot node: no IP forwarding (Docker ip-forward=false, host network only).\n' \
           b'net.ipv4.ip_forward = 0\nnet.ipv6.conf.all.forwarding = 0\n'
    state.trusted(FORWARDING)
    state.atomic(FORWARDING, body, 0o644)
    # Keep both families in the boot policy, including a future boot with IPv6
    # enabled. A kernel booted with ipv6.disable=1 has no IPv6 sysctl at all.
    parameters = ['net.ipv4.ip_forward']
    try:
        (proc/'net/ipv6/conf/all/forwarding').stat()
    except FileNotFoundError:
        if REPORT:
            REPORT.write('IPv6 недоступен в ядре: параметр IPv6 пропущен; запрет IPv4-маршрутизации сохраняется.')
    else:
        parameters.append('net.ipv6.conf.all.forwarding')
    command(['sysctl', '-q', '-w', *[name+'=0' for name in parameters]])
    if any((proc/name.replace('.', '/')).read_text().strip() != '0' for name in parameters):
        raise ValueError('IP forwarding remains enabled')


LOCK_NFT = Path('/run/lock/nft-docker-watch.lock')


def docker_rules_loaded(live):
    """dockerd names its iptables-nft chains DOCKER/DOCKER-* and its nftables
    backend tables docker-*; hand-written names such as "dockernat" are not Docker's."""
    return any(re.match(r'DOCKER(?:-|$)', x['name']) for x in nft_host_setup.objects(live, 'chain')) \
        or any(x['name'].startswith('docker-') for x in nft_host_setup.objects(live, 'table'))


def drop_stale_docker_rules(path=Path('/etc/nftables.conf')):
    """Docker's first start on a clean server (before the profile disabled its
    firewall management) creates iptables-nft chains; restarting dockerd with
    iptables=false keeps them. Load the persistent profile, which starts with
    flush ruleset and includes the node guard, exactly as the next boot does."""
    fd = os.open(LOCK_NFT, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        live = json.loads(command(['nft', '-j', 'list', 'ruleset']).stdout)
        if not docker_rules_loaded(live) or not path.exists():
            return False
        docker_firewall_disabled()
        command(['nft', '-c', '-f', path])
        command(['nft', '-f', path])
        return True
    finally:
        os.close(fd)


def verify_firewall(backend, path=Path('/etc/nftables.conf')):
    """Read back service, persistent configuration and live rules; never reload."""
    fd = os.open(LOCK_NFT, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
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
        # Anywhere in the ruleset, not only in profile tables.
        if docker_rules_loaded(live):
            raise ValueError('Docker firewall rules are loaded')
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


def upgrade_code(source, job_id=None):
    """Refresh node code and units in place, then rebuild the node guard with that code.

    State, keys and settings stay as they are. The node lock excludes a running
    job or renewal, so no ACME window can be open while the guard is replaced.
    job_id: the code phase of the bot's full update, which owns the running job."""
    progress('state')
    store = state.Store(ROOT)
    descriptor = os.open(ROOT/'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        # The bot keeps polling and the watch timer runs every 15 s; each holds
        # the lock briefly. The button's code phase waits for them, a manual
        # run still reports a busy node at once.
        attempts = 120 if job_id is not None else 1
        for attempt in range(attempts):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if attempt == attempts-1:
                    raise
                time.sleep(.5)
        job = store.read('job.json') or {}
        owned = job_id is not None and job.get('id') == job_id and job.get('state') == 'running' and job.get('phase') == 'code'
        if not store.current() or store.pending() or (job.get('state') in ('queued', 'running') and not owned) \
                or (job_id is not None and not owned):
            raise ValueError('Нода не установлена или изменение ещё не завершено')
        if job_id is None:
            # Manually installed code is no longer the commit recorded by the
            # bot's last full update; the next one compares with the clone.
            (ROOT/'code.json').unlink(missing_ok=True)
        progress('docker')
        docker_firewall_disabled()
        progress('forwarding')
        disable_forwarding()
        progress('code')
        install.install_code(source)
        # The node status reports the installed commit and checks the files.
        node_upgrade.record(ROOT, source, job_id is None)
        host = config.deployment(state.decode((install.ETC/'deployment.json').read_bytes(), state.MAX_DEPLOYMENT_BYTES))
        progress('firewall')
        Runtime(store, host).load_firewall()
        nft_host_setup.configure(host=host, mode='node')
        progress('verify')
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


def preflight(value, docker=True):
    host = value['deployment']
    if docker:
        docker_firewall_disabled()
    active = command(['docker', 'ps', '--format', '{{json .}}']).stdout.decode().splitlines()
    for line in active:
        name = json.loads(line)['Names']
        if name not in (CONTAINER, COVER_CONTAINER, AWG_CONTAINER, WARP_CONTAINER, node_adguard.CONTAINER):
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
    progress('input')
    value = enrollment(value)
    progress('preflight')
    preflight(value, docker=False)
    progress('state')
    store = state.Store(ROOT)
    descriptor = os.open(ROOT/'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous = store.current()
        if previous:
            raise ValueError('Нода уже установлена. Изменяйте настройки через основной бот')
        # Only now: an installed node is never interrupted by a Docker restart.
        progress('docker')
        prepare_docker()
        progress('forwarding')
        disable_forwarding()
        progress('accounts')
        account = install.accounts()
        host = config.deployment(value['deployment'] | {'uid': account.pw_uid, 'gid': account.pw_gid,
                                 'cover_uid': pwd.getpwnam(install.COVER).pw_uid, 'awg_uid': pwd.getpwnam(install.AWG).pw_uid})
        progress('code')
        install.install_code(source)
        node_upgrade.record(ROOT, source, True)
        state.atomic(install.ETC/'deployment.json', state.encode(host, state.MAX_DEPLOYMENT_BYTES))
        progress('bundle')
        release = ROOT/'release.json'
        if bundle:
            manifest = image_bundle.read(bundle)
            state.atomic(release, state.encode(manifest))
        else:
            image_bundle.fetch(channel, release)
            manifest = image_bundle.read(release)
        backend = Runtime(store, host)
        images = {'xr': manifest['images']['xr']}
        if value['options'].get('adguard', {}).get('enabled'):
            images['ad'] = manifest['images']['ad']
        if value['options'].get('cover'):
            images['ng'] = manifest['images']['ng']
        if value['options'].get('warp_mode', 'off') != 'off':
            images['wg'] = manifest['images']['wg']
        progress('pull')
        for image in images.values():
            backend.pull(image)
        progress('identity')
        node = dict(schema=1, options=value['options'], identity=backend.identity(images['xr']),
                    peers=[], images=images, tls={})
        backend.ensure_keys(node)
        progress('firewall')
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
                progress('certificate')
                node['tls'] = backend.certificate(node['options']['domain'], node['options'].get('domain_aliases', []))
            progress('validate')
            generation = store.create(node)
            backend.validate(generation)
            progress('ssh')
            previous_ssh = install.install_ssh(value['controller_key'], host['sources'])
            progress('start')
            backend.apply(generation)
            store.activate(generation)
            progress('services')
            command(['systemctl', 'enable', 'vpnbot-node.service', 'vpnbot-node-watch.timer', 'vpnbot-node-renew.timer'])
            # The boot service takes the same lock in its own process. State
            # and SSH policy are complete before handing control to systemd.
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            command(['systemctl', 'start', 'vpnbot-node.service', 'vpnbot-node-watch.timer', 'vpnbot-node-renew.timer'])
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            progress('verify')
            drop_stale_docker_rules()
            verify_firewall(backend)
        except Exception as error:
            failed_stage = CURRENT_STAGE
            report_error(error)
            progress('rollback')
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
            progress(failed_stage)
            raise
        progress('result')
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
    print('Другие серверы без доступа к SSH добавляйте в карточке ноды основного бота: «Серверы для VPN (без SSH)».')
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
        'IP forwarding remains enabled': 'Ядро не подтвердило отключение маршрутизации. Установка остановлена для сохранения изоляции ноды.',
        'unsafe setup log': 'Небезопасный файл журнала /var/log/vpnbot-node/setup.log: нужны обычный файл, владелец root и отсутствие жёстких ссылок.',
        'symlink in state path': 'В защищённом пути обнаружена символическая ссылка. Проверьте пути состояния и журнала ноды.',
        'untrusted state path': 'У защищённого каталога неверный владелец или разрешена запись другим пользователям.',
        'domain DNS must point only to this node': 'Все A/AAAA-записи домена должны указывать только на публичные адреса этой ноды. Проверьте также лишнюю AAAA-запись.',
        'an ED25519 public key is required': 'Нужен полный публичный ключ ssh-ed25519 из карточки ноды основного бота.',
        'invalid public key': 'Публичный SSH-ключ повреждён или обрезан. Скопируйте его полностью из карточки ноды.',
        'invalid hostname': 'Некорректное доменное имя. Введите имя без https://, пути и порта.',
        'account name is already in use': 'Служебный пользователь ноды уже существует, но её настройки отсутствуют. Требуется проверка незавершённой установки.',
        'incompatible service account': 'Существующий служебный пользователь несовместим с установкой ноды. Проверьте UID и оболочку пользователя.',
        'node core failed to start': 'Контейнер Xray не запустился. Проверьте выбранное ядро и конфигурацию ноды.',
        'node listener did not become ready': 'VPN-порт ноды не стал доступен за отведённое время.',
        'Запустите установку от root': 'Запустите установку от root.',
        'a public node address is required': 'Не задан публичный адрес ноды. Укажите IPv4 или IPv6.',
        'nftables service is not active and enabled': 'Служба nftables должна быть активна и включена в автозапуск. Проверьте её состояние и /etc/nftables.conf.',
        'nftables live rules differ from persistent configuration': 'Загруженные правила nftables не совпадают с сохранённой конфигурацией. Установка не подтверждена.',
        'Docker firewall management is enabled': 'Docker управляет фаерволом или маршрутизацией. Для ноды правила nftables задаются только вручную: добавьте в /etc/docker/daemon.json "iptables": false, "ip6tables": false и "ip-forward": false и перезапустите Docker (первичная установка делает это сама).',
        'Firewall profile does not match installation mode': 'В /etc/nftables.conf не профиль минимальной ноды. Установите шаблон nftables/noda.conf: bash scripts/init.sh --mode node делает это сам.',
        'Docker firewall rules are loaded': 'В nftables загружены цепочки или таблицы Docker. После отключения управления фаерволом в Docker перезагрузите сервер или заново загрузите /etc/nftables.conf.',
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
                    'Текущий адрес администратора отсутствует в разрешённом списке SSH',
                    'Нода уже установлена. Изменяйте настройки через основной бот',
                    'Нода не установлена или изменение ещё не завершено',
                    'Некорректный файл подключения ноды', 'Некорректные параметры сети',
                    'На сервере работают другие контейнеры. Сначала подготовьте перенос существующей установки',
                    'Имя контейнера уже занято другой установкой',
                    'Найдены действующие правила ноды без её состояния; требуется восстановление'):
        public_errors[message] = message+'.'
    # Fixed text plus the number of a port this installer checks; no input data.
    for port in (443, 8443, 9443, 9444, 8080):
        public_errors['Необходимый порт уже занят: '+str(port)] = 'Необходимый порт уже занят: '+str(port)+'.'
    detail = public_errors.get(str(error)) if isinstance(error, (ValueError, RuntimeError)) else None
    if isinstance(error, HostOperationError):
        reasons = {
            'command_failed': 'команда завершилась с ошибкой; проверьте компонент, указанный в текущем этапе',
            'disk_full': 'недостаточно места на диске',
            'permission': 'операция запрещена правами или ограничениями системы',
            'timeout': 'истекло время ожидания ответа',
            'dns': 'не удалось разрешить DNS-имя',
            'tls': 'сбой TLS-соединения или проверки сертификата',
            'port_busy': 'необходимый сетевой порт уже занят',
            'missing_sysctl': 'параметр sysctl отсутствует в ядре',
            'registry_auth': 'реестр отказал в доступе к образу',
            'acme_validation': 'центр сертификации не подтвердил домен; проверьте DNS и доступность TCP/80',
        }
        detail = host_program(error.program)+': '+reasons.get(error.category, reasons['command_failed'])
        if type(error.returncode) is int:
            detail += ' (код завершения '+str(error.returncode)+')'
        detail += '.'
    elif isinstance(error, subprocess.TimeoutExpired):
        program = host_program(error.cmd[0]) if isinstance(error.cmd, (list, tuple)) and error.cmd else host_program(None)
        detail = program+': превышено время ожидания выполнения команды.'
    elif isinstance(error, socket.gaierror):
        detail = 'Не удалось разрешить DNS-имя. Проверьте DNS-записи домена и доступность DNS-сервера.'
    elif isinstance(error, TimeoutError):
        detail = 'Превышено время ожидания сетевой операции указанного этапа.'
    elif isinstance(error, BlockingIOError):
        detail = 'Нода занята другой операцией. Дождитесь её завершения; не запускайте установки одновременно.'
    elif isinstance(error, FileNotFoundError):
        detail = 'Не найден необходимый файл, системная команда или параметр ядра. Проверьте зависимости указанного этапа.'
    elif isinstance(error, PermissionError):
        detail = 'Недостаточно прав для указанного этапа. Проверьте владельца файлов и ограничения системы.'
    elif isinstance(error, OSError) and error.errno == 28:
        detail = 'Недостаточно места на диске для продолжения установки.'
    return 'Установка ноды не завершена. '+(detail or 'Неожиданный сбой. Для диагностики сохраните номер этапа и безопасный журнал установки; повторная установка может потребовать восстановления.')


def main():
    parser = argparse.ArgumentParser(description='Установка минимальной управляемой ноды VPNBot')
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument('--config', type=Path, help='JSON с публичными параметрами подключения')
    inputs.add_argument('--controller-key', type=Path, help='Заменить ключ основного бота публичным ключом из файла; прежний доступ SSH отзывается')
    inputs.add_argument('--upgrade-code', action='store_true', help='Обновить код установленной ноды из этой копии репозитория; настройки и ключи сохраняются')
    parser.add_argument('--job', help=argparse.SUPPRESS)
    parser.add_argument('--bundle', type=Path, help='Проверенный опубликованный комплект образов')
    parser.add_argument('--channel', choices=('latest', 'dev'), default='latest')
    args = parser.parse_args()
    if args.job is not None and not args.upgrade_code:
        parser.error('--job используется только с --upgrade-code')
    if os.geteuid() != 0:
        raise ValueError('Запустите установку от root')
    os.umask(0o077)
    if args.controller_key:
        progress('ssh')
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
        if args.job is not None and not re.fullmatch('[a-f0-9]{32}', args.job):
            raise ValueError('Нода не установлена или изменение ещё не завершено')
        upgrade_code(Path(__file__).resolve().parent, args.job)
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


def run():
    global REPORT, CURRENT_STAGE
    CURRENT_STAGE = 'input'
    try:
        if os.geteuid() == 0:
            REPORT = SetupLog(LOG_PATH)
            REPORT.write('Журнал установки: /var/log/vpnbot-node/setup.log (доступ только root).')
        progress('input')
        main()
        if REPORT:
            REPORT.write('Операция завершена успешно.')
        return 0
    except KeyboardInterrupt:
        if REPORT:
            REPORT.write('Установка прервана пользователем на этапе ['+CURRENT_STAGE+'].')
        else:
            terminal('Установка прервана.')
        return 1
    except Exception as error:
        report_error(error)
        return 1
    finally:
        if REPORT:
            REPORT.close()
            REPORT = None


if __name__ == '__main__':
    sys.exit(run())
