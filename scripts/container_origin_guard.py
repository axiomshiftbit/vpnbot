#!/usr/bin/env python3
"""Проверка происхождения кадров Docker до conntrack и обучения FDB.

Политика хранится на хосте; адреса, MAC и veth берутся у локального Docker.
Неизвестный порт защищённого моста закрыт. В /run хранится атомарный снимок
для nft reload; после reboot разрешения пусты до новой сверки с Docker.
"""
import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

TABLE = 'vpnbot_origin'
CONFIG = Path('/etc/vpnbot-origin/config.json')
BASE = Path('/etc/nftables.d/vpnbot-origin.nft')
RUNTIME = Path('/run/vpnbot-origin')
PROGRAM = Path('/usr/local/sbin/vpnbot-origin')
UNIT = Path('/etc/systemd/system/vpnbot-origin.service')
BRIDGES = ('br-vpnbot0', 'br-vpnbot1', 'br-vpnbot6')
PREFIXES = ('10.10.0.0/23', 'fd42:7662:6::/64')
INCLUDES = ('include "/etc/nftables.d/vpnbot-origin.nft"',
            'include "/etc/nftables.d/vpnbot-origin*.nft"')
DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
NAME = re.compile(r'[A-Za-z0-9_.:-]{1,15}\Z')
SERVICES = frozenset(('php service dockerproxy ng up xr wg wg1 ad wp proxy ss np oc ovpn '
                      'hy tt dnstt telemt ipsec anytls mieru tuic shadowtls snolc masque').split())
INSPECT = '''{"id":{{json .Id}},"pid":{{.State.Pid}},"running":{{.State.Running}},"sandbox":{{json .NetworkSettings.SandboxKey}},"service":{{json (index .Config.Labels "com.docker.compose.service")}},"root":{{json (index .Config.Labels "com.docker.compose.project.working_dir")}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"mode":{{json .HostConfig.NetworkMode}},"privileged":{{.HostConfig.Privileged}},"networks":{{json .NetworkSettings.Networks}}}'''


class Refuse(Exception):
    pass


def run(args, data=None, timeout=20):
    p = subprocess.run(list(map(str, args)), input=data, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        # stdout/stderr Docker могут содержать конфигурацию: не публикуем их.
        raise Refuse('Команда не выполнена: ' + str(args[0]))
    return p.stdout


def trusted(path, directory=False):
    path = Path(path)
    if not path.is_absolute():
        raise Refuse('Требуется абсолютный путь')
    for part in (path, *path.parents):
        s = part.lstat()
        if stat.S_ISLNK(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise Refuse('Небезопасный владелец/права пути: ' + str(part))
    if not (path.is_dir() if directory else path.is_file()):
        raise Refuse('Неверный тип пути')
    return path


def write(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    trusted(path.parent, True)
    if path.exists() or path.is_symlink():
        trusted(path)
    fd, tmp = tempfile.mkstemp(prefix='.origin-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            os.fchmod(f.fileno(), mode)
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@contextlib.contextmanager
def lockfile(path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022 or st.st_nlink != 1:
            raise Refuse('Небезопасный lock-файл')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def lock():
    return lockfile('/run/lock/nft-docker-watch.lock')


def interface(value):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise Refuse('Неверное имя интерфейса')
    return json.dumps(value)


def mac_linklocal(mac):
    octets = bytearray.fromhex(mac.replace(':', ''))
    octets[0] ^= 2
    iid = bytes(octets[:3]) + b'\xff\xfe' + bytes(octets[3:])
    return str(ipaddress.IPv6Address(int(ipaddress.IPv6Address('fe80::')) | int.from_bytes(iid, 'big')))


def render(bridges, endpoints, prefixes=PREFIXES):
    """Весь ruleset одной таблицы; не трогает NAT, GeoIP и чужие таблицы."""
    names = ', '.join(interface(x) for x in sorted(set(bridges)))
    if not names:
        raise Refuse('Нет защищённых мостов')
    networks = {ipaddress.ip_network(x) for x in prefixes}
    for e in endpoints:
        networks.update(ipaddress.ip_network(x) for x in e.get('networks', []) + e.get('routed', []))
    generation = hashlib.sha256(json.dumps([sorted(bridges), endpoints, sorted(map(str, networks))], sort_keys=True).encode()).hexdigest()
    lines = [f'table bridge {TABLE} {{', f' comment "origin:{generation}"', ' chain ingress {',
             '  type filter hook prerouting priority -450; policy accept;',
             f'  meta ibrname {{ {names} }} jump dispatch']
    # Also catch forged trusted sources arriving through a DIFFERENT bridge.
    for version, protocol in ((4, 'ip'), (6, 'ip6')):
        values = ', '.join(sorted(str(x) for x in networks if x.version == version))
        if values:
            lines += [f'  ether type {protocol} {protocol} saddr {{ {values} }} jump dispatch']
            if version == 4:
                lines += [f'  ether type arp arp saddr ip {{ {values} }} jump dispatch']
    lines += [' }', ' chain denied {',
             '  limit rate 5/second burst 10 packets log prefix "BR-ORIGIN-DROP: "',
             '  counter drop', ' }']
    jumps = []
    seen = set()
    for n, e in enumerate(sorted(endpoints, key=lambda x: (x['bridge'], x['index']))):
        key = (e['index'], e['host'])
        if key in seen or not isinstance(e['index'], int) or e['index'] <= 0:
            raise Refuse('Неоднозначный порт моста')
        seen.add(key)
        host, bridge = interface(e['host']), interface(e['bridge'])
        mac = e['mac'].lower()
        if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac) or int(mac[:2], 16) & 1:
            raise Refuse('Неверный MAC endpoint')
        v4 = [str(ipaddress.IPv4Address(x)) for x in e['ipv4']]
        v6 = sorted({str(ipaddress.IPv6Address(x)) for x in e['ipv6']} | {mac_linklocal(mac)})
        routed = [str(ipaddress.IPv4Network(x)) for x in e.get('routed', [])]
        jumps.append(f'  meta ibrname {bridge} meta iif {e["index"]} iifname {host} jump endpoint{n}')
        lines += [f' chain endpoint{n} {{', f'  ether saddr != {mac} jump denied']
        if v4:
            addresses = ', '.join(v4)
            lines += [f'  ether type arp arp saddr ether != {mac} jump denied',
                      f'  ether type arp arp operation {{ request, reply }} arp saddr ip {{ {addresses} }} accept',
                      f'  ether type arp arp operation request arp saddr ip 0.0.0.0 arp daddr ip {{ {addresses} }} accept',
                      f'  ether type ip ip saddr {{ {", ".join(v4 + routed)} }} accept']
        addresses6 = ', '.join(v6)
        targets6 = ', '.join('0x%032x' % int(ipaddress.IPv6Address(x)) for x in v6)
        lines += ['  ether type ip6 meta l4proto ipv6-icmp icmpv6 type { nd-router-advert, nd-redirect } jump denied',
                  '  ether type ip6 meta l4proto ipv6-icmp icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit != 255 jump denied',
                  '  ether type ip6 meta l4proto ipv6-icmp icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } icmpv6 code != 0 jump denied',
                  # ICMPv6 NS/NA target address: 128 bits, offset 64 in transport header.
                  f'  ether type ip6 ip6 saddr {{ {addresses6} }} meta l4proto ipv6-icmp icmpv6 type nd-neighbor-advert @th,64,128 {{ {targets6} }} accept',
                  '  ether type ip6 meta l4proto ipv6-icmp icmpv6 type nd-neighbor-advert jump denied',
                  f'  ether type ip6 ip6 saddr :: ip6 hoplimit 255 icmpv6 type nd-neighbor-solicit icmpv6 code 0 @th,64,128 {{ {targets6} }} accept',
                  f'  ether type ip6 ip6 saddr {{ {addresses6} }} accept',
                  '  jump denied', ' }']
    lines += [' chain dispatch {', *jumps, '  jump denied', ' }', '}']
    return '\n'.join(lines) + '\n'


def containers(root):
    ids = run(DOCKER + ['ps', '-q', '--filter', 'label=com.docker.compose.project.working_dir=' + root]).split()
    if not ids:
        return []
    return [json.loads(line) for line in run(DOCKER + ['inspect', '--format', INSPECT, *ids]).splitlines()]


def client_networks(container):
    # Только названные НЕсекретные поля. Полное окружение никогда не извлекается.
    service = container['service']
    keys = {'wg': ('ADDRESS',), 'wg1': ('ADDRESS',), 'ovpn': ('OVPNSUBNET',),
            'ipsec': ('L2TPSUBNET', 'IKEV2SUBNET')}.get(service, ())
    if service == 'oc':
        return ['10.0.2.0/24']
    if not keys:
        return []
    condition = 'or ' + ' '.join('(eq (index $p 0) ' + json.dumps(k) + ')' for k in keys)
    fmt = '{{range .Config.Env}}{{$p := split . "="}}{{if ' + condition + '}}{{println (index $p 1)}}{{end}}{{end}}'
    result = []
    for value in run(DOCKER + ['inspect', '--format', fmt, container['id']]).split():
        net = ipaddress.ip_network(value, strict=False)
        private = [ipaddress.ip_network(x) for x in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
        if net.version != 4 or net.prefixlen < 16 or not any(net.subnet_of(x) for x in private):
            raise Refuse('Небезопасная клиентская подсеть VPN')
        result.append(str(net))
    return result


def inventory(cfg):
    root = cfg['bot_dir']
    hosts = {x['ifindex']: x for x in json.loads(run(['ip', '-j', 'link', 'show']))}
    endpoints, bridges, protected = [], set(cfg['bridges']), []
    cs = containers(root)
    network_cache = {}
    roles = set()
    for c in cs:
        if c['root'] != root or c['service'] not in SERVICES or c['service'] in roles or c['privileged']:
            raise Refuse('Неподдерживаемый или неоднозначный Compose сервис')
        roles.add(c['service'])
        if not c['running'] or c['pid'] <= 0 or not c['sandbox'].startswith('/var/run/docker/netns/'):
            continue  # A restarting service must not block healthy peers' DNS.
        try:
            links = json.loads(run(['nsenter', '-t', str(c['pid']), '-n', 'ip', '-j', 'link', 'show', 'type', 'veth']))
        except (Refuse, subprocess.SubprocessError):
            continue  # No allowance for this endpoint until it can be verified.
        routed = client_networks(c)
        for network, ep in c['networks'].items():
            if network not in network_cache:
                network_cache[network] = json.loads(run(DOCKER + ['network', 'inspect', '--format',
                    '{"driver":{{json .Driver}},"id":{{json .Id}},"options":{{json .Options}},"project":{{json (index .Labels "com.docker.compose.project")}},"role":{{json (index .Labels "com.docker.compose.network")}},"ipam":{{json .IPAM.Config}}}', network]))
            meta = network_cache[network]
            if meta['driver'] != 'bridge' or meta['project'] != c['project'] or meta['role'] not in ('default', 'xray', 'ipv6_egress'):
                raise Refuse('Неподдерживаемая сеть контейнера')
            bridge = (meta['options'] or {}).get('com.docker.network.bridge.name', 'br-' + meta['id'][:12])
            interface(bridge)
            bridges.add(bridge)
            protected.extend(x['Subnet'] for x in meta['ipam'])
            # Match by peer/master, not a MAC supplied by packets/container.
            candidates = [hosts[l['link_index']] for l in links if l.get('link_index') in hosts
                          and hosts[l['link_index']].get('master') == bridge]
            if len(candidates) != 1:
                continue
            if not ep['MacAddress']:
                continue
            h = candidates[0]
            endpoints.append({'container': c['id'], 'host': h['ifname'], 'index': h['ifindex'], 'bridge': bridge,
                              'mac': ep['MacAddress'], 'ipv4': [ep['IPAddress']] if ep['IPAddress'] else [],
                              'ipv6': [ep['GlobalIPv6Address']] if ep['GlobalIPv6Address'] else [],
                              'networks': [x['Subnet'] for x in meta['ipam']],
                              'routed': routed if meta['role'] == 'default' else []})
    networks = {ipaddress.ip_network(n) for n in protected}
    for e in endpoints:
        if any(ipaddress.ip_network(r).overlaps(n) for r in e['routed'] for n in networks if n.version == 4):
            raise Refuse('Клиентская подсеть пересекает сеть контейнеров')
    # Withhold only endpoints whose identity changed during discovery. Refusing
    # the entire snapshot here deadlocks a cold start if one crashing service
    # depends on DNS from another service that still has no allowance.
    after = {(c['id'], c['pid'], json.dumps(c['networks'], sort_keys=True)) for c in containers(root)}
    before = {(c['id'], c['pid'], json.dumps(c['networks'], sort_keys=True)) for c in cs}
    stable = {item[0] for item in before & after}
    endpoints = [e for e in endpoints if e.pop('container') in stable]
    return sorted(bridges), endpoints


def baseline(bridges, prefixes=PREFIXES):
    return ('# Управляется vpnbot-origin. Без /run снимка доступ закрыт.\n' + render(bridges, [], prefixes) +
            'include "/run/vpnbot-origin/active*.nft"\n')


def sync(cfg, locked=False):
    bridges, endpoints = inventory(cfg)
    prefixes = sorted(set(cfg.get('prefixes', PREFIXES)) | {x for e in endpoints for x in e['networks'] + e['routed']})
    rules = render(bridges, endpoints, prefixes)
    transaction = f'delete table bridge {TABLE}\n' + rules
    with contextlib.nullcontext() if locked else lock():
        # First install creates BASE without loading arbitrary host firewall.
        current = subprocess.run(['nft', '-j', 'list', 'table', 'bridge', TABLE], capture_output=True, text=True)
        if current.returncode == 0 and (RUNTIME / 'active.nft').exists():
            generation = re.search(r'comment "(origin:[a-f0-9]+)"', rules).group(1)
            tables = [o['table'] for o in json.loads(current.stdout)['nftables'] if 'table' in o]
            if (any(t.get('comment') == generation for t in tables) and
                    (RUNTIME / 'active.nft').read_text() == transaction and
                    BASE.is_file() and BASE.read_text() == baseline(bridges, prefixes)):
                return len(endpoints)
        live = transaction if current.returncode == 0 else rules
        run(['nft', '-c', '-f', '-'], live)
        write(RUNTIME / 'active.nft', transaction)
        if bridges != cfg['bridges'] or prefixes != cfg.get('prefixes'):
            cfg['bridges'] = bridges
            cfg['prefixes'] = prefixes
            write(CONFIG, json.dumps(cfg, indent=2) + '\n')
        write(BASE, baseline(bridges, prefixes), 0o600)
        run(['nft', '-f', '-'], live)
    return len(endpoints)


def load():
    cfg = json.loads(trusted(CONFIG).read_text())
    trusted(cfg['bot_dir'], True)
    if not isinstance(cfg['bridges'], list) or not set(BRIDGES) <= set(cfg['bridges']):
        raise Refuse('Неверная конфигурация origin guard')
    for b in cfg['bridges']:
        interface(b)
    return cfg


def boot():
    cfg = load()
    with lock():
        # /run must never carry allowances from a previous boot/installation.
        write(RUNTIME / 'active.nft', '')
        write(BASE, baseline(cfg['bridges'], cfg.get('prefixes', PREFIXES)))
        exists = subprocess.run(['nft', 'list', 'table', 'bridge', TABLE], capture_output=True).returncode == 0
        run(['nft', '-f', '-'], (f'delete table bridge {TABLE}\n' if exists else '') + render(cfg['bridges'], [], cfg.get('prefixes', PREFIXES)))


def watch():
    selector = selectors.DefaultSelector()
    events = None
    last_error, last_digest, last_check = '', '', 0.0
    try:
        while True:
            if events is None or events.poll() is not None:
                if events is not None:
                    selector.unregister(events.stdout)
                    events.stdout.close()
                events = subprocess.Popen(DOCKER + ['events', '--format', '{{.Type}} {{.Action}}'],
                                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                os.set_blocking(events.stdout.fileno(), False)
                selector.register(events.stdout, selectors.EVENT_READ)
            ready = selector.select(timeout=max(0, 2 - (time.monotonic() - last_check)))
            if ready:
                os.read(events.stdout.fileno(), 65536)
                time.sleep(0.05)
            try:
                cfg = load()
                count = sync(cfg)
                digest = hashlib.sha256((RUNTIME / 'active.nft').read_bytes()).hexdigest()
                if digest != last_digest or last_error:
                    print(f'Защита активна: интерфейсов {count}', flush=True)
                last_digest, last_error = digest, ''
            except (Refuse, OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
                # Existing rules stay closed to unknown veth. Do not flush on error.
                message = str(e) if isinstance(e, Refuse) else 'Ошибка сверки Docker; прежние ограничения сохранены'
                if message != last_error:
                    print(message, file=sys.stderr, flush=True)
                last_error = message
                time.sleep(0.3)
            last_check = time.monotonic()
    finally:
        if events is not None:
            events.terminate()
            try: events.wait(timeout=5)
            except subprocess.TimeoutExpired: events.kill(); events.wait()
        selector.close()


def _install(root, nft_config):
    root = str(trusted(root, True))
    trusted(nft_config)
    cfg = load() if CONFIG.exists() else {'bot_dir': root, 'bridges': list(BRIDGES)}
    if cfg['bot_dir'] != root:
        raise Refuse('Защита уже принадлежит другой установке')
    # Existing dynamic bridge names remain protected during migration.
    bridges, _ = inventory(cfg)
    cfg['bridges'] = bridges
    cfg['nft_config'] = str(nft_config)
    old = Path(nft_config).read_text()
    include = INCLUDES[0]
    included = any(x in old.splitlines() for x in INCLUDES)
    if re.search(r'\binclude\s+"[^"]*vpnbot-origin[^\"]*"', old) and not included:
        raise Refuse('Нестандартный include origin guard')
    write(CONFIG, json.dumps(cfg, indent=2) + '\n')
    write(PROGRAM, trusted(Path(__file__).resolve()).read_text(), 0o755)
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not (RUNTIME / 'active.nft').exists():
        write(RUNTIME / 'active.nft', '')
    write(BASE, baseline(bridges, cfg.get('prefixes', PREFIXES)))
    if not included:
        write(str(nft_config) + '.before-vpnbot-origin', old)
        # The include is the only modification to the user's base configuration.
        write(nft_config, old.rstrip() + '\n\n' + include + '\n')
    write(UNIT, '''[Unit]
Description=VPNBot container origin guard
After=docker.service nftables.service
Wants=docker.service
[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/sbin/vpnbot-origin watch
Restart=always
RestartSec=1
UMask=0077
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=read-only
ProtectKernelModules=yes
ReadWritePaths=/etc/vpnbot-origin /etc/nftables.d /run/vpnbot-origin
[Install]
WantedBy=multi-user.target
''', 0o644)
    # Boot rule must exist before Docker auto-restarts containers. /run allowances
    # are absent after boot; wildcard include avoids a missing-file parse failure.
    boot_unit = '''[Unit]
Description=VPNBot origin guard closed bootstrap
DefaultDependencies=no
After=local-fs.target
Before=docker.service nftables.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/sbin/vpnbot-origin boot
RemainAfterExit=yes
[Install]
RequiredBy=docker.service
'''
    write('/etc/systemd/system/vpnbot-origin-boot.service', boot_unit, 0o644)
    sync(cfg, locked=True)
    # Validate the persistent reload path in an isolated network namespace.
    # Never flush or reload the host's complete ruleset during installation.
    run(['unshare', '--net', 'nft', '-c', '-f', nft_config], timeout=120)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', 'vpnbot-origin-boot.service', 'vpnbot-origin.service'])


def install(root, nft_config):
    trusted(root, True)
    trusted(nft_config)
    with lockfile('/run/lock/vpnbot-origin-setup.lock'):
        units = ('vpnbot-origin.service', 'vpnbot-origin-boot.service')
        active = subprocess.run(['systemctl', 'is-active', '--quiet', units[0]], capture_output=True).returncode == 0
        enabled = {u: subprocess.run(['systemctl', 'is-enabled', '--quiet', u], capture_output=True).returncode == 0 for u in units}
        for unit in units:
            if run(['systemctl', 'show', '-p', 'DropInPaths', '--value', unit]).strip():
                raise Refuse('Сначала проверьте нестандартные drop-in службы ' + unit)
        paths = [CONFIG, BASE, PROGRAM, UNIT, Path('/etc/systemd/system/' + units[1]),
                 RUNTIME / 'active.nft', Path(nft_config), Path(str(nft_config) + '.before-vpnbot-origin')]
        with lock():
            snapshots = {}
            for path in paths:
                if path.exists() or path.is_symlink():
                    trusted(path)
                    snapshots[path] = (path.read_text(), stat.S_IMODE(path.stat().st_mode))
                else:
                    snapshots[path] = None
            previous = subprocess.run(['nft', 'list', 'table', 'bridge', TABLE], capture_output=True, text=True)
            # Check every destination before stopping a healthy watcher. A bad
            # symlink/owner must not leave the old installation unsupervised.
            if active:
                run(['systemctl', 'stop', units[0]])
        try:
            with lock():
                _install(root, nft_config)
            # Docker may need its boot guard, which takes the same nft lock.
            # Never wait for systemd dependencies while holding that lock.
            run(['systemctl', 'restart', units[0]])
        except BaseException:
            subprocess.run(['systemctl', 'stop', units[0]], capture_output=True)
            with lock():
                for unit in units:
                    if not enabled[unit]:
                        subprocess.run(['systemctl', 'disable', unit], capture_output=True)
                for path, saved in snapshots.items():
                    if saved is None:
                        path.unlink(missing_ok=True)
                    else:
                        write(path, *saved)
                exists = subprocess.run(['nft', 'list', 'table', 'bridge', TABLE], capture_output=True).returncode == 0
                restore = (f'delete table bridge {TABLE}\n' if exists else '')
                if previous.returncode == 0:
                    restore += previous.stdout
                if restore:
                    run(['nft', '-f', '-'], restore)
                run(['systemctl', 'daemon-reload'])
            if active:
                run(['systemctl', 'start', units[0]])
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'sync', 'watch', 'boot', 'check'))
    parser.add_argument('--bot-dir', type=Path, default=Path.cwd())
    parser.add_argument('--nft-config', type=Path, default=Path('/etc/nftables.conf'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise Refuse('Требуется root')
    if args.action == 'install':
        def interrupted(signum, frame):
            raise Refuse('Установка прервана; восстанавливается прежняя конфигурация')
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, interrupted)
    if args.action == 'install': install(args.bot_dir, args.nft_config)
    elif args.action == 'watch': watch()
    elif args.action == 'boot': boot()
    elif args.action == 'sync': print('Интерфейсов:', sync(load()))
    else:
        cfg = load()
        if cfg['bot_dir'] != str(args.bot_dir.resolve()):
            raise Refuse('Защита принадлежит другой установке')
        if not any(x in trusted(cfg['nft_config']).read_text().splitlines() for x in INCLUDES):
            raise Refuse('В основном firewall отсутствует include защиты')
        bridges, endpoints = inventory(cfg)
        run(['nft', '-c', '-f', '-'], f'delete table bridge {TABLE}\n' + render(bridges, endpoints, cfg.get('prefixes', PREFIXES)))
        print('Конфигурация и соответствия интерфейсов проверены')


if __name__ == '__main__':
    try:
        main()
    except (Refuse, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('[ОТКАЗ] ' + (str(error) if isinstance(error, Refuse) else 'Не удалось проверить origin guard'), file=sys.stderr)
        sys.exit(1)
