#!/usr/bin/env python3
"""Host operations for the minimal node. No caller-supplied commands or paths."""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import ipaddress
import re
import subprocess
import time
import uuid
from email.utils import parsedate_to_datetime

import node_config as config
import node_state as state
import node_xray
import node_cover
import node_wg
import node_awg


CONTAINER = 'vpnbot-node-xray'
COVER_CONTAINER = 'vpnbot-node-cover'
AWG_CONTAINER = 'vpnbot-node-amnezia'
LABEL = 'org.vpnbot.managed-node'


HOST_PROGRAMS = {'docker', 'sysctl', 'systemctl', 'nft', 'ip', 'ss', 'sshd',
                 'useradd', 'usermod', 'openssl', 'certbot', 'ssh-keygen', 'visudo'}


def host_program(value):
    # Never expose a command line, a path or an unknown executable name.
    return value if isinstance(value, str) and value in HOST_PROGRAMS else 'системная команда'


class HostOperationError(RuntimeError):
    """Only allowlisted metadata survives a failed subprocess."""
    def __init__(self, program, returncode, stderr=b''):
        super().__init__('node host operation failed')
        self.program = host_program(program)
        self.returncode = returncode if type(returncode) is int else None
        self.category = 'command_failed'
        lowered = stderr.lower()
        for category, markers in (
                ('disk_full', (b'no space left on device',)),
                ('permission', (b'permission denied', b'operation not permitted')),
                ('timeout', (b'timed out', b'timeout', b'deadline exceeded')),
                ('dns', (b'could not resolve', b'no such host', b'temporary failure in name resolution')),
                ('tls', (b'certificate verify failed', b'certificate signed by unknown authority', b'tls handshake')),
                ('port_busy', (b'address already in use', b'could not bind'))):
            if any(marker in lowered for marker in markers):
                self.category = category
                break
        if self.category == 'command_failed' and program == 'sysctl' and b'cannot stat' in lowered:
            self.category = 'missing_sysctl'
        if self.category == 'command_failed' and program == 'docker' \
                and any(marker in lowered for marker in (b'unauthorized', b'authentication required', b'pull access denied')):
            self.category = 'registry_auth'
        if self.category == 'command_failed' and program == 'certbot' \
                and any(marker in lowered for marker in (b'challenge failed', b'failed to authenticate', b'some challenges have failed')):
            self.category = 'acme_validation'


def command(args, *, data=None, timeout=30, required=True):
    result = subprocess.run(list(map(str, args)), input=data, capture_output=True, timeout=timeout,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'GODEBUG': 'multipathtcp=0'})
    if required and result.returncode:
        # Commands may mention credentials, certificates or private URLs.
        raise HostOperationError(str(args[0]), result.returncode, result.stderr)
    return result


class Runtime:
    def __init__(self, store, host, guard=Path('/etc/vpnbot-node/guard.nft')):
        self.store, self.host, self.guard = store, config.deployment(host), Path(guard)

    def routed_host(self):
        """Deployment plus the WAN segment: its on-link networks and gateways.

        Public neighbours and the provider's router are a local network of the
        node; VPN clients must not reach them through the core's UID."""
        networks = set()
        for version in (4, 6):
            result = command(['ip', '-j', '-'+str(version), 'route', 'show', 'dev', self.host['interface']], required=False)
            for route in (json.loads(result.stdout or b'[]') if not result.returncode else []):
                gateway, target = route.get('gateway'), route.get('dst', '')
                if gateway:
                    networks.add(ipaddress.ip_network(gateway))
                elif target != 'default':
                    networks.add(ipaddress.ip_network(target, strict=False))
        # A very short prefix would be a misconfiguration, not a local segment.
        keep = [str(net) for net in networks if net.is_global and net.prefixlen >= (16 if net.version == 4 else 32)]
        return self.host | {'onlink': keep}

    def tls_probe(self):
        """Probe only the committed target; never accept an arbitrary URL/IP."""
        value = self.store.load()
        options = value['options']
        own = bool(options.get('cover')) or options['transport'] != 'reality'
        name = options['domain'] if own else options['mask']
        config.hostname(name)
        family = options['family']
        if own:
            # Probe the ordinary, unauthenticated TLS path. REALITY itself
            # supplies any configured PROXY header to the loopback cover.
            address, port = ('127.0.0.1' if self.host['public4'] else '::1'), 8443
        else:
            answers = {entry[4][0] for entry in socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)}
            denied = [ipaddress.ip_network(net) for net in config.PRIVATE4 + config.PRIVATE6]
            for address in answers:
                config.public_ip(address)
                ip = ipaddress.ip_address(address)
                if address in (self.host['public4'], self.host['public6']) or any(ip in net for net in denied):
                    raise ValueError('TLS probe target is not public')
            eligible = sorted(address for address in answers if ipaddress.ip_address(address).version == family)
            if not eligible:
                raise ValueError('TLS probe address family unavailable')
            address, port = eligible[0], 443
        result = self.probe_tls(address, port, name, None if own else self.host['public'+str(family)])
        return result | {'name': name, 'own': own, 'transport': options['transport'], 'time': int(time.time())}

    @staticmethod
    def probe_tls(address, port, name, source=None):
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['h2', 'http/1.1'])
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        session = context.wrap_bio(incoming, outgoing, server_hostname=name)
        pending, total, record = b'', 0, 0
        deadline = time.monotonic()+8
        # Connect to the validated literal: DNS is never resolved a second time.
        with socket.create_connection((address, port), timeout=4, source_address=(source, 0) if source else None) as connection:
            while True:
                try:
                    session.do_handshake()
                    remaining = deadline-time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('TLS probe timed out')
                    connection.settimeout(remaining)
                    # TLS 1.3 can finish locally with Client Finished still
                    # buffered in the BIO. Deliver it before closing the socket.
                    connection.sendall(outgoing.read())
                    return {'tls': session.version(), 'alpn': session.selected_alpn_protocol() or '', 'record': record}
                except ssl.SSLWantReadError:
                    remaining = deadline-time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('TLS probe timed out')
                    connection.settimeout(remaining)
                    connection.sendall(outgoing.read())
                    data = connection.recv(16384)
                    total += len(data)
                    if not data or total > 65536:
                        raise ValueError('TLS probe response exceeds bounds')
                    pending += data
                    while len(pending) >= 5:
                        size = int.from_bytes(pending[3:5], 'big')
                        if size > 18432:
                            raise ValueError('TLS record exceeds bounds')
                        if len(pending) < size+5:
                            break
                        if pending[0] == 23 and not record:
                            record = size
                        pending = pending[size+5:]
                    incoming.write(data)

    def identity(self, image):
        result = self.core_command(image, 'origin', 'x25519')
        fields = {key.strip().lower().replace(' ', ''): value.strip() for key, value in
                  (line.split(':', 1) for line in result.stdout.decode().splitlines() if ':' in line)}
        return config.identity(dict(uuid=str(uuid.uuid4()), private=fields.get('privatekey'),
            public=fields.get('password(publickey)') or fields.get('password') or fields.get('publickey'),
            short_id=os.urandom(8).hex(), path=os.urandom(16).hex()))

    def core_command(self, image, core, action):
        if action not in ('x25519', 'mldsa65', 'vlessenc', 'version'):
            raise ValueError('unsupported core operation')
        return command(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                        '--security-opt', 'no-new-privileges', '--user', '65534:65534',
                        '--memory', '128m', '--pids-limit', '64', '--env', 'GODEBUG=multipathtcp=0',
                        '--entrypoint', config.CORES[core], image, action])

    def ensure_keys(self, value, rotate=None):
        options, keys = value['options'], value['identity']
        advanced = node_xray.settings(options.get('xray', {}), options['core'], options['transport'])
        enabled = {'encryption': advanced['encryption']['auth'] != 'off', 'mldsa': advanced['reality']['mldsa'],
                   'wireguard': options.get('wireguard', {}).get('enabled'), 'amnezia': options.get('amnezia', {}).get('enabled')}
        if rotate in enabled and not enabled[rotate]:
            raise ValueError('rotation target is disabled')
        if options.get('wireguard', {}).get('enabled') and (rotate == 'wireguard' or 'wireguard' not in keys):
            keys['wireguard'] = node_wg.generate(lambda: self.identity(value['images']['xr']))
        if options.get('amnezia', {}).get('enabled') and (rotate == 'amnezia' or 'amnezia' not in keys):
            keys['amnezia'] = node_awg.generate(lambda: self.identity(value['images']['xr']))
        advanced = node_xray.settings(options.get('xray', {}), options['core'], options['transport'])
        auth = advanced['encryption']['auth']
        if auth != 'off' and (rotate == 'encryption' or keys.get('encryption', {}).get('auth') != auth):
            output = self.core_command(value['images']['xr'], options['core'], 'vlessenc').stdout.decode()
            keys['encryption'] = node_xray.parse_encryption_output(output, auth)
        if advanced['reality']['mldsa'] and (rotate == 'mldsa' or 'mldsa' not in keys):
            output = self.core_command(value['images']['xr'], options['core'], 'mldsa65').stdout.decode()
            fields = {key.lower(): item for key, item in re.findall(r'^(Seed|Verify):\s*(\S+)', output, re.M | re.I)}
            keys['mldsa'] = node_xray.mldsa_identity(fields)
        if rotate == 'reality':
            generated = self.identity(value['images']['xr'])
            for field in ('private', 'public', 'short_id'):
                keys[field] = generated[field]
        if options.get('cover') and 'cover_auth' not in keys:
            # Only the hash survives. No password in argv, state, logs or RPC.
            password = base64.urlsafe_b64encode(os.urandom(48))+b'\n'
            keys['cover_auth'] = node_cover.password_hash(command(['openssl', 'passwd', '-6', '-stdin'], data=password).stdout.decode().strip())

    def ensure_external_keys(self, value):
        keys=value['identity']
        old=keys.get('external',{})
        peers=[peer for peer in config.peers(value['peers']) if peer.get('channel','vless') != 'vless']
        retained={peer['id']:old[peer['id']] for peer in peers if peer['id'] in old and old[peer['id']]['channel']==peer['channel']}
        used={entry['slot'] for entry in retained.values()}
        for peer in peers:
            if peer['id'] in retained: continue
            slot=next(n for n in range(1,33) if n not in used)
            used.add(slot)
            pair=self.identity(value['images']['xr'])
            retained[peer['id']]={'slot':slot,'channel':peer['channel'],
                **{name:base64.b64encode(base64.urlsafe_b64decode(pair[name]+'=')).decode() for name in ('private','public')},
                'psk':base64.b64encode(os.urandom(32)).decode()}
        if retained: keys['external']=config.node_wg.external(retained)
        else: keys.pop('external',None)

    def ensure_images(self, value):
        if value['options'].get('cover') and 'ng' not in value['images']:
            from image_bundle import fetch, read
            path = self.store.root/'release.json'
            if not path.exists():
                fetch('latest', path)
            value['images']['ng'] = read(path)['images']['ng']
        for image in value['images'].values():
            self.pull(image)

    def pull(self, image):
        # The image passed here has already been validated by snapshot().
        # A digest is immutable. Existing installations must remain manageable
        # when the registry is unavailable, including backup/rollback operations.
        if command(['docker', 'image', 'inspect', image], required=False).returncode:
            command(['docker', 'pull', image], timeout=300)

    def container(self, name=CONTAINER):
        if name not in (CONTAINER, COVER_CONTAINER, AWG_CONTAINER):
            raise ValueError('unsupported container')
        result = command(['docker', 'inspect', '--format', '{{json .}}', name], required=False)
        if result.returncode:
            return None
        info = json.loads(result.stdout)
        if info.get('Config', {}).get('Labels', {}).get(LABEL) != '1':
            raise RuntimeError('container name belongs to another installation')
        return info

    def stop(self):
        # Check ownership of every name before removing any container.
        existing = [name for name in (CONTAINER, COVER_CONTAINER, AWG_CONTAINER) if self.container(name) is not None]
        for name in existing:
            command(['docker', 'rm', '-f', name])

    def write_runtime(self, directory, files):
        state.trusted(directory)
        directory.mkdir(mode=0o750, parents=True, exist_ok=True)
        os.chown(directory, 0, self.host['gid'])
        os.chmod(directory, 0o750)
        for name, data in files.items():
            path = directory/name
            state.atomic(path, data, 0o640)
            os.chown(path, 0, self.host['gid'])

    def prepare(self, generation):
        value = self.store.load(generation)
        # Reject an unavailable bot-to-node address before any stop/apply.
        config.endpoint(value['options'], self.host)
        directory = self.store.path(generation)/'runtime/core'
        body = config.core_config(value['options'], self.routed_host(), value['identity'], value['peers'])
        files = {'xray.json': state.encode(body)}
        certificates = {name: base64.b64decode(encoded, validate=True) for name, encoded in value['tls'].items()}
        if value['options'].get('cover'):
            cover = self.store.path(generation)/'runtime/cover'
            self.write_runtime(cover, certificates | {
                'nginx.conf': node_cover.nginx(value['options'], value['identity'], bool(self.host['public6'])).encode(),
                'htpasswd': ('admin:'+value['identity']['cover_auth']+'\n').encode()})
            self.write_runtime(cover/'site', {'index.html': b'<!doctype html><title>Restricted Content</title><p>Restricted Content</p>\n'})
            for name in [value['options']['domain'], *value['options'].get('domain_aliases', [])]:
                self.check_certificate(cover, name)
        elif config.needs_certificate(value['options']):
            files.update(certificates)
        self.write_runtime(directory, files)
        if value['options'].get('amnezia', {}).get('enabled'):
            self.write_runtime(self.store.path(generation)/'runtime/amnezia', {
                'carrier.conf': node_awg.server(value['options']['amnezia'], value['identity']['amnezia'], config.external_peers(value['identity'],value['peers'],'amnezia')).encode()})
        if config.needs_certificate(value['options']) and not value['options'].get('cover'):
            for name in [value['options']['domain'], *value['options'].get('domain_aliases', [])]:
                self.check_certificate(directory, name)
        return directory

    def check_certificate(self, directory, domain):
        certificate = directory/'fullchain.pem'
        key = directory/'privkey.pem'
        command(['openssl', 'x509', '-in', certificate, '-noout', '-checkend', '3600'])
        # x509 -checkhost prints a mismatch but can still exit successfully.
        # Verify enforces hostname, validity dates and server certificate usage.
        # Trust this supplied leaf here; public client trust is checked separately.
        command(['openssl', 'verify', '-partial_chain', '-trusted', certificate,
                 '-verify_hostname', domain, '-purpose', 'sslserver', certificate])
        public = command(['openssl', 'x509', '-in', certificate, '-pubkey', '-noout']).stdout
        expected = command(['openssl', 'pkey', '-pubin', '-outform', 'DER'], data=public).stdout
        actual = command(['openssl', 'pkey', '-in', key, '-pubout', '-outform', 'DER']).stdout
        if expected != actual:
            raise ValueError('certificate and private key do not match')

    def docker_arguments(self, generation):
        value = self.store.load(generation)
        directory = self.store.path(generation)/'runtime/core'
        # REALITY's target dialer uses the OS resolver. A host-local stub such
        # as 127.0.0.53 is deliberately unreachable by the core's UID guard.
        # Keep that guard intact and provide public resolvers of the chosen
        # egress family, matching core_config's built-in DNS.
        resolvers = ['1.1.1.1', '9.9.9.9'] if value['options']['family'] == 4 else ['2606:4700:4700::1111', '2620:fe::fe']
        return ['--network', 'host', '--user', f"{self.host['uid']}:{self.host['gid']}",
                *[arg for resolver in resolvers for arg in ('--dns', resolver)],
                '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '--pids-limit', '128', '--memory', '384m', '--memory-swap', '384m',
                '--env', 'GODEBUG=multipathtcp=0', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=8m',
                '--mount', f'type=bind,src={directory},dst=/node,readonly',
                '--entrypoint', config.CORES[value['options']['core']], value['images']['xr']]

    def cover_arguments(self, generation):
        value = self.store.load(generation)
        directory = self.store.path(generation)/'runtime/cover'
        return ['--network', 'host', '--user', f"{self.host['cover_uid']}:{self.host['gid']}",
                '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '--pids-limit', '64', '--memory', '96m', '--memory-swap', '96m',
                '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=32m',
                '--mount', f'type=bind,src={directory},dst=/node,readonly',
                # -e: the read-only image cannot open the compiled-in error log
                # before /node/nginx.conf is read; that printed an alert each start.
                '--entrypoint', '/usr/sbin/nginx', value['images']['ng'], '-e', 'stderr']

    def validate(self, generation):
        self.prepare(generation)
        command(['docker', 'run', '--rm', *self.docker_arguments(generation), 'run', '-test', '-c', '/node/xray.json'], timeout=30)
        if self.store.load(generation)['options'].get('cover'):
            command(['docker', 'run', '--rm', *self.cover_arguments(generation), '-t', '-c', '/node/nginx.conf'])
        if self.store.load(generation)['options'].get('amnezia', {}).get('enabled'):
            command(['docker', 'run', '--rm', *self.amnezia_arguments(generation), '-n', '-c', '/node/carrier.conf'])
        rules = config.firewall(self.store.load(generation)['options'], self.routed_host())
        command(['nft', '-c', '-f', '-'], data=self.transaction(rules).encode())

    def transaction(self, rules):
        exists = command(['nft', 'list', 'table', 'inet', 'vpnbot_node'], required=False).returncode == 0
        return ('delete table inet vpnbot_node\n' if exists else '') + rules

    def load_firewall(self, generation=None):
        """Build the guard from a generation with the installed code; check, persist, load atomically."""
        rules = config.firewall(self.store.load(generation)['options'], self.routed_host())
        transaction = self.transaction(rules)
        command(['nft', '-c', '-f', '-'], data=transaction.encode())
        state.atomic(self.guard, rules.encode())
        command(['nft', '-f', '-'], data=transaction.encode())

    def apply(self, generation):
        value = self.store.load(generation)
        self.prepare(generation)
        self.container()
        self.container(COVER_CONTAINER)
        self.container(AWG_CONTAINER)
        self.load_firewall(generation)
        self.stop()
        command(['docker', 'run', '-d', '--name', CONTAINER, '--label', LABEL+'=1',
                 '--restart', 'no', '--log-driver', 'local', '--log-opt', 'max-size=1m', '--log-opt', 'max-file=2',
                 *self.docker_arguments(generation), 'run', '-c', '/node/xray.json'])
        if value['options'].get('cover'):
            command(['docker', 'run', '-d', '--name', COVER_CONTAINER, '--label', LABEL+'=1',
                     '--restart', 'no', '--log-driver', 'local', '--log-opt', 'max-size=1m', '--log-opt', 'max-file=2',
                     *self.cover_arguments(generation), '-c', '/node/nginx.conf', '-g', 'daemon off;'])
        if value['options'].get('amnezia', {}).get('enabled'):
            command(['docker', 'run', '-d', '--name', AWG_CONTAINER, '--label', LABEL+'=1',
                     '--restart', 'no', '--log-driver', 'none', *self.amnezia_arguments(generation),
                     '-c', '/node/carrier.conf', '-s'])
        options = value['options']
        core_port = 9444 if options.get('cover') and options['transport'] != 'reality' else 8443
        listeners = [('127.0.0.1' if self.host['public4'] or core_port == 9444 else '::1', core_port)]
        if options.get('cover'):
            listeners.append(('127.0.0.1', 9443 if options['transport'] == 'reality' else 8443))
        for _ in range(30):
            info = self.container()
            if not info or not info.get('State', {}).get('Running'):
                raise RuntimeError('node core failed to start')
            if value['options'].get('amnezia', {}).get('enabled'):
                helper = self.container(AWG_CONTAINER)
                if not helper or not helper.get('State', {}).get('Running'):
                    raise RuntimeError('node Amnezia carrier failed to start')
            try:
                for address, port in listeners:
                    with socket.create_connection((address, port), timeout=.2):
                        pass
                return
            except OSError:
                time.sleep(.2)
        raise RuntimeError('node listener did not become ready')

    def certificate(self, domain, aliases=(), *, force=False):
        domain = config.hostname(domain)
        if not isinstance(aliases, (list, tuple)) or len(aliases) > 12:
            raise ValueError('invalid additional certificate names')
        names = list(dict.fromkeys([domain, *(config.hostname(name) for name in aliases)]))
        for name in names:
            answers = {answer[4][0] for answer in socket.getaddrinfo(name, 80, type=socket.SOCK_STREAM)}
            if not answers or not answers <= {self.host['public4'], self.host['public6']}:
                raise ValueError('domain DNS must point only to this node')
        root = self.store.root/'acme'
        state.trusted(root)
        root.mkdir(mode=0o700, exist_ok=True)
        command(['nft', 'add', 'element', 'inet', 'vpnbot_node', 'acme_http', '{ 80 timeout 10m }'])
        try:
            command(['certbot', 'certonly', '--config', '/dev/null', '--non-interactive', '--agree-tos',
                     '--register-unsafely-without-email', '--standalone', '--preferred-challenges', 'http',
                     '--http-01-port', '8080', '--force-renewal' if force else '--keep-until-expiring', '--cert-name', 'vpnbot-node',
                     '--config-dir', root/'config', '--work-dir', root/'work', '--logs-dir', root/'logs',
                     *[arg for name in names for arg in ('-d', name)]], timeout=300)
        finally:
            command(['nft', 'delete', 'element', 'inet', 'vpnbot_node', 'acme_http', '{ 80 }'], required=False)
        # Certbot owns its symlinks; export only the two fixed PEM files from this isolated ACME directory.
        live = root/'config/live/vpnbot-node'
        return {name: base64.b64encode((live/name).read_bytes()).decode() for name in ('fullchain.pem', 'privkey.pem')}

    def delete_certificate(self):
        # The manager rejects this while TLS or the cover is in use. Historical
        # snapshots retain their certificate so rollback/restore remain possible.
        root = self.store.root/'acme'
        state.trusted(root)
        if not (root/'config/renewal/vpnbot-node.conf').exists():
            return
        command(['certbot', 'delete', '--config', '/dev/null', '--non-interactive',
                 '--cert-name', 'vpnbot-node', '--config-dir', root/'config',
                 '--work-dir', root/'work', '--logs-dir', root/'logs'], timeout=60)
        if (root/'config/renewal/vpnbot-node.conf').exists():
            raise RuntimeError('certificate registration was not removed')

    def amnezia_arguments(self, generation):
        value = self.store.load(generation)
        directory = self.store.path(generation)/'runtime/amnezia'
        return ['--network', 'host', '--user', f"{self.host['awg_uid']}:{self.host['gid']}",
                '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '--pids-limit', '64', '--memory', '128m', '--memory-swap', '128m',
                '--ulimit', 'nofile=512:512', '--env', 'GODEBUG=multipathtcp=0',
                '--env', 'GOMEMLIMIT=80MiB', '--env', 'GOMAXPROCS=2',
                '--mount', f'type=bind,src={directory},dst=/node,readonly',
                '--entrypoint', '/usr/bin/wireproxy-node', value['images']['xr']]

    def running(self, value=None, info=None):
        """Container state only: the 15-second watch needs no status metadata."""
        value = self.store.load() if value is None else value
        info = self.container() if info is None else info
        cover = self.container(COVER_CONTAINER) if value['options'].get('cover') else None
        running = bool(info and info.get('State', {}).get('Running'))
        if value['options'].get('cover'):
            running = running and bool(cover and cover.get('State', {}).get('Running'))
        if value['options'].get('amnezia', {}).get('enabled'):
            helper = self.container(AWG_CONTAINER)
            running = running and bool(helper and helper.get('State', {}).get('Running'))
        return running

    def status(self):
        info = self.container()
        value = self.store.load()
        running = self.running(value, info or {})
        options = dict(value['options'])
        options['xray'] = node_xray.settings(options.get('xray', {}), options['core'], options['transport'])
        options['wireguard'] = config.node_wg.settings(options.get('wireguard', {}))
        options['amnezia'] = config.node_awg.settings(options.get('amnezia', {}))
        if 'amnezia' in value['identity']:
            options['amnezia']['parameters'] = {k:v for k,v in config.node_awg.effective(options['amnezia'], value['identity']['amnezia']).items() if k != 'HeaderProtectionKey'}
        options.setdefault('domain_aliases', [])
        options.setdefault('cover', False)
        options.setdefault('connect_family', 4 if self.host['public4'] else 6)
        return {'running': running,
                'options': options, 'public4': self.host['public4'], 'public6': self.host['public6'],
                'sources': self.host['sources'], 'peers': value['peers'], 'generation': self.store.current(),
                'pending': self.store.pending(), 'cores': self.core_versions(info),
                'certificate': self.certificate_summary(value['tls'])}

    def core_versions(self, info):
        versions = {}
        if not info or not info.get('State', {}).get('Running'):
            return versions
        # Binaries change only with a new container: the per-minute status RPC
        # reuses the versions of this exact container start instead of 4 execs.
        root = getattr(self.store, 'root', None)
        started = info.get('Id'), info.get('State', {}).get('StartedAt')
        cache = root/'core-versions.json' if isinstance(root, Path) and all(isinstance(v, str) and v for v in started) else None
        if cache is not None:
            try:
                saved = self.store.read(cache.name)
            except ValueError:
                saved = None
            if isinstance(saved, dict) and saved.get('container') == list(started) and isinstance(saved.get('versions'), dict) \
                    and set(saved['versions']) == set(config.CORES) \
                    and all(isinstance(v, str) and re.fullmatch(r'[0-9][A-Za-z0-9.+_-]{0,47}', v) for v in saved['versions'].values()):
                return dict(saved['versions'])
        for core, binary in config.CORES.items():
            try:
                result = command(['docker', 'exec', CONTAINER, binary, 'version'], timeout=1, required=False)
            except TimeoutError:
                raise  # The RPC deadline must not be swallowed as optional metadata.
            except (subprocess.TimeoutExpired, OSError):
                continue
            match = re.match(rb'Xray\s+v?([0-9][A-Za-z0-9.+_-]{0,47})\s', result.stdout)
            if result.returncode == 0 and match:
                versions[core] = match[1].decode('ascii')
        # Only a complete answer is reused; a timeout is retried next time.
        if cache is not None and set(versions) == set(config.CORES):
            try:
                state.atomic(cache, state.encode({'container': list(started), 'versions': versions}))
            except (OSError, ValueError):
                pass
        return versions

    def certificate_summary(self, tls):
        if 'fullchain.pem' not in tls:
            return {}
        # Inspect only the public certificate, never the private key.
        try:
            result = command(['openssl', 'x509', '-noout', '-enddate', '-ext', 'subjectAltName'],
                             data=base64.b64decode(tls['fullchain.pem'], validate=True), timeout=3, required=False)
        except TimeoutError:
            raise
        except (ValueError, subprocess.TimeoutExpired, OSError):
            return {}
        if result.returncode:
            return {}
        text = result.stdout.decode('ascii', errors='replace')
        expiry = re.search(r'^notAfter=(.+)$', text, re.M)
        try:
            expires = int(parsedate_to_datetime(expiry[1]).timestamp()) if expiry else 0
        except (ValueError, TypeError, OverflowError):
            return {}
        domains = []
        for name in re.findall(r'DNS:([^,\s]+)', text):
            try:
                domains.append(config.hostname(name))
            except ValueError:
                continue
        return {'expires': expires, 'domains': list(dict.fromkeys(domains))[:32],
                'fingerprint': hashlib.sha256(base64.b64decode(tls['fullchain.pem'], validate=True)).hexdigest()}
