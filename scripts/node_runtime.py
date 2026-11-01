#!/usr/bin/env python3
"""Host operations for the minimal node. No caller-supplied commands or paths."""
import base64
import json
import os
from pathlib import Path
import socket
import re
import subprocess
import time
import uuid

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


def command(args, *, data=None, timeout=30, required=True):
    result = subprocess.run(list(map(str, args)), input=data, capture_output=True, timeout=timeout,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'GODEBUG': 'multipathtcp=0'})
    if required and result.returncode:
        # Commands may mention credentials, certificates or private URLs.
        raise RuntimeError('node host operation failed')
    return result


class Runtime:
    def __init__(self, store, host, guard=Path('/etc/vpnbot-node/guard.nft')):
        self.store, self.host, self.guard = store, config.deployment(host), Path(guard)

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
        directory = self.store.path(generation)/'runtime/core'
        body = config.core_config(value['options'], self.host, value['identity'], value['peers'])
        files = {'xray.json': state.encode(body)}
        certificates = {name: base64.b64decode(encoded, validate=True) for name, encoded in value['tls'].items()}
        if value['options'].get('cover'):
            cover = self.store.path(generation)/'runtime/cover'
            self.write_runtime(cover, certificates | {
                'nginx.conf': node_cover.nginx(value['options'], value['identity'], bool(self.host['public6'])).encode(),
                'htpasswd': ('admin:'+value['identity']['cover_auth']+'\n').encode()})
            self.write_runtime(cover/'site', {'index.html': b'<!doctype html><title>Restricted Content</title><p>Restricted Content</p>\n'})
            self.check_certificate(cover, value['options']['domain'])
        elif config.needs_certificate(value['options']):
            files.update(certificates)
        self.write_runtime(directory, files)
        if value['options'].get('amnezia', {}).get('enabled'):
            self.write_runtime(self.store.path(generation)/'runtime/amnezia', {
                'carrier.conf': node_awg.server(value['options']['amnezia'], value['identity']['amnezia']).encode()})
        if config.needs_certificate(value['options']) and not value['options'].get('cover'):
            self.check_certificate(directory, value['options']['domain'])
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
                '--entrypoint', '/usr/sbin/nginx', value['images']['ng']]

    def validate(self, generation):
        self.prepare(generation)
        command(['docker', 'run', '--rm', *self.docker_arguments(generation), 'run', '-test', '-c', '/node/xray.json'], timeout=30)
        if self.store.load(generation)['options'].get('cover'):
            command(['docker', 'run', '--rm', *self.cover_arguments(generation), '-t', '-c', '/node/nginx.conf'])
        if self.store.load(generation)['options'].get('amnezia', {}).get('enabled'):
            command(['docker', 'run', '--rm', *self.amnezia_arguments(generation), '-n', '-c', '/node/carrier.conf'])
        rules = config.firewall(self.store.load(generation)['options'], self.host)
        command(['nft', '-c', '-f', '-'], data=self.transaction(rules).encode())

    def transaction(self, rules):
        exists = command(['nft', 'list', 'table', 'inet', 'vpnbot_node'], required=False).returncode == 0
        return ('delete table inet vpnbot_node\n' if exists else '') + rules

    def apply(self, generation):
        value = self.store.load(generation)
        self.prepare(generation)
        self.container()
        self.container(COVER_CONTAINER)
        self.container(AWG_CONTAINER)
        rules = config.firewall(value['options'], self.host)
        transaction = self.transaction(rules)
        command(['nft', '-c', '-f', '-'], data=transaction.encode())
        state.atomic(self.guard, rules.encode())
        command(['nft', '-f', '-'], data=transaction.encode())
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

    def certificate(self, domain):
        domain = config.hostname(domain)
        answers = {answer[4][0] for answer in socket.getaddrinfo(domain, 80, type=socket.SOCK_STREAM)}
        if not answers or not answers <= {self.host['public4'], self.host['public6']}:
            raise ValueError('domain DNS must point only to this node')
        root = self.store.root/'acme'
        state.trusted(root)
        root.mkdir(mode=0o700, exist_ok=True)
        command(['nft', 'add', 'element', 'inet', 'vpnbot_node', 'acme_http', '{ 80 timeout 10m }'])
        try:
            command(['certbot', 'certonly', '--config', '/dev/null', '--non-interactive', '--agree-tos',
                     '--register-unsafely-without-email', '--standalone', '--preferred-challenges', 'http',
                     '--http-01-port', '8080', '--keep-until-expiring', '--cert-name', 'vpnbot-node',
                     '--config-dir', root/'config', '--work-dir', root/'work', '--logs-dir', root/'logs',
                     '-d', domain], timeout=300)
        finally:
            command(['nft', 'delete', 'element', 'inet', 'vpnbot_node', 'acme_http', '{ 80 }'], required=False)
        # Certbot owns its symlinks; export only the two fixed PEM files from this isolated ACME directory.
        live = root/'config/live/vpnbot-node'
        return {name: base64.b64encode((live/name).read_bytes()).decode() for name in ('fullchain.pem', 'privkey.pem')}

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

    def status(self):
        info = self.container()
        value = self.store.load()
        cover = self.container(COVER_CONTAINER) if value['options'].get('cover') else None
        running = bool(info and info.get('State', {}).get('Running'))
        if value['options'].get('cover'):
            running = running and bool(cover and cover.get('State', {}).get('Running'))
        if value['options'].get('amnezia', {}).get('enabled'):
            helper = self.container(AWG_CONTAINER)
            running = running and bool(helper and helper.get('State', {}).get('Running'))
        options = dict(value['options'])
        options['xray'] = node_xray.settings(options.get('xray', {}), options['core'], options['transport'])
        options.setdefault('cover', False)
        options.setdefault('connect_family', 4 if self.host['public4'] else 6)
        return {'running': running,
                'options': options, 'public4': self.host['public4'], 'public6': self.host['public6'],
                'sources': self.host['sources'], 'peers': value['peers'], 'generation': self.store.current(),
                'pending': self.store.pending()}
