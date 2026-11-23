#!/usr/bin/env python3
"""Restricted SSH RPC and serialized node maintenance jobs (root only)."""
import copy
import fcntl
import hashlib
import base64
import ipaddress
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import sys
import time
import uuid

# Installed files and their parents are root-owned; -I ignores Python environment.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import node_config as config
import node_state as state
from node_runtime import Runtime, command

ROOT = Path('/var/lib/vpnbot-node')
DEPLOYMENT = Path('/etc/vpnbot-node/deployment.json')
OPERATIONS = ('configure', 'peers', 'rotate', 'restart', 'rollback', 'restore', 'update', 'upgrade', 'renew', 'renew_force', 'certificate_delete')
# Full update: vpnbot-node-upgrade.service installs the code, then the worker the images.
UPGRADE_UNIT = 'vpnbot-node-upgrade.service'


# Node card in the main bot: values read from the kernel at status time. A
# source that cannot be read is omitted; nothing is estimated or cached.
PROC = Path('/proc')
# nftables redirects TCP/443 of the permitted servers to this listener.
VPN_TCP_PORT = 8443
UDP_PORTS = (51820, 51821)
CONNTRACK_LIMIT = 8 * 1024 * 1024


def proc_address(value):
    """Address in /proc/net/tcp{,6} hex form; an IPv4-mapped IPv6 as IPv4."""
    raw = bytes.fromhex(value)
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw[::-1]))
    if len(raw) != 16:
        raise ValueError('address')
    address = ipaddress.IPv6Address(b''.join(raw[i:i+4][::-1] for i in range(0, 16, 4)))
    return str(address.ipv4_mapped or address)


def tcp_connections(proc=PROC, port=VPN_TCP_PORT):
    """Established TCP connections to the VPN listener now, per remote address."""
    counts, readable = {}, False
    for name in ('tcp', 'tcp6'):
        try:
            lines = (proc/'net'/name).read_text().splitlines()[1:]
        except OSError:
            continue
        readable = True
        for line in lines:
            fields = line.split()
            try:
                if len(fields) < 4 or fields[3] != '01' or int(fields[1].rsplit(':', 1)[1], 16) != port:
                    continue
                address = proc_address(fields[2].rsplit(':', 1)[0])
            except (ValueError, IndexError):
                continue
            counts[address] = counts.get(address, 0) + 1
    return counts if readable else None


def udp_peers(proc=PROC, ports=UDP_PORTS):
    """Sources of UDP flows to WireGuard/AmneziaWG that the node answered.

    conntrack keeps such a flow for about two minutes after the last packet."""
    try:
        with (proc/'net'/'nf_conntrack').open('rb') as stream:
            data = stream.read(CONNTRACK_LIMIT + 1)
    except OSError:
        return None
    if len(data) > CONNTRACK_LIMIT:
        return None
    result = set()
    for line in data.decode('ascii', 'replace').splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[2] != 'udp' or '[UNREPLIED]' in fields:
            continue
        values = {}
        for field in fields:
            name, mark, value = field.partition('=')
            if mark:
                values.setdefault(name, value)  # the first tuple is the original direction
        try:
            if int(values.get('dport', '')) in ports:
                result.add(str(ipaddress.ip_address(values['src'])))
        except (KeyError, ValueError):
            continue
    return result


def connections(sources, vpn_sources, proc=PROC):
    """Permitted servers (main bot, VPN-only sources) and their live connections."""
    tcp, udp = tcp_connections(proc), udp_peers(proc)
    servers, known = [], set()
    for role, addresses in (('main', sources), ('vpn', vpn_sources)):
        for value in addresses:
            address = str(ipaddress.ip_address(value))
            if address in known:
                continue
            known.add(address)
            servers.append({'address': address, 'role': role, 'tcp': None if tcp is None else tcp.get(address, 0),
                            'udp': None if udp is None else address in udp})
    result = {'servers': servers}
    if tcp is not None:
        # Loopback: VLESS carried inside AmneziaWG reaches the listener locally.
        result['local'] = sum(n for a, n in tcp.items() if ipaddress.ip_address(a).is_loopback)
        result['other'] = sum(n for a, n in tcp.items() if a not in known and not ipaddress.ip_address(a).is_loopback)
    return result


def host_metrics(interface, proc=PROC, root='/'):
    result = {'cpus': os.cpu_count() or 0}
    try:
        result['uptime'] = int(float((proc/'uptime').read_text().split()[0]))
    except (OSError, ValueError, IndexError):
        pass
    try:
        result['load'] = [round(value, 2) for value in os.getloadavg()]
    except OSError:
        pass
    try:
        memory = {}
        for line in (proc/'meminfo').read_text().splitlines():
            name, _, rest = line.partition(':')
            if name in ('MemTotal', 'MemAvailable'):
                memory[name] = int(rest.split()[0]) * 1024
        if len(memory) == 2:
            result['memory'] = {'total': memory['MemTotal'], 'available': memory['MemAvailable']}
    except (OSError, ValueError, IndexError):
        pass
    try:
        usage = shutil.disk_usage(root)
        result['disk'] = {'total': usage.total, 'free': usage.free}
    except OSError:
        pass
    if interface:
        try:
            for line in (proc/'net'/'dev').read_text().splitlines()[2:]:
                name, _, rest = line.partition(':')
                if name.strip() == interface:
                    values = rest.split()
                    result['network'] = {'rx': int(values[0]), 'tx': int(values[8])}
        except (OSError, ValueError, IndexError):
            pass
    return result


def operation(request):
    if not isinstance(request, dict) or set(request)-{'generation'} != {'operation', 'value'} \
            or request['operation'] not in OPERATIONS:
        raise ValueError('invalid operation')
    name, value = request['operation'], request['value']
    if name == 'configure':
        value = config.settings(value)
    elif name == 'peers':
        value = config.peers(value)
    elif name == 'rotate':
        if not isinstance(value, str) or (value not in ('controller', 'reality', 'encryption', 'mldsa', 'wireguard', 'amnezia') and str(uuid.UUID(value)) != value):
            raise ValueError('invalid rotation target')
    elif name == 'restore':
        value = state.snapshot(value)
    elif name in ('update', 'upgrade'):
        if value not in ('latest', 'dev'):
            raise ValueError('invalid update channel')
    elif value is not None:
        raise ValueError('operation takes no parameters')
    result = {'operation': name, 'value': value}
    if 'generation' in request:
        if not isinstance(request['generation'], str) or not state.GENERATION.fullmatch(request['generation']):
            raise ValueError('invalid base generation')
        result['generation'] = request['generation']
    return result


class Manager:
    def __init__(self, store, runtime):
        self.store, self.runtime = store, runtime

    def apply(self, value, bundle=None):
        if bundle is None:
            from node_upgrade import matching_bundle
            bundle = matching_bundle(self.store, value['images'])
        generation = self.store.create(value, bundle)
        self.runtime.validate(generation)
        pending = self.store.begin(generation)
        try:
            self.runtime.apply(generation)
            self.store.activate(generation)
        except Exception:
            # Keep pending until rollback is applied. Boot/watch can retry recovery.
            self.runtime.apply(pending['before'])
            self.store.rollback()
            raise
        return {'pending': pending}

    def recover(self):
        pending = self.store.pending()
        if pending:
            self.runtime.apply(pending['before'])
            self.store.rollback()
        return pending is not None

    def execute(self, request):
        request = operation(request)
        if 'generation' in request and request['generation'] != self.store.current():
            raise ValueError('node generation changed')
        if self.store.pending():
            raise ValueError('another change awaits confirmation')
        name, data = request['operation'], request['value']
        value = self.store.load()
        bundle = None
        certificate_result = {}
        if name == 'restart':
            self.runtime.apply(self.store.current())
            return {'restarted': True}
        if name == 'configure':
            previous = value['options']
            config.endpoint(data, self.runtime.host)
            if data.get('cover') and not previous.get('cover'):
                # Older snapshots retained an inactive cover's stale image.
                value['images'].pop('ng', None)
            value['options'] = data
            if config.needs_certificate(data) and (not value['tls'] or previous['domain'] != data['domain']
                    or previous.get('domain_aliases', []) != data.get('domain_aliases', [])):
                value['tls'] = self.certificate(data)
                certificate_result = {'certificate_result': 'issued'}
            if 'xray' in data or data.get('cover') or data.get('warp_mode', 'off') != 'off' or any(data.get(channel, {}).get('enabled') for channel in ('wireguard', 'amnezia')):
                self.runtime.ensure_keys(value)
        elif name == 'peers':
            bindings = value['options'].get('policy', {}).get('bindings', {})
            keep = {config.node_policy.peer_scope(peer['id']) for peer in data}
            for scope in list(bindings):
                if scope.startswith('peer-') and scope not in keep:
                    del bindings[scope]
            value['peers'] = data
            dns = value['options'].get('adguard')
            if dns:
                enabled = {peer['id'] for peer in data if peer['enabled']}
                dns['peers'] = [key for key in dns['peers'] if key in enabled]
            for peer in data:
                channel=peer.get('channel','vless')
                if channel != 'vless': value['options'].setdefault(channel,{})['enabled']=True
            if any(peer.get('channel','vless') != 'vless' for peer in data): self.runtime.ensure_keys(value)
        elif name == 'rotate':
            if data == 'controller':
                value['identity']['uuid'] = str(uuid.uuid4())
                if 'warp_uuid' in value['identity']:
                    value['identity']['warp_uuid'] = str(uuid.uuid4())
            elif data in ('reality', 'encryption', 'mldsa', 'wireguard', 'amnezia'):
                self.runtime.ensure_keys(value, rotate=data)
            else:
                found = False
                for peer in value['peers']:
                    if peer['id'] == data:
                        peer['id'] = str(uuid.uuid4())
                        bindings = value['options'].get('policy', {}).get('bindings', {})
                        old_scope = config.node_policy.peer_scope(data)
                        if old_scope in bindings:
                            bindings[config.node_policy.peer_scope(peer['id'])] = bindings.pop(old_scope)
                        dns = value['options'].get('adguard')
                        if dns and data in dns['peers']:
                            dns['peers'] = [peer['id'] if key == data else key for key in dns['peers']]
                        found = True
                if not found:
                    raise ValueError('peer no longer exists')
        elif name == 'restore':
            value = data
        elif name == 'rollback':
            from node_upgrade import matching_bundle
            previous = self.store.read('previous.json')
            if previous is None:
                raise ValueError('no previous generation is available')
            value = self.store.load(previous)
            bundle = matching_bundle(self.store, value['images'], previous)
        elif name in ('update', 'upgrade'):
            from image_bundle import fetch, read
            import node_upgrade
            node_upgrade.preserve_current_bundle(self.store)
            if name == 'upgrade':
                # Images of exactly the commit whose code the upgrade unit installed.
                path = self.store.root/node_upgrade.RELEASE
            else:
                path = self.store.root/'release.json'
                fetch(data, path)
            bundle = read(path)
            if name == 'upgrade' and bundle['source'] != node_upgrade.installed(self.store):
                raise ValueError('installed code and image bundle differ')
            value['images']['xr'] = bundle['images']['xr']
            if value['options'].get('adguard', {}).get('enabled'):
                value['images']['ad'] = bundle['images']['ad']
            if value['options'].get('warp_mode', 'off') != 'off':
                value['images']['wg'] = bundle['images']['wg']
            if value['options'].get('cover'):
                value['images']['ng'] = bundle['images']['ng']
        elif name in ('renew', 'renew_force'):
            if not config.needs_certificate(value['options']):
                raise ValueError('this transport does not use a certificate')
            previous = value['tls'].get('fullchain.pem')
            value['tls'] = self.certificate(value['options'], force=name == 'renew_force')
            if previous == value['tls'].get('fullchain.pem'):
                return {'certificate_result': 'unchanged'}
            certificate_result = {'certificate_result': 'renewed'}
        elif name == 'certificate_delete':
            if config.needs_certificate(value['options']):
                raise ValueError('disable the cover and select external Reality before deleting TLS')
            self.runtime.delete_certificate()
            value['tls'] = {}
            certificate_result = {'certificate_result': 'deleted'}
        if name in ('peers','rotate') and ('external' in value['identity'] or any(peer.get('channel','vless') != 'vless' for peer in value['peers'])):
            self.runtime.ensure_external_keys(value)
        if value['options'].get('warp_mode', 'off') == 'off':
            value['images'].pop('wg', None)
        if not value['options'].get('cover'):
            value['images'].pop('ng', None)
        filtering = value['options'].get('adguard', {}).get('enabled')
        if not filtering:
            value['images'].pop('ad', None)
        if filtering or value['options'].get('cover') or value['options'].get('warp_mode', 'off') != 'off':
            self.runtime.ensure_images(value)
        value = state.snapshot(value)
        self.runtime.pull(value['images']['xr'])
        if certificate_result and value['tls']:
            certificate_result['certificate_fingerprint'] = hashlib.sha256(base64.b64decode(value['tls']['fullchain.pem'], validate=True)).hexdigest()
        return self.apply(value, bundle) | certificate_result

    def certificate(self, options, force=False):
        if force:
            return self.runtime.certificate(options['domain'], options.get('domain_aliases', []), force=True)
        if options.get('domain_aliases'):
            return self.runtime.certificate(options['domain'], options['domain_aliases'])
        return self.runtime.certificate(options['domain'])

    def submit(self, request):
        request = operation(request)
        if 'generation' in request and request['generation'] != self.store.current():
            raise ValueError('node generation changed')
        job = self.store.read('job.json')
        if self.store.pending() or (job and job.get('state') in ('queued', 'running')):
            raise ValueError('node is busy')
        identifier = secrets.token_hex(16)
        state.atomic(self.store.root/'request.json', state.encode(request, state.policy_size(request)))
        state.atomic(self.store.root/'job.json', state.encode({'id': identifier, 'state': 'queued', 'time': int(time.time())}))
        try:
            command(['systemctl', 'start', '--no-block', UPGRADE_UNIT if request['operation'] == 'upgrade'
                     else 'vpnbot-node-worker.service'], timeout=5)
        except Exception:
            state.atomic(self.store.root/'job.json', state.encode({'id': identifier, 'state': 'failed', 'time': int(time.time())}))
            (self.store.root/'request.json').unlink(missing_ok=True)
            raise
        return {'job': identifier}

    def worker(self):
        job = self.store.read('job.json')
        if not job or job.get('state') != 'queued':
            return
        request = self.store.read('request.json')
        if isinstance(request, dict) and request.get('operation') == 'upgrade' and job.get('phase') != 'images':
            return  # The code phase belongs to the upgrade unit.
        job.update(state='running', time=int(time.time()))
        state.atomic(self.store.root/'job.json', state.encode(job))
        try:
            result = self.execute(request)
            job.update(state='done', result=result)
        except Exception:
            # No exception text: subprocess output and input can contain keys.
            job.update(state='failed', error='operation_failed')
        finally:
            job['time'] = int(time.time())
            state.atomic(self.store.root/'job.json', state.encode(job))
            (self.store.root/'request.json').unlink(missing_ok=True)

    def recover_job(self):
        # SIGKILL and systemd timeouts cannot execute the worker's finally block.
        # This runs under the same exclusive lock; an active worker cannot race it.
        job = self.store.read('job.json')
        if not job or job.get('state') not in ('queued', 'running'):
            return
        if job['state'] == 'queued' and time.time()-job['time'] < 30:
            return
        request = self.store.read('request.json')
        code = job.get('phase') == 'code' or (job['state'] == 'queued' and 'phase' not in job
                and isinstance(request, dict) and request.get('operation') == 'upgrade')
        result = command(['systemctl', 'show', '--property=ActiveState', '--value',
                          UPGRADE_UNIT if code else 'vpnbot-node-worker.service'], timeout=5)
        if result.stdout.strip() not in (b'inactive', b'failed'):
            return
        self.recover()
        job.update(state='failed', error='operation_interrupted', time=int(time.time()))
        state.atomic(self.store.root/'job.json', state.encode(job))
        (self.store.root/'request.json').unlink(missing_ok=True)

    def watch(self):
        """15-second pass: dead worker, expired confirmation, stopped containers, lost guard."""
        self.recover_job()
        pending = self.store.pending()
        if pending and time.time() >= pending['deadline']:
            self.recover()
        elif not self.runtime.running():
            self.runtime.apply(self.store.current())
        # A failed `systemctl restart nftables` flushes the ruleset and loads
        # nothing; the running node would stay unfiltered until the next apply.
        if not self.runtime.firewall_loaded():
            self.runtime.load_firewall()

    def rpc(self, request):
        if not isinstance(request, dict) or not isinstance(request.get('action'), str):
            raise ValueError('invalid RPC request')
        action = request['action']
        fields = {'ping': set(), 'status': set(), 'tls_probe': set(), 'backup': set(), 'profile': {'peer'},
                  'confirm': {'nonce'}, 'submit': {'request'}, 'job': {'id'}}
        if action not in fields or set(request) != fields[action] | {'action'}:
            raise ValueError('unknown action or fields')
        if action == 'ping':
            return {'schema': 1}
        if action == 'status':
            import node_upgrade
            status = self.runtime.status()
            # 'upgrade': this node accepts the full code and image update.
            code = node_upgrade.code_status(self.store) | {'images': node_upgrade.images_source(self.store)}
            try:
                options = status.get('options') if isinstance(status.get('options'), dict) else {}
                host = host_metrics((getattr(self.runtime, 'host', None) or {}).get('interface'))
                host |= connections(status.get('sources') or [], options.get('vpn_sources') or [])
            except Exception:
                host = {}
            return status | {'code': code, 'host': host, 'warp_egress': True, 'adguard_filter': True, 'named_policy': True, 'controller_ip_guard': True}
        if action == 'tls_probe':
            return self.runtime.tls_probe()
        if action == 'backup':
            pending = self.store.pending()
            return self.store.load(pending['before'] if pending else None)
        if action == 'profile':
            value = self.store.load()
            peer = None
            if request['peer'] is not None:
                if self.store.pending():
                    raise ValueError('external profile awaits confirmed state')
                peer = next((p for p in value['peers'] if p['id'] == request['peer']), None)
                if peer is None:
                    raise ValueError('peer no longer exists')
            return config.export_profile(value['options'], self.runtime.host, value['identity'], peer)
        if action == 'confirm':
            self.store.confirm(request['nonce'])
            # Confirmed: only the current generation's VPNBot images are kept.
            self.runtime.prune_images()
            return {'confirmed': True}
        if action == 'submit':
            return self.submit(request['request'])
        job = self.store.read('job.json')
        if not isinstance(request['id'], str) or not re.fullmatch('[a-f0-9]{32}', request['id']):
            raise ValueError('invalid job id')
        if not job or not secrets.compare_digest(job['id'], request['id']):
            # A restored controller backup can reference a job already replaced
            # by later maintenance. Distinguish that from transport failure.
            return {'state': 'missing'}
        return job


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in ('rpc', 'worker', 'boot', 'watch', 'stop', 'renew', 'upgrade'):
        raise ValueError('unsupported invocation')
    os.umask(0o077)
    mode = sys.argv[1]
    if mode == 'upgrade':
        # The installer of the new code takes the node lock itself; this
        # process holds it only while changing the job state.
        import node_upgrade
        node_upgrade.run(state.Store(ROOT), ROOT/'lock')
        return
    if mode == 'rpc':
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError()))
        signal.alarm(12)
        first = sys.stdin.buffer.read(1)
        panel = first == b'!'
        policy_frame = first == b'#'
        limit = 2*1024*1024 if panel else state.POLICY_BYTES + 1024 if policy_frame else state.MAX_BYTES
        request = state.decode((b'' if panel or policy_frame else first) + sys.stdin.buffer.read(limit+1), limit)
        if policy_frame and (not isinstance(request, dict) or set(request) != {'action','request'}
                or request['action'] != 'submit' or not isinstance(request['request'], dict)
                or state.policy_size(request['request']) != state.POLICY_BYTES):
            raise ValueError('invalid named policy frame')
        if panel and (not isinstance(request, dict) or set(request) != {'action','http'} or request['action'] != 'adguard_panel'):
            raise ValueError('invalid panel frame')
    store = state.Store(ROOT)
    descriptor = os.open(ROOT/'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        # Workers can start before submit releases its lock; boot can race
        # the recovery timer. Both must wait for serialized state access.
        # RPC/watch still return busy without blocking polling.
        fcntl.flock(descriptor, fcntl.LOCK_EX | (0 if mode in ('worker', 'boot') else fcntl.LOCK_NB))
        state.trusted(DEPLOYMENT)
        with DEPLOYMENT.open('rb') as stream:
            host = config.deployment(state.decode(stream.read(state.MAX_DEPLOYMENT_BYTES+1), state.MAX_DEPLOYMENT_BYTES))
        manager = Manager(store, Runtime(store, host))
        if mode == 'rpc':
            if panel:
                import node_adguard
                if not store.load()['options'].get('adguard', {}).get('enabled'):
                    raise ValueError('DNS panel is disabled')
                result = node_adguard.panel(request['http'], store.root, manager.runtime.container(node_adguard.CONTAINER), command)
            else:
                result = manager.rpc(request)
            limit = 12*1024*1024 if panel else state.MAX_BYTES
            if request.get('action') in ('status', 'backup') and state.policy_size(result) == state.POLICY_BYTES:
                limit = state.POLICY_BYTES + 1024
            sys.stdout.buffer.write(state.encode({'ok': True, 'result': result}, limit)+b'\n')
        elif mode == 'worker':
            manager.worker()
        elif mode == 'boot':
            if not manager.recover():
                manager.runtime.apply(store.current())
            job = store.read('job.json')
            if job and job.get('state') in ('queued', 'running'):
                job.update(state='failed', error='interrupted_by_restart')
                state.atomic(ROOT/'job.json', state.encode(job))
        elif mode == 'watch':
            manager.watch()
        elif mode == 'stop':
            manager.runtime.stop()
        elif mode == 'renew':
            if config.needs_certificate(store.load()['options']):
                result = manager.execute({'operation': 'renew', 'value': None})
                # The certificate job does not change routing, users or transport.
                if result.get('pending'):
                    store.confirm(result['pending']['nonce'])
    finally:
        os.close(descriptor)


if __name__ == '__main__':
    try:
        main()
    except BlockingIOError:
        print('{"ok":false,"error":"busy"}')
        # The 15-second recovery pass simply runs again; a held lock is no failure.
        sys.exit(0 if sys.argv[1:] == ['watch'] else 1)
    except Exception:
        print('{"ok":false,"error":"operation_failed"}')
        sys.exit(1)
