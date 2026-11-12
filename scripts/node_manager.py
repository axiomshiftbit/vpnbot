#!/usr/bin/env python3
"""Restricted SSH RPC and serialized node maintenance jobs (root only)."""
import copy
import fcntl
import hashlib
import base64
import os
from pathlib import Path
import re
import secrets
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

    def apply(self, value):
        generation = self.store.create(value)
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
        certificate_result = {}
        if name == 'restart':
            self.runtime.apply(self.store.current())
            return {'restarted': True}
        if name == 'configure':
            previous = value['options']
            config.endpoint(data, self.runtime.host)
            value['options'] = data
            if config.needs_certificate(data) and (not value['tls'] or previous['domain'] != data['domain']
                    or previous.get('domain_aliases', []) != data.get('domain_aliases', [])):
                value['tls'] = self.certificate(data)
                certificate_result = {'certificate_result': 'issued'}
            if 'xray' in data or data.get('cover') or any(data.get(channel, {}).get('enabled') for channel in ('wireguard', 'amnezia')):
                self.runtime.ensure_keys(value)
        elif name == 'peers':
            value['peers'] = data
            for peer in data:
                channel=peer.get('channel','vless')
                if channel != 'vless': value['options'].setdefault(channel,{})['enabled']=True
            if any(peer.get('channel','vless') != 'vless' for peer in data): self.runtime.ensure_keys(value)
        elif name == 'rotate':
            if data == 'controller':
                value['identity']['uuid'] = str(uuid.uuid4())
            elif data in ('reality', 'encryption', 'mldsa', 'wireguard', 'amnezia'):
                self.runtime.ensure_keys(value, rotate=data)
            else:
                found = False
                for peer in value['peers']:
                    if peer['id'] == data:
                        peer['id'] = str(uuid.uuid4())
                        found = True
                if not found:
                    raise ValueError('peer no longer exists')
        elif name == 'restore':
            value = data
        elif name == 'rollback':
            previous = self.store.read('previous.json')
            if previous is None:
                raise ValueError('no previous generation is available')
            value = self.store.load(previous)
        elif name in ('update', 'upgrade'):
            from image_bundle import fetch, read
            if name == 'upgrade':
                # Images of exactly the commit whose code the upgrade unit installed.
                import node_upgrade
                path = self.store.root/node_upgrade.RELEASE
                if read(path)['source'] != node_upgrade.installed(self.store):
                    raise ValueError('installed code and image bundle differ')
            else:
                path = self.store.root/'release.json'
                fetch(data, path)
            value['images']['xr'] = read(path)['images']['xr']
            if value['options'].get('cover'):
                value['images']['ng'] = read(path)['images']['ng']
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
        if value['options'].get('cover'):
            self.runtime.ensure_images(value)
        value = state.snapshot(value)
        self.runtime.pull(value['images']['xr'])
        if certificate_result and value['tls']:
            certificate_result['certificate_fingerprint'] = hashlib.sha256(base64.b64decode(value['tls']['fullchain.pem'], validate=True)).hexdigest()
        return self.apply(value) | certificate_result

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
        state.atomic(self.store.root/'request.json', state.encode(request))
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
            # 'upgrade': this node accepts the full code and image update.
            return self.runtime.status() | {'code': {'source': node_upgrade.installed(self.store), 'upgrade': True}}
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
        request = state.decode(sys.stdin.buffer.read(state.MAX_BYTES+1))
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
            result = manager.rpc(request)
            sys.stdout.buffer.write(state.encode({'ok': True, 'result': result})+b'\n')
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
            manager.recover_job()
            pending = store.pending()
            if pending and time.time() >= pending['deadline']:
                manager.recover()
            elif not manager.runtime.running():
                manager.runtime.apply(store.current())
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
