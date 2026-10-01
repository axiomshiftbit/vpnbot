#!/usr/bin/env python3
"""Quota checkpoints and graceful stop. Mutations require the shared telemt lock."""
import base64
import fcntl
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import tomllib
import urllib.request


class TelemtState:
    def __init__(self, root='/telemt', api='http://127.0.0.1:9091'):
        self.root = Path(root)
        self.config = self.root / 'telemt.toml'
        self.path = self.root / 'data/telemt.limit.json'
        self.api = api

    def settings(self):
        return tomllib.loads(self.config.read_text()).get('access', {})

    @staticmethod
    def integer(value):
        return type(value) is int and 0 <= value <= 2**64 - 1

    @classmethod
    def validate(cls, data):
        if not isinstance(data, dict) or not cls.integer(data.get('last_reset_epoch_secs')):
            raise ValueError('invalid_quota_state')
        users = data.get('users')
        if not isinstance(users, dict) or len(users) > 65536:
            raise ValueError('invalid_quota_users')
        for name, value in users.items():
            if not isinstance(name, str) or not isinstance(value, dict) or not all(
                cls.integer(value.get(field)) for field in ('used_bytes', 'last_reset_epoch_secs')
            ):
                raise ValueError('invalid_quota_user')
        return data

    def read(self):
        if self.path.is_symlink():
            raise ValueError('invalid_quota_file')
        if not self.path.exists():
            return {'last_reset_epoch_secs': 0, 'users': {}}
        if self.path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError('invalid_quota_file')
        return self.validate(json.loads(self.path.read_bytes()))

    def write(self, data):
        self.validate(data)
        payload = json.dumps(data, ensure_ascii=False) + '\n'
        if len(payload.encode()) > 16 * 1024 * 1024:
            raise ValueError('oversized_quota_state')
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix='.quota-', dir=self.path.parent)
        try:
            with os.fdopen(fd, 'w') as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def fetch(self, route):
        # The Control API stays on loopback; ignore environment proxies.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(self.api + route, timeout=2) as response:
            body = response.read(16 * 1024 * 1024 + 1)
        if len(body) > 16 * 1024 * 1024:
            raise ValueError('oversized_quota_response')
        data = json.loads(body)
        if data.get('ok') is not True:
            raise ValueError('quota_api_failed')
        return data['data']

    def processes(self):
        result = {}
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit():
                continue
            try:
                argv = (entry / 'cmdline').read_bytes().split(b'\0')
                if os.fsencode(self.config) not in argv:
                    continue
                stat = (entry / 'stat').read_text().rsplit(') ', 1)[1].split()
                if stat[0] != 'Z':
                    result[int(entry.name)] = stat[19]
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
        return result

    def prepare(self):
        access = self.settings()
        state = self.read()
        required = set(access.get('user_data_quota', {}))
        if required - set(state['users']):
            raise ValueError('quota_state_missing_restore_backup_or_reset')
        # A deleted username must not inherit its previous quota when recreated.
        state['users'] = {name: state['users'].get(name, {'used_bytes': 0, 'last_reset_epoch_secs': 0})
                          for name in access.get('users', {})}
        self.write(state)

    def checkpoint(self):
        access = self.settings()
        required = set(access.get('user_data_quota', {}))
        if not required:
            return
        before = self.processes()
        if not before:
            raise ValueError('core_not_running')
        data = self.fetch('/v1/stats/users/quota')
        updates = {}
        for item in data['users']:
            name = item['username']
            if name in updates:
                raise ValueError('duplicate_quota_user')
            updates[name] = {field: item[field] for field in ('used_bytes', 'last_reset_epoch_secs')}
        self.validate({'last_reset_epoch_secs': 0, 'users': updates})
        if required - set(updates) or self.processes() != before:
            raise ValueError('incomplete_quota_snapshot')
        state = self.read()
        previous = json.dumps(state, sort_keys=True)
        for name in required:
            old = state['users'].get(name, {})
            new = updates[name]
            if new['last_reset_epoch_secs'] < old.get('last_reset_epoch_secs', 0) or (
                new['last_reset_epoch_secs'] == old.get('last_reset_epoch_secs', 0)
                and new['used_bytes'] < old.get('used_bytes', 0)
            ):
                raise ValueError('quota_counter_regressed')
            state['users'][name] = new
        state['last_reset_epoch_secs'] = max([0] + [v['last_reset_epoch_secs'] for v in state['users'].values()])
        if json.dumps(state, sort_keys=True) != previous:
            self.write(state)

    def ready(self):
        end = time.monotonic() + 10
        while True:
            try:
                if not self.processes():
                    raise ValueError('core_not_running')
                self.fetch('/v1/stats/users/quota')
                self.checkpoint()
                return
            except (OSError, ValueError, KeyError):
                if time.monotonic() >= end:
                    raise ValueError('core_not_ready')
                time.sleep(.2)

    def watch(self, lock_path='/logs/.lock.telemt'):
        # Один процесс вместо нового Python на каждой секундной итерации.
        # Неблокирующий flock отдаёт приоритет изменениям настроек из бота.
        stopping = False

        def stop_watch(*_):
            nonlocal stopping
            stopping = True

        signal.signal(signal.SIGTERM, stop_watch)
        signal.signal(signal.SIGINT, stop_watch)
        while not stopping:
            try:
                with open(lock_path, 'a') as lock:
                    try:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        continue
                    enabled = self.root / 'service-enabled'
                    if self.config.is_file() and (not enabled.exists() or enabled.read_text().strip() == '1'):
                        self.checkpoint()
            except (OSError, ValueError, KeyError, TypeError) as error:
                print('TELEMT_CHECKPOINT_ERROR:' + type(error).__name__, file=sys.stderr, flush=True)
            finally:
                time.sleep(1)

    def stop(self, timeout=25):
        pids = self.processes()
        if not pids:
            return
        try:
            self.checkpoint()
        except (OSError, ValueError, KeyError):
            pass  # SIGTERM still saves the exact native counters on shutdown.
        before = self.path.stat().st_ino if self.path.exists() else None
        for pid, started in pids.items():
            if self.processes().get(pid) == started:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        end = time.monotonic() + timeout
        while self.processes() and time.monotonic() < end:
            time.sleep(.1)
        if self.processes():
            raise ValueError('graceful_stop_timeout')
        if self.settings().get('user_data_quota'):
            if not self.path.exists() or self.path.stat().st_ino == before:
                raise ValueError('final_quota_checkpoint_failed')
            self.validate(self.read())

    def reset(self, name):
        if self.processes():
            raise ValueError('reset_requires_stopped_core')
        access = self.settings()
        if name not in access.get('users', {}):
            raise ValueError('user_not_found')
        state = self.read()
        if set(access.get('user_data_quota', {})) - {name} - set(state['users']):
            raise ValueError('other_quota_state_missing')
        epoch = int(time.time())
        state['users'][name] = {'used_bytes': 0, 'last_reset_epoch_secs': epoch}
        state['last_reset_epoch_secs'] = max(epoch, state['last_reset_epoch_secs'])
        self.write(state)


if __name__ == '__main__':
    try:
        state = TelemtState()
        action = sys.argv[1]
        if action == 'version':
            pass
        elif action in ('prepare', 'checkpoint', 'stop', 'ready', 'watch'):
            getattr(state, action)()
        elif action == 'reset':
            state.reset(base64.b64decode(sys.argv[2], validate=True).decode())
        else:
            raise ValueError('unknown_action')
        print('TELEMT_STATE_OK')
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        # Do not expose config, credentials, HTTP bodies or exception values.
        print('TELEMT_STATE_ERROR:' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
