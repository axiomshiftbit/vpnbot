"""Real filesystem crash/ENOSPC tests; systemctl is an inert recording stub."""
import errno
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import node_code as code
import node_upgrade as upgrade

LAUNCHER = Path(code.__file__).read_bytes()
SERVICES = {'vpnbot-node.service': 'old service', 'vpnbot-node-watch.timer': 'old timer'}


def modules(version):
    return {'node_manager.py': ("import sys;from pathlib import Path\n"
                               "sys.path.insert(0,str(Path(__file__).parent))\n"
                               "import component\n"
                               "if __name__=='__main__': print(component.VERSION)\n").encode(),
            'component.py': ('VERSION='+repr(version)+'\n').encode()}


class NodeCode(unittest.TestCase):
    def setUp(self):
        mask = os.umask(0o077); self.addCleanup(os.umask, mask)
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lib = self.root/'lib'; self.lib.mkdir()
        self.units = self.root/'units'; self.units.mkdir()
        self.commands = []
        self.install('old', SERVICES)
        self.old = code.active_id(self.lib)
        self.commands.clear()

    def command(self, args):
        self.assertEqual(args, ['systemctl', 'daemon-reload'])
        self.commands.append(args)

    def install(self, version, services=None):
        code.install(self.lib, self.units, modules(version), services or {k: v.replace('old', version) for k, v in SERVICES.items()}, LAUNCHER, self.command)

    def assert_old(self):
        self.assertEqual(code.active_id(self.lib), self.old)
        self.assertEqual({n: (self.units/n).read_text() for n in SERVICES}, SERVICES)
        self.assertEqual(subprocess.check_output([sys.executable, '-I', '-B', str(code.active_path(self.lib)/'node_manager.py')]).strip(), b'old')

    def test_complete_generation_and_real_import_validation(self):
        self.install('new')
        self.assertNotEqual(code.active_id(self.lib), self.old)
        self.assertTrue((self.lib/'releases'/self.old/'component.py').exists())
        self.assertEqual(subprocess.check_output([sys.executable, '-I', '-B', str(code.active_path(self.lib)/'node_manager.py')]).strip(), b'new')
        broken = modules('broken'); broken['node_manager.py'] = b'import absent_module\n'
        current = code.active_id(self.lib)
        with self.assertRaisesRegex(ValueError, 'import validation'):
            code.install(self.lib, self.units, broken, SERVICES, LAUNCHER, self.command)
        self.assertEqual(code.active_id(self.lib), current)

    def test_enospc_at_every_stage_preserves_old_generation(self):
        real_atomic = code.atomic
        points = ['node_manager.py', 'component.py', 'launcher', 'old-unit', 'new-unit', code.JOURNAL, code.ACTIVE]
        for point in points:
            triggered = []
            def atomic(path, body, mode=0o644):
                kind = ('launcher' if path == self.lib/'node_manager.py' else
                        'old-unit' if path.name.startswith('old-') else
                        'new-unit' if path.name.startswith('new-') else path.name)
                if kind == point and not triggered:
                    triggered.append(True)
                    raise OSError(errno.ENOSPC, 'synthetic full filesystem')
                return real_atomic(path, body, mode)
            with self.subTest(point=point), patch.object(code, 'atomic', side_effect=atomic):
                with self.assertRaises(OSError): self.install('new')
            self.assertTrue(triggered)
            self.assert_old()
            self.assertFalse((self.lib/code.JOURNAL).exists())

    def test_masque_shell_syntax_checked_before_publishing_any_files(self):
        # A valid script may exit nonzero when run without an operation.
        good = modules('new') | {'warp_masque.sh': b'#!/bin/sh\nexit 17\n'}
        code.install(self.lib, self.units, good, SERVICES, LAUNCHER, self.command)
        active = code.active_id(self.lib)
        releases = set((self.lib/'releases').iterdir())
        bad = good | {'warp_masque.sh': b'#!/bin/sh\nif true; then\n'}
        with self.assertRaisesRegex(ValueError, 'shell helper syntax'):
            code.install(self.lib, self.units, bad, {'vpnbot-node.service': 'candidate'}, LAUNCHER, self.command)
        self.assertEqual(code.active_id(self.lib), active)
        self.assertEqual(set((self.lib/'releases').iterdir()), releases)
        self.assertEqual({name:(self.units/name).read_text() for name in SERVICES}, SERVICES)

    def test_daemon_reload_failure_rolls_back_units_before_return(self):
        calls = []
        def command(args):
            calls.append(args)
            if len(calls) == 1: raise RuntimeError('synthetic systemd refusal')
        with patch.object(self, 'command', side_effect=command):
            with self.assertRaises(RuntimeError): self.install('new')
        self.assertEqual(len(calls), 2)
        self.assert_old()

    def test_kill_during_units_or_pointer_is_recoverable(self):
        ctx = multiprocessing.get_context('fork')
        for point in ('first-unit', 'all-units', 'pointer-before', 'pointer-after'):
            # Restore a known old generation for each independent crash.
            self.install('old', SERVICES); self.old = code.active_id(self.lib)
            real_replace, real_publish = code.os.replace, code.publish
            def child():
                count = 0
                def replace(first, second):
                    nonlocal count
                    result = real_replace(first, second)
                    if Path(second).parent == self.units and Path(second).name in SERVICES:
                        count += 1
                        if (point == 'first-unit' and count == 1) or (point == 'all-units' and count == len(SERVICES)):
                            os._exit(42)
                    return result
                def publish(lib, identifier):
                    if point == 'pointer-before': os._exit(42)
                    real_publish(lib, identifier)
                    if point == 'pointer-after': os._exit(42)
                with patch.object(code.os, 'replace', side_effect=replace), patch.object(code, 'publish', side_effect=publish):
                    self.install('new')
            process = ctx.Process(target=child); process.start(); process.join(15)
            try:
                self.assertEqual(process.exitcode, 42)
                with code.locked(self.lib): code.recover(self.lib, self.units, self.command)
                if point == 'pointer-after':
                    self.assertNotEqual(code.active_id(self.lib), self.old)
                    self.assertEqual({n: (self.units/n).read_text() for n in SERVICES}, {n: v.replace('old', 'new') for n, v in SERVICES.items()})
                else: self.assert_old()
                self.assertFalse((self.lib/code.JOURNAL).exists())
                with code.locked(self.lib): code.recover(self.lib, self.units, self.command)
            finally:
                if process.is_alive(): process.terminate(); process.join(5)

    def test_existing_process_imports_only_its_original_generation(self):
        directory = code.active_path(self.lib)
        ready, resume = self.root/'ready', self.root/'resume'
        program = ('import pathlib,sys,time;sys.path.insert(0,sys.argv[1]);'
                   'pathlib.Path(sys.argv[2]).touch()\n'
                   'while not pathlib.Path(sys.argv[3]).exists(): time.sleep(.01)\n'
                   'import component;print(component.VERSION)\n')
        process = subprocess.Popen([sys.executable, '-I', '-B', '-c', program, str(directory), str(ready), str(resume)], stdout=subprocess.PIPE)
        try:
            import time
            deadline = time.monotonic()+5
            while not ready.exists() and time.monotonic() < deadline: time.sleep(.01)
            self.assertTrue(ready.exists())
            self.install('new'); resume.touch()
            self.assertEqual(process.communicate(timeout=5)[0].strip(), b'old')
        finally:
            if process.poll() is None: process.kill(); process.wait()

    def test_legacy_migration_keeps_old_code_if_install_fails(self):
        legacy = self.root/'legacy'; legacy.mkdir()
        for name, body in modules('legacy').items(): (legacy/name).write_bytes(body)
        calls = []
        def fail_once(args):
            calls.append(args)
            if len(calls) == 1: raise RuntimeError('synthetic failure')
        with self.assertRaises(RuntimeError):
            code.install(legacy, self.units, modules('new'), SERVICES, LAUNCHER, fail_once)
        self.assertEqual(subprocess.check_output([sys.executable, '-I', '-B', str(code.active_path(legacy)/'node_manager.py')]).strip(), b'legacy')
        self.assertEqual((legacy/'node_manager.py').read_bytes(), LAUNCHER)

    def test_existing_lock_uses_read_only_open_and_trusted_rejects_symlinks(self):
        real_open = code.os.open; modes = []
        def opened(path, flags, *args):
            if Path(path).name == '.code.lock': modes.append(flags)
            return real_open(path, flags, *args)
        with patch.object(code.os, 'open', side_effect=opened):
            with code.locked(self.lib): pass
        self.assertEqual(modes[0] & os.O_ACCMODE, os.O_RDONLY)
        (self.lib/'link').symlink_to(code.active_path(self.lib))
        with self.assertRaises(ValueError): code.trusted(self.lib/'link')

    def test_installed_digest_uses_active_modules_not_launcher(self):
        with patch.object(upgrade, 'LIB', self.lib), patch.object(upgrade, 'MODULES', tuple(modules('old'))):
            old = upgrade.digest()
            self.install('new')
            self.assertNotEqual(old, upgrade.digest())
            self.assertEqual(old, upgrade.digest(self.lib/'releases'/self.old))

    @unittest.skipUnless(os.environ.get('VPNBOT_KERNEL_SANDBOX') == '1', 'только отдельный root namespace/chroot')
    def test_root_rpc_recovers_real_modules_after_readonly_worker_refuses(self):
        # This integration case can run only inside the lab's fresh chroot.
        self.assertEqual(os.geteuid(), 0)
        self.assertNotEqual(os.readlink('/proc/self/ns/net'), os.environ['VPNBOT_PARENT_NETNS'])
        self.assertFalse(Path('/etc/vpnbot-node').exists())
        import node_state as state
        source = Path(code.__file__).parent
        actual = {name: (source/name).read_bytes() for name in upgrade.MODULES}
        root_units = Path('/etc/systemd/system'); root_units.mkdir(parents=True)
        stub = self.root/'systemctl'; stub.write_text('#!/bin/sh\nexit 0\n'); stub.chmod(0o755)
        target = Path('/usr/bin/systemctl')
        subprocess.run(['mount', '--bind', str(stub), str(target)], check=True, capture_output=True)
        readonly = False
        try:
            lib = self.root/'real-lib'; lib.mkdir()
            code.install(lib, root_units, actual, SERVICES, LAUNCHER, self.command)
            old = code.active_id(lib)
            ctx = multiprocessing.get_context('fork')
            def killed():
                with patch.object(code, 'publish', side_effect=lambda *_: os._exit(42)):
                    code.install(lib, root_units, actual, {k: v+' changed' for k, v in SERVICES.items()}, LAUNCHER, self.command)
            process = ctx.Process(target=killed); process.start(); process.join(15)
            self.assertEqual(process.exitcode, 42)
            # Simulate ProtectSystem's read-only LIB/units, without changing host mounts.
            for path in (lib, root_units):
                subprocess.run(['mount', '--bind', str(path), str(path)], check=True, capture_output=True)
                subprocess.run(['mount', '-o', 'remount,bind,ro', str(path)], check=True, capture_output=True)
            readonly = True
            entry = [sys.executable, '-I', '-B', str(lib/'node_manager.py'), 'rpc']
            blocked = subprocess.run(entry, input=b'{"action":"ping"}', capture_output=True, timeout=10)
            self.assertNotEqual(blocked.returncode, 0)
            self.assertTrue((lib/code.JOURNAL).exists())
            for path in (root_units, lib): subprocess.run(['umount', str(path)], check=True, capture_output=True)
            readonly = False
            deployment = dict(public4='11.77.0.4', public6='2606:4700:4700::1111', sources=['11.77.0.2'],
                              admins=['11.77.0.3'], routers=['fe80::1'], ssh_ports=[22], interface='eth0', uid=995, gid=995)
            etc = Path('/etc/vpnbot-node'); etc.mkdir(mode=0o700)
            state.atomic(etc/'deployment.json', state.encode(deployment))
            value = {'schema': 1, 'options': dict(transport='reality', family=4, core='origin', domain='', mask='mask.example.test'),
                     'identity': dict(uuid='11111111-1111-4111-8111-111111111111', private='A'*43, public='B'*43,
                                      short_id='0123456789abcdef', path='0123456789abcdef'*2),
                     'peers': [], 'images': {'xr': 'ghcr.io/axiomshiftbit/vpnbot-xr@sha256:'+'a'*64}, 'tls': {}}
            store = state.Store(Path('/var/lib/vpnbot-node')); store.activate(store.create(value))
            for action in ('ping', 'status'):
                result = subprocess.run(entry, input=json.dumps({'action': action}).encode(), capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, 'root RPC must restore without manual code copying')
                self.assertTrue(json.loads(result.stdout)['ok'])
            self.assertEqual(code.active_id(lib), old)
            self.assertFalse((lib/code.JOURNAL).exists())
            self.assertEqual({n: (root_units/n).read_text() for n in SERVICES}, SERVICES)
        finally:
            if readonly:
                for path in (root_units, lib): subprocess.run(['umount', str(path)], capture_output=True)
            subprocess.run(['umount', str(target)], check=True, capture_output=True)


if __name__ == '__main__': unittest.main()
