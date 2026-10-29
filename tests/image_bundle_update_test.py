"""Actual updater + real Git, with isolated Docker/Telegram boundaries."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bundle_update', ROOT / 'scripts/image_bundle.py')
bundle = importlib.util.module_from_spec(spec); spec.loader.exec_module(bundle)


class BundleUpdaterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name); self.root = self.base / 'bot'; self.root.mkdir()
        self.bin = self.base / 'bin'; self.bin.mkdir()
        self.events = self.base / 'events'; self.events.touch()
        self.mode = self.base / 'mode'; self.mode.write_text('success')
        self.env = os.environ | {'PATH': str(self.bin) + ':' + os.environ['PATH'],
                                 'BUNDLE_FIXTURE': str(self.base), 'VPNBOT_HOST_SERVICES': 'off'}
        for key in ('VPNBOT_BUNDLE_FILE', 'COMPOSE_FILE', 'VPNBOT_TAG'):
            self.env.pop(key, None)
        for directory in ('scripts', 'update', 'config', 'certs', 'ssh'):
            (self.root / directory).mkdir()
        for name in ('scripts/image_bundle.py', 'scripts/protocol_modules.py', 'scripts/host_services.py',
                     'scripts/preserve_update_state.sh', 'scripts/sync_image_tag.sh', 'update/update.sh'):
            shutil.copy2(ROOT / name, self.root / name)
        (self.root / '.gitignore').write_text('update/*\n!update/update.sh\noverride.env\n')
        (self.root / '.env').write_text('VPNBOT_TAG=dev\nTELEGRAM_API=synthetic.invalid\n')
        (self.root / 'config/custom.json').write_text('{"template":1}')
        (self.root / 'makefile').write_text(
            'pull:\n\tpython3 scripts/image_bundle.py ensure\n'
            '\tpython3 scripts/protocol_modules.py compose pull --policy missing\n'
            'start: pull\n\tpython3 scripts/protocol_modules.py compose up -d\n')
        self.git('init', '-q', '-b', 'dev')
        self.git('config', 'user.name', 'axiomshiftbit')
        self.git('config', 'user.email', '227203165+axiomshiftbit@users.noreply.github.com')
        self.git('add', '.'); self.git('commit', '-qm', 'Synthetic old code')
        self.before = self.git('rev-parse', 'HEAD')
        (self.root / 'code.txt').write_text('new code')
        self.git('add', 'code.txt'); self.git('commit', '-qm', 'Synthetic new code')
        self.after = self.git('rev-parse', 'HEAD')
        origin = self.base / 'origin.git'
        subprocess.run(['git', 'clone', '-q', '--bare', str(self.root), str(origin)], check=True)
        self.git('remote', 'add', 'origin', str(origin))
        self.git('checkout', '-q', '--detach', self.before)
        self.git('branch', '-f', 'dev', self.before); self.git('checkout', '-q', 'dev')
        self.value = dict(schema=1, source=self.after, run=123, attempt=1, state_epoch=1,
                          images={name: bundle.REGISTRY + name + '@sha256:' + 'b' * 64 for name in bundle.IMAGES})
        (self.base / 'candidate.json').write_text(json.dumps(self.value))
        self.runtime = '{"new_client":"synthetic","usage":789}'
        (self.root / 'config/custom.json').write_text(self.runtime)
        (self.root / 'override.env').write_text('TZ=Europe/Moscow\nCUSTOM=keep\n')
        # These stubs never contact Docker, Telegram or any external host.
        docker = self.bin / 'docker'
        docker.write_text('''#!/usr/bin/env python3
import json,os,pathlib,shutil,sys
b=pathlib.Path(os.environ['BUNDLE_FIXTURE']);a=sys.argv[1:];mode=(b/'mode').read_text()
with (b/'events').open('a') as f:f.write(json.dumps(a)+'\\n')
if a[0]=='pull':raise SystemExit(1 if mode=='registry-failure' else 0)
if a[:2]==['image','inspect']:print('sha256:'+'a'*64)
elif a[0]=='create':print('fixture-metadata')
elif a[0]=='cp':shutil.copyfile(b/'candidate.json',a[-1])
elif a[0]=='rm':pass
elif a[0]=='compose':
 if 'config' in a:print(json.dumps({'services':{'php':{'image':'ghcr.io/axiomshiftbit/vpnbot-php:dev'}}}))
 elif 'pull' in a:raise SystemExit(1 if mode=='image-failure' else 0)
 elif 'up' in a or 'down' in a:pass
 else:raise SystemExit(2)
else:raise SystemExit(2)
'''); docker.chmod(0o700)
        curl = self.bin / 'curl'; curl.write_text('#!/bin/sh\ncat >/dev/null\n'); curl.chmod(0o700)

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, stderr=subprocess.PIPE, text=True).strip()

    def wait_for(self, predicate):
        end = time.monotonic() + 20
        while time.monotonic() < end:
            if predicate(): return
            time.sleep(.05)
        self.fail('updater fixture timed out')

    def run_update(self, command='1'):
        with (self.base / 'worker.log').open('wb') as output:
            process = subprocess.Popen(['bash', 'update/update.sh'], cwd=self.root, env=self.env,
                                       stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                self.wait_for(lambda: (self.root / 'update/update_pid').exists())
                (self.root / 'update/key').write_text('synthetic-test-token')
                (self.root / 'update/curl').write_text('{"chat_id":1,"message_id":1}')
                (self.root / 'update/branch').write_text('dev')
                (self.root / 'update/pipe').write_text(command)
                self.wait_for(lambda: self.events.stat().st_size > 0)
                self.wait_for(lambda: not (self.root / 'update/pipe').read_text().strip())
                time.sleep(.1)
            finally:
                try: os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError: pass
                process.wait(timeout=10)
        return [json.loads(line) for line in self.events.read_text().splitlines()]

    def test_full_update_preserves_runtime_and_selects_exact_code_and_images(self):
        events = self.run_update()
        self.assertEqual(self.after, self.git('rev-parse', 'HEAD'))
        self.assertEqual(self.value, bundle.read(self.root / 'update/image-bundle.json'))
        self.assertEqual(self.runtime, (self.root / 'config/custom.json').read_text())
        self.assertIn('CUSTOM=keep', (self.root / 'override.env').read_text())
        pull = next(i for i, args in enumerate(events) if args[0] == 'compose' and 'pull' in args)
        down = next(i for i, args in enumerate(events) if 'down' in args)
        self.assertLess(pull, down)
        self.assertTrue(any('up' in args and '--no-build' in args for args in events))

    def test_failed_download_keeps_working_services_and_source(self):
        for mode, command in (('registry-failure', '1'), ('image-failure', '1'), ('image-failure', '2')):
            self.events.write_text(''); self.mode.write_text(mode)
            (self.root / 'update/update_pid').unlink(missing_ok=True)
            if command == '2':
                active = self.value | {'source': self.before}
                bundle.atomic(self.root / 'update/image-bundle.json', bundle.canonical(active))
            with self.subTest(mode=mode, command=command):
                events = self.run_update(command)
                self.assertFalse(any('down' in args or 'up' in args for args in events))
                self.assertEqual(self.before, self.git('rev-parse', 'HEAD'))
                self.assertEqual(self.runtime, (self.root / 'config/custom.json').read_text())

    def test_update_from_a_release_without_snolc_keeps_it_as_previous(self):
        previous = dict(self.value, source=self.before,
                        images={k: v for k, v in self.value['images'].items() if k != 'snolc'})
        bundle.atomic(self.root / 'update/image-bundle.json', bundle.canonical(previous))
        # Установленный код без snolc (мост 17b209e) уже записал overlay нового
        # комплекта по своему списку сервисов: snolc в нём не закреплён.
        stale = bundle.overlay(self.value); del stale['services']['snolc']
        bundle.atomic(self.root / 'update' / ('compose-images-' + bundle.fingerprint(self.value) + '.json'), bundle.canonical(stale))
        events = self.run_update()
        up = [args for args in events if args[0] == 'compose' and 'up' in args][-1]
        overlay = next(arg for arg in up if 'compose-images-' in arg)
        self.assertEqual(self.value['images']['snolc'], json.loads(Path(overlay).read_text())['services']['snolc']['image'])
        self.assertEqual(self.after, self.git('rev-parse', 'HEAD'))
        self.assertEqual(self.value, bundle.read(self.root / 'update/image-bundle.json'))
        self.assertEqual(previous, bundle.read(self.root / 'update/image-bundle.previous.json', previous=True))
        self.assertEqual(self.runtime, (self.root / 'config/custom.json').read_text())
        self.assertTrue(any('up' in args and '--no-build' in args for args in events))


if __name__ == '__main__':
    unittest.main()
