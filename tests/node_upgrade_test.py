#!/usr/bin/env python3
"""Code phase of the node's full update against real temporary Git repositories."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import node_manager as manager
import node_state as state
import node_upgrade as upgrade
from node_card_status_test import bundle as image_manifest
from node_config_test import HOST
from node_runtime import Runtime
from node_state_test import VALUE

JOB = 'e'*32


def git(directory, *args):
    return subprocess.run(['git', '-C', str(directory), *args], check=True, capture_output=True,
                          env={'PATH': os.environ['PATH'], 'HOME': str(directory), 'GIT_CONFIG_NOSYSTEM': '1',
                               'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@example.test',
                               'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@example.test'}).stdout.decode().strip()


class NodeUpgrade(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='vpnbot-node-upgrade-')
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.marker = self.base/'setup-calls'
        self.store = state.Store(self.base/'state')
        self.store.activate(self.store.create(VALUE))
        work = self.base/'work'
        work.mkdir()
        git(work, 'init', '-q', '-b', 'master')
        self.commits = [self.commit(work, 'first', 0), self.commit(work, 'second', 0)]
        git(self.base, 'clone', '-q', '--bare', str(work), 'origin.git')
        self.repository = self.base/'node'
        git(self.base, 'clone', '-q', str(self.base/'origin.git'), 'node')
        git(self.repository, 'reset', '-q', '--hard', self.commits[0])
        self.work = work
        for name, value in (('REPOSITORY', self.repository),):
            patcher = patch.object(upgrade, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.started = []
        patcher = patch.object(upgrade, 'command', side_effect=lambda args, **_: self.started.append(args))
        patcher.start()
        self.addCleanup(patcher.stop)
        # git -C <clone> uses the test HOME, never the developer's settings.
        patcher = patch.dict(os.environ, {'GIT_CONFIG_NOSYSTEM': '1'})
        patcher.start()
        self.addCleanup(patcher.stop)

    def commit(self, work, text, code):
        scripts = work/'scripts'
        scripts.mkdir(exist_ok=True)
        (scripts/'node_setup.py').write_text(
            'import sys\n'
            f'open({str(self.marker)!r}, "a").write(" ".join(sys.argv[1:]) + "\\n")\n'
            'print("Этап [code]: x", file=sys.stderr)\n'
            f'if {code}:\n    print("Этап [firewall]: x", file=sys.stderr); sys.exit(1)\n')
        (scripts/'version.txt').write_text(text)
        git(work, 'add', '-A')
        git(work, 'commit', '-q', '-m', text)
        return git(work, 'rev-parse', 'HEAD')

    def queue(self, channel='latest'):
        state.atomic(self.store.root/'request.json', state.encode({'operation': 'upgrade', 'value': channel, 'generation': self.store.current()}))
        state.atomic(self.store.root/'job.json', state.encode({'id': JOB, 'state': 'queued', 'time': 0}))

    def run_upgrade(self, source):
        def fetch(channel, path):
            bundle = {'source': source}
            Path(path).write_text(json.dumps(bundle))
            return bundle
        with patch.object(upgrade.image_bundle, 'fetch', side_effect=fetch):
            upgrade.run(self.store, self.store.root/'lock')
        return self.store.read('job.json')

    def setup_calls(self):
        return self.marker.read_text().splitlines() if self.marker.exists() else []

    def test_installs_published_commit_then_hands_images_to_worker(self):
        self.queue()
        job = self.run_upgrade(self.commits[1])
        self.assertEqual(self.setup_calls(), ['--upgrade-code --job '+JOB])
        self.assertEqual((job['state'], job['phase'], job['code'], job['checkout']), ('queued', 'images', self.commits[1], 'updated'))
        self.assertEqual(self.store.read('code.json')['source'], self.commits[1])
        self.assertEqual(git(self.repository, 'rev-parse', 'HEAD'), self.commits[1])
        self.assertFalse((self.store.root/upgrade.SOURCE).exists())
        self.assertEqual(self.store.read('request.json')['operation'], 'upgrade')
        self.assertEqual(self.started, [['systemctl', 'start', '--no-block', 'vpnbot-node-worker.service']])

    def test_local_edits_in_clone_are_kept(self):
        (self.repository/'scripts/version.txt').write_text('local edit')
        self.queue()
        job = self.run_upgrade(self.commits[1])
        self.assertEqual((job['state'], job['checkout']), ('queued', 'kept'))
        self.assertEqual(git(self.repository, 'rev-parse', 'HEAD'), self.commits[0])
        self.assertEqual((self.repository/'scripts/version.txt').read_text(), 'local edit')
        self.assertEqual(self.setup_calls(), ['--upgrade-code --job '+JOB])

    def test_older_commit_is_refused(self):
        state.atomic(self.store.root/'code.json', state.encode({'source': self.commits[1], 'time': 0}))
        self.queue()
        job = self.run_upgrade(self.commits[0])
        self.assertEqual((job['state'], job['error'], job['stage']), ('failed', 'code_upgrade_failed', 'downgrade'))
        self.assertEqual(self.setup_calls(), [])
        self.assertFalse((self.store.root/'request.json').exists())
        self.assertFalse((self.store.root/upgrade.RELEASE).exists())
        self.assertEqual(self.started, [])

    def test_commit_outside_release_branch_is_refused(self):
        git(self.work, 'checkout', '-q', '-b', 'side', self.commits[0])
        foreign = self.commit(self.work, 'side', 0)
        git(self.work, 'push', '-q', str(self.base/'origin.git'), 'side')
        self.queue()
        job = self.run_upgrade(foreign)
        self.assertEqual((job['state'], job['stage']), ('failed', 'fetch'))
        self.assertEqual(self.setup_calls(), [])

    def test_installer_failure_reports_only_its_stage(self):
        broken = self.commit(self.work, 'broken', 1)
        git(self.work, 'push', '-q', str(self.base/'origin.git'), 'master')
        self.queue()
        job = self.run_upgrade(broken)
        self.assertEqual((job['state'], job['stage']), ('failed', 'setup_firewall'))
        self.assertIsNone(self.store.read('code.json'))
        self.assertEqual(git(self.repository, 'rev-parse', 'HEAD'), self.commits[0])

    def test_already_installed_commit_skips_installer(self):
        state.atomic(self.store.root/'code.json', state.encode({'source': self.commits[1], 'time': 0}))
        self.queue()
        job = self.run_upgrade(self.commits[1])
        self.assertEqual((job['state'], job['phase']), ('queued', 'images'))
        self.assertEqual(self.setup_calls(), [])

    def test_symlink_in_sources_is_refused(self):
        (self.work/'scripts/link').symlink_to('/etc/passwd')
        git(self.work, 'add', '-A')
        git(self.work, 'commit', '-q', '-m', 'link')
        linked = git(self.work, 'rev-parse', 'HEAD')
        git(self.work, 'push', '-q', str(self.base/'origin.git'), 'master')
        self.queue()
        job = self.run_upgrade(linked)
        self.assertEqual((job['state'], job['stage']), ('failed', 'source'))
        self.assertEqual(self.setup_calls(), [])

    def test_only_a_queued_upgrade_job_is_taken(self):
        state.atomic(self.store.root/'request.json', state.encode({'operation': 'restart', 'value': None}))
        state.atomic(self.store.root/'job.json', state.encode({'id': JOB, 'state': 'queued', 'time': 0}))
        self.assertEqual(self.run_upgrade(self.commits[1])['state'], 'queued')
        self.assertEqual(self.setup_calls(), [])


class ManagerUpgrade(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='vpnbot-manager-upgrade-')
        self.addCleanup(temp.cleanup)
        self.store = state.Store(Path(temp.name)/'state')
        self.store.activate(self.store.create(VALUE))
        self.runtime = SimpleNamespace(status=lambda: {'running': True}, pull=lambda image: None,
                                       validate=lambda g: None, apply=lambda g: None, host={})
        self.manager = manager.Manager(self.store, self.runtime)

    def test_submit_starts_upgrade_unit_and_worker_leaves_code_phase(self):
        with patch('node_manager.command') as command:
            self.manager.submit({'operation': 'upgrade', 'value': 'dev'})
        command.assert_called_once_with(['systemctl', 'start', '--no-block', manager.UPGRADE_UNIT], timeout=5)
        self.manager.worker()
        self.assertEqual(self.store.read('job.json')['state'], 'queued')
        with self.assertRaises(ValueError):
            manager.operation({'operation': 'upgrade', 'value': 'nightly'})

    def test_image_phase_requires_bundle_of_installed_commit(self):
        source = 'a'*40
        bundle = {'source': source, 'images': {'xr': 'ghcr.io/axiomshiftbit/vpnbot-xr@sha256:'+'1'*64}}
        state.atomic(self.store.root/upgrade.RELEASE, json.dumps(bundle).encode())
        with patch('image_bundle.read', side_effect=lambda path: json.loads(Path(path).read_text())):
            state.atomic(self.store.root/'code.json', state.encode({'source': 'b'*40, 'time': 0}))
            with self.assertRaisesRegex(ValueError, 'differ'):
                self.manager.execute({'operation': 'upgrade', 'value': 'latest'})
            state.atomic(self.store.root/'code.json', state.encode({'source': source, 'time': 0}))
            result = self.manager.execute({'operation': 'upgrade', 'value': 'latest'})
        self.assertEqual(self.store.load(result['pending']['after'])['images']['xr'], bundle['images']['xr'])

    def test_optional_images_follow_confirmed_update_and_manual_rollback(self):
        original = image_manifest('a'*40)
        full = image_manifest('b'*40)
        images_only = image_manifest('c'*40)
        # An unchanged Xray digest alone cannot distinguish these releases.
        for name in ('wg', 'ad'):
            # An image of a removed node service must never be acquired.
            prefix = upgrade.image_bundle.REGISTRY + name + '@sha256:'
            full['images'][name] = prefix + 'c'*64
            images_only['images'][name] = prefix + 'd'*64
        state.atomic(self.store.root/'release.json', state.encode(original))
        state.atomic(self.store.root/upgrade.RELEASE, state.encode(full))
        state.atomic(self.store.root/upgrade.CODE, state.encode({'source': full['source']}))
        runtime = Runtime(self.store, HOST)
        service = manager.Manager(self.store, runtime)

        def apply(operation, value):
            result = service.execute({'operation': operation, 'value': value})
            self.store.confirm(result['pending']['nonce'])

        def fetch(channel, path):
            state.atomic(path, state.encode(images_only))

        with patch.object(runtime, 'pull'), patch.object(runtime, 'apply'), patch.object(runtime, 'validate'):
            apply('upgrade', 'dev')
            with patch('image_bundle.fetch', side_effect=fetch):
                apply('update', 'latest')
            self.assertEqual(upgrade.images_source(self.store), images_only['source'])
            apply('rollback', None)
            self.assertEqual(upgrade.images_source(self.store), full['source'])
            apply('configure', self.store.load()['options'] | {'warp_mode': 'wireguard', 'adguard': {'enabled': True}})
        self.assertEqual(self.store.load()['images'], {name: full['images'][name] for name in ('xr', 'wg')})

    def test_legacy_generation_with_ambiguous_digests_does_not_mix_optional_images(self):
        full, normal = image_manifest('b'*40), image_manifest('c'*40)
        normal['images']['wg'] = upgrade.image_bundle.REGISTRY + 'wg@sha256:' + 'd'*64
        state.atomic(self.store.root/'release.json', state.encode(normal))
        state.atomic(self.store.root/upgrade.RELEASE, state.encode(full))
        runtime = Runtime(self.store, HOST)
        config = self.store.load()
        config['options']['warp_mode'] = 'wireguard'
        with patch.object(runtime, 'pull') as pull, self.assertRaisesRegex(ValueError, 'matching image bundle'):
            runtime.ensure_images(config)
        pull.assert_not_called()
        self.assertNotIn('wg', config['images'])

    def test_first_update_preserves_a_legacy_generations_bundle_for_rollback(self):
        original = image_manifest('a'*40)
        later = image_manifest('b'*40, xr=upgrade.image_bundle.REGISTRY + 'xr@sha256:' + 'd'*64)
        state.atomic(self.store.root/'release.json', state.encode(original))
        with patch('image_bundle.fetch', side_effect=lambda channel, path: state.atomic(path, state.encode(later))):
            update = self.manager.execute({'operation': 'update', 'value': 'latest'})
        self.store.confirm(update['pending']['nonce'])
        rollback = self.manager.execute({'operation': 'rollback', 'value': None})
        self.store.confirm(rollback['pending']['nonce'])
        self.assertEqual(upgrade.images_source(self.store), original['source'])

    def test_reenabling_a_cover_replaces_a_legacy_inactive_image(self):
        manifest = image_manifest('c'*40)
        state.atomic(self.store.root/'release.json', state.encode(manifest))
        current = self.store.load()
        current['images']['ng'] = upgrade.image_bundle.REGISTRY + 'ng@sha256:' + 'd'*64
        current['options']['domain'] = 'node.example.test'
        current['identity']['cover_auth'] = '$2y$10$' + 'a'*53
        current['tls'] = {name: base64.b64encode(b'-----BEGIN FIXTURE-----\n').decode()
                          for name in ('fullchain.pem', 'privkey.pem')}
        self.store.activate(self.store.create(current))
        runtime = Runtime(self.store, HOST | {'cover_uid': 997})
        service = manager.Manager(self.store, runtime)
        with patch.object(runtime, 'pull'), patch.object(runtime, 'apply'), patch.object(runtime, 'validate'):
            enable = service.execute({'operation': 'configure', 'value': current['options'] | {'cover': True}})
            self.store.confirm(enable['pending']['nonce'])
            self.assertEqual(self.store.load()['images']['ng'], manifest['images']['ng'])
            disable = service.execute({'operation': 'configure', 'value': current['options']})
            self.store.confirm(disable['pending']['nonce'])
        self.assertNotIn('ng', self.store.load()['images'])

    def test_recovery_watches_upgrade_unit_during_code_phase(self):
        state.atomic(self.store.root/'request.json', state.encode({'operation': 'upgrade', 'value': 'latest'}))
        state.atomic(self.store.root/'job.json', state.encode({'id': JOB, 'state': 'running', 'phase': 'code', 'time': 0}))
        with patch('node_manager.command', return_value=SimpleNamespace(stdout=b'active\n')) as command:
            self.manager.recover_job()
        self.assertIn(manager.UPGRADE_UNIT, command.call_args.args[0])
        self.assertEqual(self.store.read('job.json')['state'], 'running')
        with patch('node_manager.command', return_value=SimpleNamespace(stdout=b'failed\n')):
            self.manager.recover_job()
        self.assertEqual(self.store.read('job.json')['state'], 'failed')

    def test_status_reports_capability_and_installed_commit(self):
        self.assertEqual(self.manager.rpc({'action': 'status'})['code'], {'source': None, 'upgrade': True, 'origin': None, 'images': None})
        state.atomic(self.store.root/'code.json', state.encode({'source': 'c'*40, 'time': 0}))
        code = self.manager.rpc({'action': 'status'})['code']
        self.assertEqual((code['source'], code['origin']), ('c'*40, 'button'))


if __name__ == '__main__':
    unittest.main()
