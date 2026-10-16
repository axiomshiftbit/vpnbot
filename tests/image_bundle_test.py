import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bundle', ROOT / 'scripts/image_bundle.py')
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


def candidate():
    return dict(schema=1, source='a' * 40, run=123, attempt=1, state_epoch=1,
                images={name: bundle.REGISTRY + name + '@sha256:' + 'b' * 64 for name in bundle.IMAGES})


class ImageBundleTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def evidence(self, value):
        return dict(source=value['source'], bundle=bundle.fingerprint(value), status='success', checks=99, suite='c' * 64)

    def test_complete_set_covers_shared_and_optional_containers(self):
        value = candidate()
        overlay = bundle.overlay(value)['services']
        self.assertEqual(18, len(value['images']))
        self.assertEqual(26, len(overlay))
        for a, b in [('php', 'service'), ('wg', 'wp'), ('ng', 'dockerproxy'), ('anytls', 'tuic')]:
            self.assertEqual(overlay[a], overlay[b])

    def test_partial_extra_mutable_foreign_and_malformed_images_are_rejected(self):
        for mutation in ['missing', 'extra', 'tag', 'foreign', 'digest', 'source', 'schema', 'epoch', 'run', 'fields']:
            value = candidate()
            if mutation == 'missing': del value['images']['tt']
            if mutation == 'extra': value['images']['unexpected'] = value['images']['php']
            if mutation == 'tag': value['images']['php'] = bundle.REGISTRY + 'php:dev'
            if mutation == 'foreign': value['images']['php'] = value['images']['php'].replace('axiomshiftbit', 'other')
            if mutation == 'digest': value['images']['php'] += 'x'
            if mutation == 'source': value['source'] = 'dev'
            if mutation == 'schema': value['schema'] = 2
            if mutation == 'epoch': value['state_epoch'] = 2
            if mutation == 'run': value['run'] = True
            if mutation == 'fields': value['credentials'] = 'must never be published'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): bundle.validate(value)

    def test_every_unsuccessful_or_missing_gate_blocks_publication(self):
        value = candidate()
        passed = dict.fromkeys(('build', 'tests', 'security', 'native'), 'success')
        bundle.admit(value, self.evidence(value), passed)
        for job in passed:
            for state in ('failure', 'cancelled', 'skipped', 'in_progress', 'queued', None):
                with self.subTest(job=job, state=state), self.assertRaises(ValueError):
                    bundle.admit(value, self.evidence(value), passed | {job: state})
            partial = passed.copy(); del partial[job]
            with self.assertRaises(ValueError): bundle.admit(value, self.evidence(value), partial)

    def test_image_source_rerun_and_suite_substitution_invalidates_evidence(self):
        value = candidate(); evidence = self.evidence(value)
        statuses = dict.fromkeys(('build', 'tests', 'security', 'native'), 'success')
        for field in ('images', 'source', 'run', 'attempt'):
            changed = copy.deepcopy(value)
            if field == 'images': changed['images']['php'] = bundle.REGISTRY + 'php@sha256:' + 'd' * 64
            elif field == 'source': changed[field] = 'd' * 40
            else: changed[field] += 1
            with self.subTest(field=field), self.assertRaises(ValueError): bundle.admit(changed, evidence, statuses)
        for field, data in [('checks', 0), ('checks', True), ('status', 'skipped'), ('suite', '')]:
            with self.assertRaises(ValueError): bundle.admit(value, evidence | {field: data}, statuses)

    def test_code_mismatch_cannot_switch_active_set(self):
        active = self.root / 'update/image-bundle.json'
        original = candidate(); bundle.atomic(active, bundle.canonical(original))
        changed = copy.deepcopy(original); changed['source'] = 'c' * 40
        with patch.object(bundle, 'command', return_value=original['source']), self.assertRaises(ValueError):
            bundle.activate(self.root, changed)
        self.assertEqual(original, bundle.read(active))

    def test_bundle_without_snolc_is_accepted_only_as_previous(self):
        # Комплекты, выпущенные до возвращения snolc, нужны только для отката:
        # текущий комплект обязан закрепить образ каждого сервиса.
        old = candidate(); del old['images']['snolc']
        active = self.root / 'update/image-bundle.json'
        bundle.atomic(active, bundle.canonical(old))
        new = candidate(); new['run'] += 1
        with patch.object(bundle, 'command', return_value=new['source']): bundle.activate(self.root, new)
        self.assertEqual(new, bundle.read(active))
        previous = active.with_name('image-bundle.previous.json')
        self.assertEqual(old, bundle.read(previous, previous=True))
        with self.assertRaises(ValueError): bundle.read(previous)
        with self.assertRaises(ValueError): bundle.overlay(old)
        with patch.object(bundle, 'command', return_value=old['source']), self.assertRaises(ValueError):
            bundle.activate(self.root, old)
        self.assertEqual(new, bundle.read(active))
        del old['images']['php']
        with self.assertRaises(ValueError): bundle.validate(old, previous=True)

    def test_successful_switch_retains_previous_set_without_touching_runtime(self):
        active = self.root / 'update/image-bundle.json'
        original = candidate(); bundle.atomic(active, bundle.canonical(original))
        runtime = self.root / 'clients.json'; runtime.write_bytes(b'new-client-and-usage')
        changed = copy.deepcopy(original); changed['run'] += 1
        with patch.object(bundle, 'command', return_value=changed['source']): bundle.activate(self.root, changed)
        self.assertEqual(changed, bundle.read(active))
        self.assertEqual(original, bundle.read(active.with_name('image-bundle.previous.json')))
        self.assertEqual(b'new-client-and-usage', runtime.read_bytes())
        # Restarting the same set must not overwrite the rollback pointer.
        with patch.object(bundle, 'command', return_value=changed['source']): bundle.activate(self.root, changed)
        self.assertEqual(original, bundle.read(active.with_name('image-bundle.previous.json')))

    def test_disk_full_or_failed_rename_preserves_active_set(self):
        path = self.root / 'bundle.json'; original = bundle.canonical(candidate()); bundle.atomic(path, original)
        for target in ('fsync', 'replace'):
            with self.subTest(target=target), patch.object(bundle.os, target, side_effect=OSError('ENOSPC')):
                with self.assertRaises(OSError): bundle.atomic(path, b'new')
            self.assertEqual(original, path.read_bytes())
            self.assertEqual(['bundle.json'], sorted(p.name for p in self.root.iterdir()))

    def test_overlay_keeps_existing_compose_files_and_does_not_change_user_data(self):
        value = candidate(); path = self.root / 'bundle.json'; bundle.atomic(path, bundle.canonical(value))
        override = self.root / 'override.env'; override.write_text('TZ=Europe/Moscow\nPORT=1234\n')
        env = {'VPNBOT_BUNDLE_FILE': str(path), 'COMPOSE_FILE': 'docker-compose.yml:custom.yml'}
        files = bundle.compose_files(self.root, env)
        self.assertEqual(['-f', 'docker-compose.yml', '-f', 'custom.yml'], files[:4])
        self.assertEqual(bundle.overlay(value), json.loads(Path(files[-1]).read_text()))
        self.assertEqual('TZ=Europe/Moscow\nPORT=1234\n', override.read_text())

    def test_overlay_written_by_previous_code_is_replaced(self):
        # prepare установленного кода пишет overlay того же комплекта по своему
        # списку сервисов (мост: без snolc). Новый код не должен его принять.
        value = candidate(); path = self.root / 'update/image-bundle.json'; bundle.atomic(path, bundle.canonical(value))
        stale = bundle.overlay(value); del stale['services']['snolc']
        target = self.root / 'update' / ('compose-images-' + bundle.fingerprint(value) + '.json')
        bundle.atomic(target, bundle.canonical(stale))
        with patch.object(bundle, 'command', return_value='a' * 40):
            files = bundle.compose_files(self.root, {})
        self.assertEqual(str(target), files[-1])
        self.assertEqual(value['images']['snolc'], json.loads(target.read_text())['services']['snolc']['image'])

    def test_missing_explicit_bundle_and_explicit_rollback_pin_fail_closed(self):
        with self.assertRaises(ValueError): bundle.compose_files(self.root, {'VPNBOT_BUNDLE_FILE': str(self.root / 'absent')})
        bundle.atomic(self.root / 'update/image-bundle.json', bundle.canonical(candidate()))
        with patch.object(bundle, 'command', return_value='a' * 40), self.assertRaises(ValueError):
            bundle.compose_files(self.root, {'VPNBOT_TAG': 'sha-' + 'a' * 40})

    def test_custom_image_overrides_are_not_silently_replaced(self):
        for image in ('custom/php:tested', bundle.REGISTRY + 'php:sha-' + 'a' * 40,
                      candidate()['images']['php']):
            data = {'services': {'php': {'image': image}}}
            result = subprocess.CompletedProcess([], 0, json.dumps(data).encode(), b'')
            with self.subTest(image=image), patch.object(bundle.subprocess, 'run', return_value=result):
                with self.assertRaises(ValueError): bundle.check_image_overrides(self.root)
        for channel in ('dev', 'latest'):
            data = {'services': {'php': {'image': bundle.REGISTRY + 'php:' + channel}}}
            result = subprocess.CompletedProcess([], 0, json.dumps(data).encode(), b'')
            with patch.object(bundle.subprocess, 'run', return_value=result): bundle.check_image_overrides(self.root)

    def test_simultaneous_writes_never_produce_a_mixed_manifest(self):
        path = self.root / 'bundle.json'; bundle.atomic(path, bundle.canonical(candidate()))
        code = ('import sys;sys.path.insert(0,sys.argv[1]);import image_bundle as b;'
                'v=b.read(sys.argv[2]);v["run"]=int(sys.argv[3]);b.atomic(sys.argv[2],b.canonical(v))')
        processes = [subprocess.Popen(['python3', '-c', code, str(ROOT / 'scripts'), str(path), str(n)]) for n in range(1, 13)]
        while any(p.poll() is None for p in processes): bundle.read(path)
        self.assertTrue(all(p.wait() == 0 for p in processes))
        self.assertIn(bundle.read(path)['run'], range(1, 13))

    def test_prepare_registry_or_pull_failure_keeps_code_runtime_and_active_set(self):
        value = candidate()
        active = self.root / 'update/image-bundle.json'
        bundle.atomic(active, bundle.canonical(value))
        runtime = self.root / 'clients.json'; runtime.write_text('new client and current usage')
        for failure in ('registry', 'pull'):
            before = {p: p.read_bytes() for p in (active, runtime)}
            def invoke(args, **kwargs):
                if args[0] == 'git': return subprocess.CompletedProcess(args, 0)
                return subprocess.CompletedProcess(args, 1, b'', b'private registry error')
            with patch.object(bundle, 'check_image_overrides'), patch.object(bundle, 'command', return_value=''), \
                 patch.object(bundle.subprocess, 'run', side_effect=invoke), \
                 patch.object(bundle, 'fetch', side_effect=RuntimeError('registry unavailable') if failure == 'registry' else None,
                              return_value=value):
                with self.subTest(failure=failure), self.assertRaises(RuntimeError):
                    bundle.prepare(self.root, 'dev', self.root / 'pending.json')
            self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_no_network_is_needed_for_an_existing_matching_bundle(self):
        value = candidate(); bundle.atomic(self.root / 'update/image-bundle.json', bundle.canonical(value))
        with patch.dict(os.environ, {}, clear=True), patch.object(bundle, 'command', return_value=value['source']), \
             patch.object(bundle, 'check_image_overrides'), patch.object(bundle, 'fetch') as fetch:
            self.assertEqual(value, bundle.ensure(self.root))
            fetch.assert_not_called()
        with patch.dict(os.environ, {}, clear=True), patch.object(bundle, 'command', return_value='f' * 40):
            with self.assertRaises(ValueError): bundle.ensure(self.root)


if __name__ == '__main__':
    unittest.main()
