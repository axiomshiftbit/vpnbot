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

    def test_missing_explicit_bundle_and_explicit_rollback_pin_fail_closed(self):
        with self.assertRaises(ValueError): bundle.compose_files(self.root, {'VPNBOT_BUNDLE_FILE': str(self.root / 'absent')})
        bundle.atomic(self.root / 'update/image-bundle.json', bundle.canonical(candidate()))
        with patch.object(bundle, 'command', return_value='a' * 40), self.assertRaises(ValueError):
            bundle.compose_files(self.root, {'VPNBOT_TAG': 'sha-' + 'a' * 40})

    def test_simultaneous_writes_never_produce_a_mixed_manifest(self):
        path = self.root / 'bundle.json'; bundle.atomic(path, bundle.canonical(candidate()))
        code = ('import sys;sys.path.insert(0,sys.argv[1]);import image_bundle as b;'
                'v=b.read(sys.argv[2]);v["run"]=int(sys.argv[3]);b.atomic(sys.argv[2],b.canonical(v))')
        processes = [subprocess.Popen(['python3', '-c', code, str(ROOT / 'scripts'), str(path), str(n)]) for n in range(1, 13)]
        while any(p.poll() is None for p in processes): bundle.read(path)
        self.assertTrue(all(p.wait() == 0 for p in processes))
        self.assertIn(bundle.read(path)['run'], range(1, 13))


if __name__ == '__main__':
    unittest.main()
