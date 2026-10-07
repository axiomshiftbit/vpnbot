"""Правила, по которым комплект образов собирается и попадает в канал.

Послабления экономят пересборку, но не должны пропустить чужой образ: комплект
собирается только из образов своего запуска и коммита, а master получает без
пересборки только комплект, допущенный ровно для его коммита.
"""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import ci_promote_bundle as promote  # noqa: E402
import ci_publish_bundle as publish  # noqa: E402
import image_bundle as bundles  # noqa: E402

SOURCE, OTHER = 'a' * 40, 'b' * 40


def bundle(source=SOURCE, attempt=1):
    return dict(schema=1, source=source, run=123, attempt=attempt, state_epoch=1,
                images={name: bundles.REGISTRY + name + '@sha256:' + '%064x' % index
                        for index, name in enumerate(bundles.IMAGES, 1)})


class CollectTest(unittest.TestCase):
    def collect(self, descriptors, attempt):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'in').mkdir()
            for index, value in enumerate(descriptors):
                (root / 'in' / (str(index) + '.json')).write_text(json.dumps(value))
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/image_bundle.py'), 'collect', str(root / 'in'),
                                     str(root / 'bundle.json'), '--source', SOURCE, '--run', '123', '--attempt', str(attempt)],
                                    capture_output=True, text=True)
            return result.returncode, json.loads((root / 'bundle.json').read_text()) if result.returncode == 0 else None

    def descriptors(self, **changes):
        rows = [dict(image=name, digest='sha256:' + '%064x' % index, source=SOURCE, run=123, attempt=1)
                for index, name in enumerate(bundles.IMAGES, 1)]
        rows[0].update(changes)
        return rows

    def test_rebuilt_image_joins_images_of_an_earlier_attempt(self):
        code, result = self.collect(self.descriptors(attempt=2), 2)
        self.assertEqual(code, 0)
        self.assertEqual((result['source'], result['run'], result['attempt']), (SOURCE, 123, 2))
        self.assertEqual(len(result['images']), len(bundles.IMAGES))

    def test_same_attempt_still_accepted(self):
        self.assertEqual(self.collect(self.descriptors(), 1)[0], 0)

    def test_foreign_or_impossible_descriptor_rejected(self):
        for label, change, attempt in [('другой коммит', dict(source=OTHER), 2), ('другой запуск', dict(run=124), 2),
                                       ('попытка из будущего', dict(attempt=3), 2), ('нулевая попытка', dict(attempt=0), 2),
                                       ('попытка не число', dict(attempt='1'), 2), ('попытка bool', dict(attempt=True), 2)]:
            with self.subTest(label):
                self.assertNotEqual(self.collect(self.descriptors(**change), attempt)[0], 0)

    def test_incomplete_set_rejected(self):
        self.assertNotEqual(self.collect(self.descriptors()[1:], 1)[0], 0)


class PromoteTest(unittest.TestCase):
    def run_promote(self, *, branch='master', event='workflow_dispatch', full='', found=bundle(), remote=SOURCE):
        calls = []

        def command(*args):
            calls.append(args)
            if args[:2] == ('gh', 'api'):
                return remote
            return ''

        def fetch(ref, destination):
            calls.append(('fetch', ref))
            if found is None:
                raise RuntimeError('docker operation failed')
            return found

        env = dict(GITHUB_REF_NAME=branch, GITHUB_EVENT_NAME=event, GITHUB_SHA=SOURCE, FULL_BUILD=full,
                   GITHUB_REPOSITORY='axiomshiftbit/vpnbot')
        with patch.dict(os.environ, env, clear=True), patch.object(promote, 'command', command), \
                patch.object(promote, 'fetch_reference', fetch), patch('sys.stdout', io.StringIO()):
            try:
                return promote.promote(), calls
            except ValueError as error:
                return error, calls

    def test_master_takes_the_set_admitted_for_its_commit(self):
        result, calls = self.run_promote()
        self.assertIs(result, True)
        self.assertEqual(calls[0], ('fetch', bundles.BUNDLE_REPO + ':bundle-source-' + SOURCE))
        inspected = [c[-1] for c in calls if c[:4] == ('docker', 'buildx', 'imagetools', 'inspect')]
        self.assertEqual(sorted(inspected), sorted(bundle()['images'].values()))
        self.assertEqual(calls[-1], ('docker', 'buildx', 'imagetools', 'create', '--prefer-index=false', '--tag',
                                     bundles.BUNDLE_REPO + ':bundle-latest', bundles.BUNDLE_REPO + ':bundle-source-' + SOURCE))
        self.assertLess(calls.index(next(c for c in calls if c[:2] == ('gh', 'api'))), len(calls) - 1)

    def test_everything_else_builds_in_full_without_touching_the_registry(self):
        for label, options in [('dev', dict(branch='dev')), ('расписание', dict(event='schedule')),
                               ('принудительная сборка', dict(full='true'))]:
            with self.subTest(label):
                result, calls = self.run_promote(**options)
                self.assertIs(result, False)
                self.assertEqual(calls, [])

    def test_no_admitted_set_means_full_build(self):
        result, calls = self.run_promote(found=None)
        self.assertIs(result, False)
        self.assertEqual(len(calls), 1)

    def test_set_of_another_commit_is_an_error_not_a_fallback(self):
        result, calls = self.run_promote(found=bundle(source=OTHER))
        self.assertIsInstance(result, ValueError)
        self.assertFalse(any('bundle-latest' in ' '.join(c) for c in calls))

    def test_moved_branch_does_not_move_the_channel(self):
        result, calls = self.run_promote(remote=OTHER)
        self.assertIsInstance(result, ValueError)
        self.assertFalse(any('bundle-latest' in ' '.join(c) for c in calls))

    def test_reference_requires_a_full_commit(self):
        for value in ('', 'a' * 39, 'A' * 40, 'latest', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                bundles.source_reference(value)


class PublishTest(unittest.TestCase):
    def publish(self, branch, event='workflow_dispatch'):
        calls = []
        value = bundle()

        def command(*args):
            calls.append(args)
            return SOURCE if args[:2] == ('gh', 'api') else ''

        with tempfile.TemporaryDirectory() as directory:
            manifest, evidence = Path(directory) / 'bundle.json', Path(directory) / 'native.json'
            manifest.write_bytes(bundles.canonical(value))
            evidence.write_text('{}')
            env = dict(CHECKS='{}', EXPECTED_BUNDLE=bundles.fingerprint(value), GITHUB_SHA=SOURCE, GITHUB_REF_NAME=branch,
                       GITHUB_EVENT_NAME=event, GITHUB_REPOSITORY='axiomshiftbit/vpnbot')
            with patch.dict(os.environ, env, clear=True), patch.object(publish, 'command', command), \
                    patch.object(publish, 'admit', lambda *a: None), patch('sys.stdout', io.StringIO()), \
                    patch.object(sys, 'argv', ['ci_publish_bundle.py', str(manifest), str(evidence)]):
                publish.main()
        return [c[6] for c in calls if c[:4] == ('docker', 'buildx', 'imagetools', 'create')]

    def test_only_a_dev_publication_leaves_the_commit_reference(self):
        reference = bundles.BUNDLE_REPO + ':bundle-source-' + SOURCE
        dev = self.publish('dev')
        self.assertEqual(dev[-2:], [bundles.BUNDLE_REPO + ':bundle-dev', reference])
        self.assertNotIn(reference, self.publish('master'))
        self.assertNotIn(reference, self.publish('dev', 'schedule'))
        self.assertNotIn(reference, self.publish('feature'))


if __name__ == '__main__':
    unittest.main()
