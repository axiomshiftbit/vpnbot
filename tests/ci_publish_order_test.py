"""CI-02 (audit A): a dev publication prepares the immutable commit reference
before it moves the working channel, so a failure never leaves bundle-dev
switched while the publish job fails and master cannot be promoted."""
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import ci_publish_bundle as publish  # noqa: E402
import image_bundle as bundles  # noqa: E402

SOURCE = 'a' * 40
DIGEST = 'sha256:' + 'c' * 64


def bundle():
    return dict(schema=1, source=SOURCE, run=123, attempt=1, state_epoch=1,
                images={name: bundles.REGISTRY + name + '@sha256:' + '%064x' % index for index, name in enumerate(bundles.IMAGES, 1)})


class PublishOrderTest(unittest.TestCase):
    def publish(self, fail_reference):
        moved = []
        reference = bundles.source_reference(SOURCE)

        def command(*args):
            if args[:2] == ('gh', 'api'):
                return SOURCE
            if args[:4] == ('docker', 'buildx', 'imagetools', 'create'):
                if args[6] == reference and fail_reference:
                    raise RuntimeError('docker operation failed')
                moved.append(args[6])
            return DIGEST if '--format' in args else ''

        value = bundle()
        with tempfile.TemporaryDirectory() as directory:
            manifest, evidence = Path(directory) / 'bundle.json', Path(directory) / 'native.json'
            manifest.write_bytes(bundles.canonical(value)); evidence.write_text('{}')
            env = dict(CHECKS='{}', EXPECTED_BUNDLE=bundles.fingerprint(value), GITHUB_SHA=SOURCE, GITHUB_REF_NAME='dev',
                       CI_REPORT_DIRECTORY='unused', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REPOSITORY='axiomshiftbit/vpnbot')
            with patch.dict(os.environ, env, clear=True), patch.object(publish, 'command', command), \
                    patch.object(publish, 'admit', lambda *a, **k: None), \
                    patch.object(publish.release_policy, 'collect', return_value={'warnings': []}), patch('sys.stdout', io.StringIO()), \
                    patch.object(sys, 'argv', ['ci_publish_bundle.py', str(manifest), str(evidence)]), \
                    patch.object(publish.retrying.__globals__['time'], 'sleep'):
                try:
                    publish.main()
                    failed = False
                except RuntimeError:
                    failed = True
        return failed, moved, reference

    def test_failed_commit_reference_leaves_the_channel_untouched(self):
        failed, moved, _ = self.publish(fail_reference=True)
        self.assertTrue(failed)
        self.assertNotIn(bundles.BUNDLE_REPO + ':bundle-dev', moved, 'bundle-dev moved although publication failed')

    def test_successful_publication_creates_reference_then_moves_channel(self):
        failed, moved, reference = self.publish(fail_reference=False)
        self.assertFalse(failed)
        self.assertEqual(moved[-2:], [reference, bundles.BUNDLE_REPO + ':bundle-dev'])


if __name__ == '__main__':
    unittest.main()
