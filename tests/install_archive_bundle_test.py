"""INS-03: an archive installation without .git starts the image-set mechanism.

GitHub "Download ZIP" and `git archive` write the commit id as the ZIP comment.
The installer records it; ensure() then selects the published image set of
exactly that commit instead of failing on `git rev-parse`.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bundle_archive', ROOT / 'scripts/image_bundle.py')
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)
SOURCE = 'c' * 40


def candidate(source=SOURCE):
    return dict(schema=1, source=source, run=123, attempt=1, state_epoch=1,
                images={name: bundle.REGISTRY + name + '@sha256:' + 'b' * 64 for name in bundle.IMAGES})


class ArchiveInstallTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.tmp = Path(directory.name)
        self.root = self.tmp / 'vpnbot'
        (self.root / 'update').mkdir(parents=True)

    def archive(self, comment):
        path = self.tmp / 'vpnbot.zip'
        with zipfile.ZipFile(path, 'w') as z:
            z.writestr('vpnbot-dev/makefile', 'all:\n')
            z.comment = comment
        return path

    def record(self, archive):
        return subprocess.run([sys.executable, '-I', str(ROOT / 'scripts/image_bundle.py'), 'archive-source', str(archive),
                               '--root', str(self.root)], capture_output=True, text=True,
                              env={'PATH': os.environ.get('PATH', '/usr/bin:/bin')})

    def test_archive_without_git_selects_the_image_set_of_its_commit(self):
        result = self.record(self.archive(SOURCE.encode()))
        self.assertEqual(0, result.returncode, result.stderr)
        fetched = []

        def fetch_reference(ref, destination, admission=None):
            fetched.append(ref)
            value = candidate()
            bundle.atomic(Path(destination), bundle.canonical(value))
            return value
        with patch.dict(os.environ, {}, clear=True), patch.object(bundle, 'check_image_overrides'), \
                patch.object(bundle, 'fetch_reference', side_effect=fetch_reference):
            value = bundle.ensure(self.root)
            self.assertEqual(SOURCE, value['source'])
            self.assertEqual([bundle.source_reference(SOURCE)], fetched)
            self.assertEqual(SOURCE, bundle.read(self.root / 'update/image-bundle.json')['source'])
            # Restart of the same installation: no network, same image set.
            self.assertEqual(value, bundle.ensure(self.root))
            self.assertEqual(1, len(fetched))
            # Compose overlay selection compares the same recorded source.
            self.assertTrue(bundle.compose_files(self.root, {}))

    def test_archive_without_commit_id_or_marker_fails_clearly(self):
        for comment in (b'', b'not a commit', b'C' * 40, SOURCE.encode() + b'\n' + b'd' * 40):
            with self.subTest(comment=comment[:12]):
                result = self.record(self.archive(comment))
                self.assertNotEqual(0, result.returncode)
                self.assertFalse((self.root / 'update/archive-source').exists())
        # Nothing recorded: no image set is selected and nothing is activated.
        with patch.dict(os.environ, {}, clear=True), patch.object(bundle, 'check_image_overrides'), \
                patch.object(bundle, 'fetch_reference') as fetch, self.assertRaises((ValueError, RuntimeError)):
            bundle.ensure(self.root)
        fetch.assert_not_called()
        self.assertFalse((self.root / 'update/image-bundle.json').exists())
        # A damaged marker is rejected, never used as a registry reference.
        (self.root / 'update/archive-source').write_text('../../latest\n')
        with patch.dict(os.environ, {}, clear=True), patch.object(bundle, 'check_image_overrides'), \
                patch.object(bundle, 'fetch_reference') as fetch, self.assertRaisesRegex(ValueError, 'recorded source'):
            bundle.ensure(self.root)
        fetch.assert_not_called()

    def test_installer_records_the_commit_of_an_archive_without_git(self):
        source = (ROOT / 'scripts/init.sh').read_text()
        body = re.search(r'^install_from_archive\(\) \{.*?^\}\n', source, re.M | re.S).group()
        self.assertIn('scripts/image_bundle.py archive-source "$ARCHIVE"', body)


if __name__ == '__main__':
    unittest.main()
