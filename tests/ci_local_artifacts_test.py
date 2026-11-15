#!/usr/bin/env python3
"""Real files: CI handoff, corruption, run isolation and safe cleanup."""
import concurrent.futures
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import ci_local_artifacts as artifacts


class LocalArtifactsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name).resolve()
        self.store = self.make_store()

    def make_store(self, run='100', attempt='1', source='a' * 40):
        return artifacts.Store(self.work / 'store', run, attempt, source, self.work)

    def upload(self, name='image-bundle', value=None, store=None):
        source = self.work / 'input' / artifacts.FILES[name]
        source.parent.mkdir(exist_ok=True)
        content = json.dumps(value or {'example': 'synthetic'}, ensure_ascii=False).encode()
        source.write_bytes(content)
        (store or self.store).upload(name, str(source))
        return content

    def test_round_trip_preserves_bytes_and_private_store(self):
        content = self.upload(value={'label': 'проверка', 'format': '\n'})
        self.store.download('image-bundle', '', False, str(self.work / 'out'))
        self.assertEqual((self.work / 'out/bundle.json').read_bytes(), content)
        self.assertEqual(self.store.root.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.store.directory / 'image-bundle.json').stat().st_mode & 0o777, 0o600)

    def test_download_to_runner_temp_itself(self):
        content = self.upload('native-admission')
        self.store.download('native-admission', '', False, str(self.work))
        self.assertEqual((self.work / 'native.json').read_bytes(), content)

    def test_parallel_descriptors_and_merge(self):
        names = [n for n in artifacts.FILES if n.startswith('descriptor-')]
        with concurrent.futures.ThreadPoolExecutor(4) as executor:
            list(executor.map(self.upload, names))
        self.store.download('', 'descriptor-*', True, str(self.work / 'out'))
        self.assertEqual({p.name for p in (self.work / 'out').iterdir()}, {artifacts.FILES[n] for n in names})

    def test_missing_descriptor_fails_before_any_output(self):
        self.upload('descriptor-php')
        with self.assertRaises(FileNotFoundError):
            self.store.download('', 'descriptor-*', True, str(self.work / 'out'))
        self.assertFalse((self.work / 'out').exists())

    def test_all_admission_reports_are_required_and_survive_failed_job_retry(self):
        names = sorted(n for n in artifacts.FILES if n.startswith('admission-'))
        extra = {'admission-components', 'admission-security-assets', 'admission-unit-host',
                 'admission-unit-alpine84', 'admission-unit-alpine85'}
        self.assertEqual(set(names), extra | {'admission-security-'+image for image in artifacts.IMAGES})
        for name in names[:-1]: self.upload(name)
        retry = self.make_store(attempt='2')
        with self.assertRaises(FileNotFoundError):
            retry.download('', 'admission-*', True, str(self.work/'out'))
        self.assertFalse((self.work/'out').exists())
        self.upload(names[-1], store=retry)
        retry.download('', 'admission-*', True, str(self.work/'out'))
        self.assertEqual({p.name for p in (self.work/'out').iterdir()}, {artifacts.FILES[n] for n in names})

    def test_failed_job_retry_reuses_prior_attempt_but_not_another_run_or_commit(self):
        content = self.upload()
        retry = self.make_store(attempt='2')
        retry.download('image-bundle', '', False, str(self.work / 'out'))
        self.assertEqual((self.work / 'out/bundle.json').read_bytes(), content)
        for store in (self.make_store(run='101'), self.make_store(source='b' * 40)):
            with self.assertRaises(FileNotFoundError):
                store.download('image-bundle', '', False, str(self.work / 'other'))
        self.upload(value={'new': True}, store=retry)
        with self.assertRaises(ValueError):
            self.upload()
        with self.assertRaises(ValueError):
            self.store.download('image-bundle', '', False, str(self.work / 'old'))

    def test_corruption_and_wrong_identity_never_reach_output(self):
        for field, value in (('sha256', '0' * 64), ('content', '{}'), ('attempt', 0),
                             ('identity', {'run': '101', 'source': 'a' * 40}), ('name', 'native-admission')):
            with self.subTest(field=field):
                self.store.cleanup()
                self.upload()
                path = self.store.directory / 'image-bundle.json'
                envelope = json.loads(path.read_bytes())
                envelope[field] = value
                path.write_text(json.dumps(envelope))
                with self.assertRaises(ValueError):
                    self.store.download('image-bundle', '', False, str(self.work / 'out'))
                self.assertFalse((self.work / 'out').exists())

    def test_unsupported_paths_names_files_and_empty_glob(self):
        self.upload()
        for name, path in (('../escape', str(self.work / 'input/bundle.json')),
                           ('image-bundle', str(self.work / 'input/absent*.json')),
                           ('image-bundle', str(self.work / 'input')),
                           ('image-bundle', str(self.work / 'input/../input/bundle.json'))):
            with self.subTest(name=name, path=path), self.assertRaises(ValueError):
                self.store.upload(name, path)
        for destination in (str(self.work.parent / 'escape'), str(self.work / '../escape')):
            with self.assertRaises(ValueError):
                self.store.download('image-bundle', '', False, destination)
        with self.assertRaises(ValueError):
            self.store.download('', '*', True, str(self.work / 'out'))

    def test_symlink_and_hardlink_inputs_and_outputs_rejected(self):
        self.upload()
        source = self.work / 'linked'
        source.mkdir()
        link = source / 'bundle.json'
        link.symlink_to(self.work / 'input/bundle.json')
        with self.assertRaises(ValueError):
            self.store.upload('image-bundle', str(link))
        link.unlink()
        os.link(self.work / 'input/bundle.json', link)
        with self.assertRaises(ValueError):
            self.store.upload('image-bundle', str(link))
        (self.work / 'out').symlink_to(self.work / 'input', target_is_directory=True)
        with self.assertRaises(ValueError):
            self.store.download('image-bundle', '', False, str(self.work / 'out'))

    def test_non_json_oversized_and_fifo_inputs_rejected(self):
        path = self.work / 'bundle.json'
        for data in (b'not JSON', b'[]', b' ' * (artifacts.MAX_BYTES + 1)):
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                self.store.upload('image-bundle', str(path))
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises(ValueError):
            self.store.upload('image-bundle', str(path))

    def test_cleanup_only_own_run_and_expired_store_directories(self):
        self.upload()
        recent = self.make_store(run='101')
        expired = self.make_store(run='102')
        self.upload(store=recent)
        self.upload(store=expired)
        old = time.time() - artifacts.RETENTION - 10
        os.utime(expired.directory, (old, old))
        foreign = self.store.root / 'unrelated'
        foreign.mkdir()
        os.utime(foreign, (old, old))
        self.store.cleanup()
        self.assertFalse(self.store.directory.exists())
        self.assertFalse(expired.directory.exists())
        self.assertTrue(recent.directory.exists())
        self.assertTrue(foreign.exists())
        self.store.cleanup()  # idempotent

    def test_run_path_traversal_and_non_private_store_rejected(self):
        for kwargs in ({'run': '../100'}, {'attempt': '0'}, {'source': '../' + 'a' * 40}):
            with self.assertRaises(ValueError):
                self.make_store(**kwargs)
        self.store.root.mkdir(mode=0o755)
        self.store.root.chmod(0o755)  # Keep this unsafe fixture independent of the caller's umask.
        with self.assertRaises(ValueError):
            self.upload()


if __name__ == '__main__':
    unittest.main()
