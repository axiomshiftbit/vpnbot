import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('protocol_modules_acme', Path(__file__).resolve().parents[1] / 'scripts/protocol_modules.py')
modules = importlib.util.module_from_spec(spec)
spec.loader.exec_module(modules)


class AcmeWebrootPermissions(unittest.TestCase):
    def test_restrictive_umask_allows_challenge_traversal_without_exposing_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = os.umask(0o077)
            try:
                modules.ensure_self_certificate(root)
            finally:
                os.umask(old)
            for path in [root / 'certs', root / 'certs/.well-known', root / 'certs/.well-known/acme-challenge']:
                self.assertTrue(path.is_dir(), str(path))
                self.assertEqual(path.stat().st_mode & 0o111, 0o111)
                self.assertEqual(path.stat().st_mode & 0o022, 0)
            self.assertEqual((root / 'certs/self_private').stat().st_mode & 0o777, 0o600)

    def test_existing_certificate_is_preserved_while_webroot_is_repaired(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            certs = root / 'certs'
            certs.mkdir(mode=0o700)
            for name in ('self_public', 'self_private'):
                (certs / name).write_bytes(b'synthetic fixture, never a production key')
                (certs / name).chmod(0o600)
            modules.ensure_self_certificate(root)
            self.assertEqual(certs.stat().st_mode & 0o111, 0o111)
            self.assertEqual((certs / 'self_private').read_bytes(), b'synthetic fixture, never a production key')
            self.assertEqual((certs / 'self_private').stat().st_mode & 0o777, 0o600)

    def test_webroot_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            other = root / 'other'
            other.mkdir(mode=0o700)
            (root / 'certs').symlink_to(other, target_is_directory=True)
            with self.assertRaises((ValueError, RuntimeError)):
                modules.ensure_self_certificate(root)
            self.assertEqual(list(other.iterdir()), [])
            self.assertEqual(other.stat().st_mode & 0o777, 0o700)


if __name__ == '__main__':
    unittest.main()
