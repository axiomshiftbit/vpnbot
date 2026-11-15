import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location('protocol_modules', Path(__file__).resolve().parents[1] / 'scripts/protocol_modules.py')
modules = importlib.util.module_from_spec(spec)
spec.loader.exec_module(modules)


class FreshPortsTests(unittest.TestCase):
    def test_clean_install_has_requested_external_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertTrue(modules.fresh_minimal(root))
            self.assertTrue((root / 'docker-compose.override.yml').is_file())
            content = (root / 'docker-compose.override.yml').read_text()
            for binding in ('51820:51820/udp', '51821:51820/udp', '9443:443/tcp', '5443:443/udp'):
                self.assertIn('"' + binding + '"', content)
            self.assertEqual(modules.FRESH, modules.settings(root))

    def test_existing_override_is_never_replaced_even_when_empty(self):
        for content in ('', 'services:\n  telemt:\n    ports: ["12345:443/tcp"]\n'):
            with self.subTest(content=bool(content)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                override = root / 'docker-compose.override.yml'
                override.write_text(content)
                self.assertTrue(modules.fresh_minimal(root))
                self.assertEqual(content, override.read_text())
                self.assertFalse(modules.fresh_minimal(root))
                self.assertEqual(content, override.read_text())

    def test_existing_installation_does_not_gain_new_bindings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'config').mkdir()
            (root / 'config/protocol-services.json').write_text('{}')
            self.assertFalse(modules.fresh_minimal(root))
            self.assertFalse((root / 'docker-compose.override.yml').exists())


if __name__ == '__main__':
    unittest.main()
