"""Registration/full result checks; runner subprocess uses explicit unit stubs."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT/'tests/integration/fixtures/tests/published-main'
spec = importlib.util.spec_from_file_location('native_registry_test', BASE/'registry.py')
registry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registry)


class NativeDiscoveryTest(unittest.TestCase):
    def test_repository_cases_are_all_classified_and_include_protocols(self):
        cases = registry.load_cases(BASE)
        self.assertIn('trusttunnel_native', cases)
        self.assertIn('adguard', cases)
        self.assertIn('xdrive_native', cases)
        self.assertNotIn('proxy_helpers', cases)

    def test_new_missing_or_duplicate_fixture_fails_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for name in registry.CASES + tuple(registry.HELPERS):
                (base/(name+'.py')).touch()
            self.assertEqual(registry.load_cases(base), list(registry.CASES))
            extra = base/'forgotten_case.py';extra.touch()
            with self.assertRaisesRegex(ValueError, 'unregistered'):
                registry.load_cases(base)
            extra.unlink(); (base/(registry.CASES[0]+'.py')).unlink()
            with self.assertRaisesRegex(ValueError, 'missing'):
                registry.load_cases(base)
            with patch.object(registry, 'CASES', ('duplicate', 'duplicate')):
                with self.assertRaisesRegex(ValueError, 'registry'):
                    registry.load_cases(base)

    def test_exact_results_required_before_and_after_restore(self):
        cases = registry.load_cases(BASE)
        rows = [dict(case=n, exit=0, passed=1, total=1) for n in cases]
        self.assertTrue(registry.validate_results(rows, cases))
        for bad in (rows[:-1], rows[:-1]+[rows[0]], rows+[rows[0]],
                    [dict(rows[0], passed=0)]+rows[1:], [dict(rows[0], exit=False)]+rows[1:]):
            with self.subTest(count=len(bad)), self.assertRaises(ValueError):
                registry.validate_results(bad, cases)
        script = (ROOT/'tests/integration/suite/run.py').read_text()
        self.assertIn('case_registry.validate_results(rows,expected_cases)', script)
        self.assertIn("native('native-before-restore')", script)
        self.assertIn("native('native-after-restore')", script)

    def test_real_runner_executes_every_registered_unit_stub(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            shutil.copyfile(BASE/'run.py', base/'run.py')
            code = (BASE/'registry.py').read_text() + "\nCASES=('first','second')\nHELPERS={'run','registry'}\n"
            (base/'registry.py').write_text(code)
            for name in ('first', 'second'):
                (base/(name+'.py')).write_text("print('{\"passed\":1,\"total\":1}')\n")
            value = subprocess.run([sys.executable, str(base/'run.py')], capture_output=True, timeout=20)
            self.assertEqual(value.returncode, 0, value.stderr.decode())
            rows = json.loads((base/'results.json').read_text())
            self.assertEqual([r['case'] for r in rows], ['first', 'second'])
            (base/'forgotten.py').write_text("raise SystemExit('must not execute')")
            value = subprocess.run([sys.executable, str(base/'run.py')], capture_output=True, timeout=20)
            self.assertNotEqual(value.returncode, 0)
            self.assertNotIn(b'START', value.stdout)


if __name__ == '__main__':
    unittest.main()
