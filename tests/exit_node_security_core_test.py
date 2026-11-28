"""Защита соединения выходных узлов настоящими ядрами из матрицы CI."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get('VLESS_TEST_XRAY'), 'нужно VLESS_TEST_XRAY')
class ExitNodeSecurityCoreTest(unittest.TestCase):
    def test_authenticated_transports_and_vision_payload(self):
        cores = [os.environ['VLESS_TEST_XRAY']]
        if os.environ.get('XRAY_FORK_TEST_BINARY'):
            cores.append(os.environ['XRAY_FORK_TEST_BINARY'])
        for core in cores:
            self.assertTrue(os.access(core, os.X_OK), 'ядро должно быть исполняемым')
        result = subprocess.run(
            [sys.executable, str(ROOT / 'tests/integration/fixtures/exit-nodes/security_core.py'), *cores],
            capture_output=True, text=True, timeout=150,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        summary = json.loads(result.stdout.splitlines()[-1])
        self.assertEqual(30 if len(cores) == 2 else 24, summary['total'])
        self.assertEqual(summary['total'], summary['passed'], summary['results'])


if __name__ == '__main__':
    unittest.main()
