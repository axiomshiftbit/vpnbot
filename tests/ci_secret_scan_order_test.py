"""CI-03 (audit A): repository files are scanned for secrets before any job
pushes candidate images to the registry (in the public repository the
packages are public). The bundle job keeps its own scan with private markers."""
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCAN = 'python3 scripts/ci_scan_layers.py --tree .'


class SecretScanOrderTest(unittest.TestCase):
    def setUp(self):
        self.images = yaml.safe_load((ROOT / '.github/workflows/images.yml').read_text())['jobs']
        self.tests = yaml.safe_load((ROOT / '.github/workflows/tests.yml').read_text())['jobs']

    def test_every_pushing_job_waits_for_a_tree_scan(self):
        pushing = [name for name, job in self.images.items()
                   if any(step.get('with', {}).get('push') in (True, 'true') for step in job.get('steps', []))]
        self.assertIn('build', pushing)
        for name in pushing:
            needs = self.images[name].get('needs', [])
            needs = [needs] if isinstance(needs, str) else needs
            self.assertIn('tests', needs, name)
        self.assertEqual(self.images['tests'].get('uses'), './.github/workflows/tests.yml')
        steps = [step.get('run', '') for step in self.tests['tests']['steps']]
        self.assertTrue(any(SCAN in run for run in steps), 'tests job has no repository secret scan')
        # The scan precedes the long unit suites, so a leak stops the run early.
        index = next(i for i, run in enumerate(steps) if SCAN in run)
        self.assertLess(index, 6)

    def test_bundle_job_keeps_the_private_marker_scan(self):
        self.assertTrue(any(SCAN in step.get('run', '') for step in self.images['bundle']['steps']))


if __name__ == '__main__':
    unittest.main()
