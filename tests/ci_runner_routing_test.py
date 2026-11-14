import json
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]


class RunnerRoutingTest(unittest.TestCase):
    """Публичный репозиторий: только серверы GitHub, домашний runner недоступен никому."""

    def test_every_job_runs_on_github_hosted_ubuntu_only(self):
        for workflow in sorted((ROOT / '.github/workflows').glob('*.yml')):
            jobs = yaml.safe_load(workflow.read_text()).get('jobs', {})
            for name, job in jobs.items():
                if 'uses' in job:
                    continue
                with self.subTest(workflow=workflow.name, job=name):
                    runner = job.get('runs-on')
                    self.assertIsInstance(runner, str)
                    self.assertRegex(runner, r'^ubuntu-(latest|[0-9.]+)$')

    def test_no_home_runner_switches_remain(self):
        for path in sorted((ROOT / '.github').rglob('*.y*ml')):
            text = path.read_text()
            if path.name == 'actionlint.yaml':
                self.assertEqual([], yaml.safe_load(text)['self-hosted-runner']['labels'])
                continue
            with self.subTest(path=str(path.relative_to(ROOT))):
                for marker in ('vpnbot-home', 'home_runner', 'VPNBOT_HOME_RUNNER', 'runs-on: [self-hosted'):
                    self.assertNotIn(marker, text)
        self.assertNotIn('home_runner', (ROOT / 'scripts/ci_promote_master.py').read_text())


if __name__ == '__main__':
    unittest.main()
