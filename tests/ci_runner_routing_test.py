import json
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def evaluate(expression, context):
    expression = expression.removeprefix('${{').removesuffix('}}').strip()
    expression = expression.replace('&&', ' and ').replace('||', ' or ')
    return eval(expression, {'__builtins__': {}, 'fromJSON': json.loads, 'always': lambda: True}, context)


class RunnerRoutingTest(unittest.TestCase):
    def test_host_checks_and_local_stand_follow_selected_runner(self):
        for workflow in ('tests', 'images'):
            jobs = yaml.safe_load((ROOT / f'.github/workflows/{workflow}.yml').read_text())['jobs']
            for repository, actor, enabled, variable in [('axiomshiftbit/vpnbot', 'axiomshiftbit', True, 'enabled'),
                                                         ('axiomshiftbit/vpnbot', 'contributor', True, 'enabled'),
                                                         ('other/vpnbot', 'other', True, 'enabled'),
                                                         ('axiomshiftbit/vpnbot', 'axiomshiftbit', False, 'enabled'),
                                                         ('axiomshiftbit/vpnbot', 'axiomshiftbit', True, '')]:
                for name, job in jobs.items():
                    if not isinstance(job.get('runs-on'), str) or 'fromJSON' not in job['runs-on']:
                        continue
                    context = {'github': SimpleNamespace(repository=repository, actor=actor, event_name='workflow_dispatch'),
                               'inputs': SimpleNamespace(home_runner=enabled),
                               'vars': SimpleNamespace(VPNBOT_HOME_RUNNER=variable)}
                    runner = evaluate(job['runs-on'], context)
                    local = isinstance(runner, list) and 'self-hosted' in runner
                    if not variable:
                        # Репозиторий без переменной (публичный): только серверы GitHub.
                        self.assertFalse(local, f'{workflow}/{name} ушёл на self-hosted без VPNBOT_HOME_RUNNER')
                    context['runner'] = SimpleNamespace(environment='self-hosted' if local else 'github-hosted')
                    for step in job.get('steps', []):
                        body = step.get('run', '')
                        with self.subTest(workflow=workflow, job=name, repository=repository, actor=actor, enabled=enabled):
                            if '/etc/vpnbot-ci-test-host' in body and 'if' in step:
                                self.assertEqual(bool(evaluate(step.get('if', 'True'), context)), local,
                                                 'Проверка HomeBuild попала на сервер GitHub')
                            for expression in re.findall(r'\$\{\{(.*?)\}\}', body, re.S):
                                if '--local-test' in expression:
                                    self.assertEqual(bool(evaluate(expression, context)), local,
                                                     'Режим локального стенда не соответствует runner')
