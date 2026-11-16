"""Split native testing: shares of one run merge into one admission, nothing less."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('hosted_ci_split', ROOT / 'scripts/ci_hosted_test.py')
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)
from image_bundle import IMAGES  # noqa: E402
import ci_release_policy  # noqa: E402,F401 -- ci.evidence() imports it lazily
sys.path.pop(0)
spec = importlib.util.spec_from_file_location('isolated_cases', ROOT / 'tests/integration/suite/isolated_cases.py')
cases = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cases)

BUNDLE = dict(schema=1, source='a' * 40, run=1, attempt=1, state_epoch=1,
              images={name: ci.BUNDLE_REPO.removesuffix('php') + name + '@sha256:' + 'b' * 64 for name in IMAGES})
SUITE = 'c' * 64
GROUPS = [['backup-node-cold', 'naive-upgrade', 'mieru-idle', 'ocserv-upgrade'],
          ['telemt-native', 'snolc-native'], ['masque-native', 'hysteria-native']]


def counts(**values):
    return dict.fromkeys(ci.GROUPS, 0) | values


def shares():
    core = ci.part(BUNDLE, dict.fromkeys(ci.GROUPS, 10), SUITE, 'core')
    isolated = [ci.part(BUNDLE, counts(native=5, backup_restore=3 if 'backup-node-cold' in group else 0),
                        SUITE, 'isolated', group) for group in GROUPS]
    return [core] + isolated


class MergeTests(unittest.TestCase):
    def test_all_shares_of_this_run_give_the_usual_admission(self):
        result = ci.merge(BUNDLE, shares())
        self.assertEqual(result, ci.evidence(BUNDLE, counts(**{g: 10 for g in ci.GROUPS}) | {
            'native': 25, 'backup_restore': 13}, SUITE))
        self.assertEqual({'source', 'bundle', 'suite', 'status', 'checks'}, set(result))

    def test_a_missing_repeated_or_unknown_suite_is_rejected(self):
        parts = shares()
        for broken in (parts[:-1],                                   # missing group
                       parts + [parts[-1]],                          # repeated group
                       parts[:-1] + [dict(parts[-1], cases=['masque-native'])],
                       parts[:-1] + [dict(parts[-1], cases=['masque-native', 'hysteria-native', 'other'])],
                       parts[:-1] + [dict(parts[-1], cases=[])]):
            with self.subTest(broken=[p['cases'] for p in broken]), self.assertRaises(ValueError):
                ci.merge(BUNDLE, broken)

    def test_shares_of_another_candidate_or_suite_are_rejected(self):
        parts = shares()
        for key, value in (('source', 'd' * 40), ('bundle', 'e' * 64), ('suite', 'f' * 64), ('suite', 'short')):
            for index in (0, 2):
                broken = list(parts); broken[index] = dict(parts[index], **{key: value})
                with self.subTest(key=key, index=index), self.assertRaises(ValueError):
                    ci.merge(BUNDLE, broken)

    def test_exactly_one_core_without_cases(self):
        core, *isolated = shares()
        for broken in (isolated, [core, core] + isolated, [dict(core, cases=['masque-native'])] + isolated,
                       [core, dict(isolated[0], split='other')] + isolated[1:],
                       [dict(core, split=None)] + isolated):
            with self.subTest(splits=[p.get('split') for p in broken]), self.assertRaises(ValueError):
                ci.merge(BUNDLE, broken)

    def test_isolated_shares_carry_checks_and_no_warnings(self):
        core, *isolated = shares()
        empty = dict(isolated[1], counts=counts())
        warned = dict(isolated[1], warnings=[{'stage': 'native'}])
        for broken in (empty, warned):
            with self.assertRaises(ValueError):
                ci.merge(BUNDLE, [core, isolated[0], broken, isolated[2]])

    def test_malformed_counters_are_rejected(self):
        core, *isolated = shares()
        for bad in ({'native': True}, {'native': -1}, {'native': '1'}, {'profile': 1}):
            broken = dict(isolated[1], counts=isolated[1]['counts'] | bad)
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ci.merge(BUNDLE, [core, isolated[0], broken, isolated[2]])
            with self.assertRaises(ValueError):
                ci.part(BUNDLE, counts() | bad, SUITE, 'isolated', ['masque-native'])

    def test_a_core_group_without_checks_cannot_be_admitted(self):
        core, *isolated = shares()
        core = dict(core, counts=core['counts'] | {'update_rollback': 0})
        with self.assertRaises(ValueError):
            ci.merge(BUNDLE, [core] + isolated)


class SplitWiringTests(unittest.TestCase):
    def test_case_lists_agree(self):
        self.assertEqual(ci.ISOLATED, cases.CASES)
        self.assertEqual(sorted(sum(GROUPS, [])), sorted(cases.CASES))
        self.assertTrue(set(cases.NATIVE_MINI) <= set(cases.CASES))

    def test_stand_runs_every_self_contained_suite_only_through_shared_definitions(self):
        run = (ROOT / 'tests/integration/suite/run.py').read_text()
        for direct in ('node-cold.py', 'naive-upgrade/run.py', 'mieru-idle/run.py', 'ocserv-upgrade/run.py',
                       "('telemt-native',", "'Naive-H2-H3-auth-idle'"):
            self.assertNotIn(direct, run)
        self.assertIn("isolated_case('backup-node-cold')", run)
        self.assertIn("for name in ('naive-upgrade','mieru-idle','ocserv-upgrade'):isolated_case(name)", run)
        self.assertIn('for name in isolated.NATIVE_MINI:isolated_case(name)', run)
        self.assertIn("if SPLIT!='core':isolated.run_case(", run)

    def test_split_is_only_for_hosted_tests(self):
        for argv in (['test', '--local-test', '--cases', 'masque-native'], ['test', '--local-test', '--split', 'core'],
                     ['assets', '--cases', 'masque-native'], ['test', '--split', 'core', '--cases', 'masque-native'],
                     ['test', '--cases', 'masque-native,masque-native'], ['test', '--cases', 'unknown']):
            with self.subTest(argv=argv), patch.object(sys, 'argv', ['ci_hosted_test.py'] + argv), \
                    patch.object(ci, 'host') as host, patch.object(ci, 'test') as test, \
                    self.assertRaises(ValueError):
                ci.main()
            host.assert_not_called(); test.assert_not_called()

    def test_merge_action_writes_the_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            (directory / 'parts').mkdir()
            (directory / 'bundle.json').write_text(ci.canonical(BUNDLE).decode())
            for index, share in enumerate(shares()):
                (directory / 'parts' / ('share-%d.json' % index)).write_text(json.dumps(share))
            argv = ['ci_hosted_test.py', 'merge', '--manifest', str(directory / 'bundle.json'),
                    '--parts', str(directory / 'parts'), '--output', str(directory / 'native.json')]
            with patch.object(sys, 'argv', argv), patch.object(ci, 'read', return_value=BUNDLE), \
                    patch.object(ci, 'host') as host:
                ci.main()
            host.assert_not_called()
            self.assertEqual(json.loads((directory / 'native.json').read_text()), ci.merge(BUNDLE, shares()))


class IsolatedCaseTests(unittest.TestCase):
    def context(self, directory, run):
        counted = dict.fromkeys(ci.GROUPS, 0)
        passed = []

        def check(group, name, ok):
            if not ok:
                raise RuntimeError(name)
            counted[group] += 1; passed.append(name)
        retried = []

        def twice(name, attempt):
            try:
                return attempt()
            except RuntimeError:
                retried.append(name)
            return attempt()
        return dict(candidate=BUNDLE, checkout=directory, results=directory, run=run, check=check,
                    counts=counted, twice=twice), counted, passed, retried

    def test_counts_match_the_former_sequential_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)

            def run(name, cmd, timeout=180):
                rows = [{'passed': True}] * {'mieru-idle': 9, 'naive-upgrade': 15, 'ocserv-upgrade': 15}[name]
                (directory / name).mkdir(exist_ok=True)
                (directory / name / 'results.json').write_text(json.dumps(rows))
            ctx, counted, passed, _ = self.context(directory, run)
            for name in ('naive-upgrade', 'mieru-idle', 'ocserv-upgrade'):
                cases.run_case(name, ctx)
            self.assertEqual(counted['native'], 15 + 9 + 15 + 3)
            self.assertEqual(passed, ['Naive-H2-H3-auth-idle', 'Mieru-idle-old-client', 'ocserv-TLS13-DTLS-strict-config'])

    def test_short_or_failed_results_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)

            def run(name, cmd, timeout=180):
                (directory / name).mkdir(exist_ok=True)
                (directory / name / 'results.json').write_text(json.dumps([{'passed': True}] * 8 + [{'passed': False}]))
            ctx, *_ = self.context(directory, run)
            with self.assertRaises(RuntimeError):
                cases.run_case('mieru-idle', ctx)

    def test_native_mini_stand_is_retried_once_and_copied(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(cases, 'ROOT', Path(directory) / 'opt'):
            directory = Path(directory)
            (directory / 'opt/snolc-native').mkdir(parents=True)
            attempts = []

            def run(name, cmd, timeout=180):
                attempts.append(cmd)
                good = len(attempts) > 1
                (directory / 'opt/snolc-native/results.json').write_text(json.dumps(
                    [{'exit': 0, 'total': 4, 'passed': 4 if good else 3}]))
            ctx, counted, passed, retried = self.context(directory, run)
            cases.run_case('snolc-native', ctx)
            self.assertEqual((retried, len(attempts), counted['native']), (['snolc-native'], 2, 4 + 1))
            self.assertTrue((directory / 'snolc-native.json').is_file())
            self.assertEqual(attempts[0][2:], [str(directory), BUNDLE['images']['snolc'], BUNDLE['images']['php']])

    def test_unknown_case_is_rejected(self):
        with self.assertRaises(ValueError):
            cases.run_case('other', dict(candidate=BUNDLE, results=Path('.'), run=None, check=None,
                                         counts={}, twice=None, checkout=Path('.')))


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.jobs = yaml.safe_load((ROOT / '.github/workflows/images.yml').read_text())['jobs']

    def test_matrix_covers_every_self_contained_suite_once(self):
        matrix = self.jobs['native-isolated']['strategy']['matrix']['include']
        self.assertEqual(sorted(c for row in matrix for c in row['cases'].split(',')), sorted(cases.CASES))
        self.assertEqual(len({row['group'] for row in matrix}), len(matrix))
        self.assertFalse(self.jobs['native-isolated']['strategy']['fail-fast'])

    def test_isolated_jobs_do_nothing_on_the_home_runner(self):
        for step in self.jobs['native-isolated']['steps']:
            condition = step.get('if', '')
            self.assertTrue("runner.environment == 'github-hosted'" in condition
                            or "steps.diagnostics.outputs.produced == 'true'" in condition, step)
        for step in self.jobs['native-gate']['steps']:
            self.assertIn("runner.environment == 'github-hosted'", step.get('if', ''))

    def test_admission_comes_from_one_place_per_runner_kind(self):
        native = self.jobs['native']['steps']
        uploads = {s['with']['name']: s.get('if') for s in native if 'upload-artifact' in s.get('uses', '')
                   and not s['with']['name'].startswith('native-diagnostics')}
        self.assertEqual(uploads, {'native-admission': "runner.environment == 'self-hosted'",
                                   'native-part-core': "runner.environment == 'github-hosted'"})
        step = next(s['run'] for s in native if 'ci_hosted_test.py test' in s.get('run', ''))
        self.assertIn("(runner.environment == 'github-hosted') && '--split core' || ''", step)
        gate = self.jobs['native-gate']
        self.assertEqual(set(gate['needs']), {'bundle', 'native', 'native-isolated'})
        self.assertNotIn('always()', gate['if'])
        self.assertIn('native-gate', self.jobs['publish']['needs'])
        checks = next(s['env']['CHECKS'] for s in self.jobs['publish']['steps'] if 'CHECKS' in s.get('env', {}))
        self.assertIn('"native":"${{ needs.native-gate.result }}"', checks)

    def test_both_native_jobs_share_conditions_and_host_preparation(self):
        for name in ('native-isolated', 'native-gate'):
            self.assertEqual(self.jobs[name]['if'], self.jobs['native']['if'])
            self.assertEqual(self.jobs[name]['runs-on'], self.jobs['native']['runs-on'])
        for name in ('native', 'native-isolated'):
            self.assertTrue(any(s.get('uses') == './.github/actions/prepare-native-host' for s in self.jobs[name]['steps']))
        names = [s['with']['name'] for s in self.jobs['native-isolated']['steps'] if 'upload-artifact' in s.get('uses', '')]
        self.assertEqual(names, ['native-part-${{ matrix.group }}', 'native-diagnostics-encrypted-${{ matrix.group }}'])


if __name__ == '__main__':
    unittest.main()
