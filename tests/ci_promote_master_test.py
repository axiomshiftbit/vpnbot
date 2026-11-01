"""Автоматический перенос dev в master после публикации комплекта.

Ветка master двигается только вперёд и только на коммит, прошедший полный
прогон: всё остальное — отказ без изменений в репозитории.
"""
import io
import os
from pathlib import Path
import re
import sys
import unittest
import urllib.error
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import ci_promote_master as promote  # noqa: E402

TESTED, OLD, NEWER = 'a' * 40, 'b' * 40, 'c' * 40
ENV = {'GITHUB_SHA': TESTED, 'GITHUB_REF': 'refs/heads/dev', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
       'GITHUB_REPOSITORY': 'axiomshiftbit/vpnbot', 'PROMOTE_TOKEN': 'token'}


def http_error(code):
    return urllib.error.HTTPError('https://api.github.com', code, 'error', {}, io.BytesIO(b''))


class GitHub:
    def __init__(self, dev=TESTED, master=OLD, status='ahead', behind=0, patch_error=None, failures=None):
        self.heads = {'dev': dev, 'master': master}
        self.status, self.behind, self.patch_error = status, behind, patch_error
        self.failures = dict(failures or {})
        self.writes = []

    def __call__(self, path, secret, body=None, method=None):
        assert secret == 'token', 'the dedicated token must be used for every request'
        for prefix in list(self.failures):
            if path.startswith(prefix) and self.failures[prefix] > 0:
                self.failures[prefix] -= 1
                raise RuntimeError('GitHub is unreachable')
        if path.startswith('/git/ref/heads/'):
            return {'object': {'sha': self.heads[path.rsplit('/', 1)[1]]}}
        if path.startswith('/compare/'):
            assert path == '/compare/' + self.heads['master'] + '...' + TESTED
            return {'status': self.status, 'behind_by': self.behind}
        if path == '/git/refs/heads/master':
            assert method == 'PATCH' and body == {'sha': TESTED, 'force': False}, 'master may only be fast-forwarded'
            if self.patch_error:
                raise http_error(self.patch_error)
            self.heads['master'] = body['sha']
            self.writes.append('move')
            return {}
        if path == '/actions/workflows/images.yml/dispatches':
            assert set(body) == {'ref', 'inputs'} and body['ref'] == 'master' and set(body['inputs']) == {'home_runner'}
            self.dispatched = body['inputs']['home_runner']
            self.writes.append('dispatch')
            return {}
        raise AssertionError('unexpected request ' + path)


class PromoteMasterTest(unittest.TestCase):
    def run_main(self, github, **env):
        out, err = io.StringIO(), io.StringIO()
        values = {key: value for key, value in {**ENV, **env}.items() if value is not None}
        with patch.object(promote, 'api', github), patch.dict(os.environ, values, clear=True), \
                patch('ci_retry.time.sleep'), patch('sys.stdout', out), patch('sys.stderr', err):
            try:
                promote.main()
            except promote.Rejected as error:
                return str(error), github.writes, out.getvalue()
        return None, github.writes, out.getvalue()

    def test_master_behind_dev_is_moved_forward_and_the_master_run_is_started(self):
        github = GitHub()
        self.assertEqual(self.run_main(github)[:2], (None, ['move', 'dispatch']))
        self.assertEqual(github.heads['master'], TESTED)

    def test_github_hosted_run_starts_the_master_run_on_github_servers(self):
        github = GitHub()
        error, writes, _ = self.run_main(github, PROMOTE_HOME_RUNNER='false')
        self.assertIsNone(error)
        self.assertIn('dispatch', writes)
        self.assertEqual(github.dispatched, 'false')

    def test_master_already_on_the_commit_only_starts_the_master_run(self):
        self.assertEqual(self.run_main(GitHub(master=TESTED))[:2], (None, ['dispatch']))

    def test_commits_only_in_master_are_never_overwritten(self):
        for status, behind in (('diverged', 1), ('behind', 3), ('identical', 0), ('ahead', 1)):
            with self.subTest(status=status, behind=behind):
                error, writes, _ = self.run_main(GitHub(status=status, behind=behind))
                self.assertIn('master has commits', error)
                self.assertEqual(writes, [])

    def test_dev_that_moved_on_is_not_promoted(self):
        error, writes, _ = self.run_main(GitHub(dev=NEWER))
        self.assertIn('dev has moved on', error)
        self.assertEqual(writes, [])

    def test_only_a_manual_run_of_dev_is_promoted(self):
        for change in ({'GITHUB_REF': 'refs/heads/master'}, {'GITHUB_REF': 'refs/heads/feature'}, {'GITHUB_EVENT_NAME': 'push'},
                       {'GITHUB_EVENT_NAME': 'schedule'}):
            with self.subTest(change=change):
                error, writes, _ = self.run_main(GitHub(), **change)
                self.assertIn('only a manual run of dev', error)
                self.assertEqual(writes, [])

    def test_missing_token_is_a_refusal_not_a_silent_skip(self):
        error, writes, _ = self.run_main(GitHub(), PROMOTE_TOKEN=None)
        self.assertIn('PROMOTE_TOKEN', error)
        self.assertEqual(writes, [])

    def test_race_on_master_is_a_refusal_and_no_run_is_started(self):
        error, writes, _ = self.run_main(GitHub(patch_error=422))
        self.assertIn('master moved during promotion', error)
        self.assertEqual(writes, [])

    def test_rejected_token_is_reported_and_not_retried(self):
        github = GitHub(patch_error=403)
        with self.assertRaises(urllib.error.HTTPError):
            self.run_main(github)
        self.assertEqual(github.writes, [])

    def test_network_hiccups_are_retried(self):
        github = GitHub(failures={'/git/ref/heads/dev': 1, '/compare/': 2, '/git/refs/heads/master': 1, '/actions/': 1})
        self.assertEqual(self.run_main(github)[:2], (None, ['move', 'dispatch']))

    def test_token_never_reaches_the_output(self):
        _, _, out = self.run_main(GitHub())
        self.assertNotIn('token', out)

    def test_server_errors_are_retried_and_client_errors_are_not(self):
        calls = []

        def urlopen(request, timeout):
            calls.append(request.get_method())
            raise http_error(503 if len(calls) < 2 else 404)

        with patch.object(promote.urllib.request, 'urlopen', urlopen), patch.dict(os.environ, ENV, clear=True):
            with self.assertRaises(RuntimeError):
                promote.api('/git/ref/heads/dev', 'token')
            with self.assertRaises(urllib.error.HTTPError):
                promote.api('/git/ref/heads/dev', 'token')


class WorkflowTest(unittest.TestCase):
    """Задание переноса не должно расширять права остального прогона."""

    def setUp(self):
        self.workflow = (ROOT / '.github/workflows/images.yml').read_text()
        self.job = re.search(r'\n  release:\n(.*?)(?=\n  [a-z_-]+:\n|\n# |\Z)', self.workflow, re.S).group(1)

    def test_promotion_is_opt_in(self):
        flag = re.search(r'\n      promote_master:\n(.*?)(?=\n      [a-z_]+:\n|\n  #)', self.workflow, re.S).group(1)
        self.assertIn('default: false', flag)

    def test_job_runs_only_after_publication_of_a_manual_dev_run_where_the_build_ran(self):
        self.assertIn('needs: publish\n', self.job)
        condition = re.search(r'\n    if: (.*)\n', self.job).group(1)
        for part in ("github.repository == 'axiomshiftbit/vpnbot'", "github.event_name == 'workflow_dispatch'", "github.actor == 'axiomshiftbit'",
                     "github.ref == 'refs/heads/dev'", 'inputs.promote_master'):
            self.assertIn(part, condition)
        self.assertNotIn('||', condition)
        self.assertNotIn('always()', condition)
        runner = re.search(r'\n    runs-on: (.*)\n', self.job).group(1)
        self.assertIn('inputs.home_runner', runner)
        self.assertIn('vpnbot-home', runner)
        self.assertIn("'ubuntu-24.04'", runner)
        self.assertIn('PROMOTE_HOME_RUNNER: ${{ inputs.home_runner }}', self.job)

    def test_dedicated_token_is_visible_to_this_job_only_and_builtin_token_stays_read_only(self):
        self.assertEqual(self.workflow.count('secrets.PROMOTE_TOKEN'), 1)
        self.assertIn('secrets.PROMOTE_TOKEN', self.job)
        self.assertNotIn('contents: write', self.workflow)
        self.assertNotIn('actions: write', self.workflow)
        self.assertIn('persist-credentials: false', self.job)
        self.assertNotIn('GITHUB_TOKEN', self.job)

    def test_script_never_forces_the_branch(self):
        source = (ROOT / 'scripts/ci_promote_master.py').read_text()
        self.assertIn("'force': False", source)
        self.assertNotIn("'force': True", source)


if __name__ == '__main__':
    unittest.main()
