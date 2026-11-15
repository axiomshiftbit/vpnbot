"""Exception flags cannot turn missing evidence or a core failure into success."""
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import ci_release_policy as release
import ci_unit_tests as unit
import ci_scan_gate as scan
import ci_hosted_test as hosted
import ci_promote_bundle as promote
import ci_publish_bundle as publish
import image_bundle as bundles

SOURCE = 'a'*40
STRICT = dict.fromkeys(release.FLAGS, False)
ENV = dict(GITHUB_SHA=SOURCE, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='2')


def bundle():
    return dict(schema=1, source=SOURCE, run=123, attempt=2, state_epoch=1,
                images={name: bundles.REGISTRY+name+'@sha256:'+'b'*64 for name in bundles.IMAGES})


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, ENV, clear=True)
        self.env.start(); self.addCleanup(self.env.stop)
        self.quiet = patch('sys.stdout', io.StringIO())
        self.quiet.start(); self.addCleanup(self.quiet.stop)

    def reports(self, root, *, attempt=1):
        for stage in release.stages():
            value = release.write_report(stage, [], 1, root/(stage+'.json'))
            value['attempt'] = attempt
            (root/(stage+'.json')).write_text(json.dumps(value))

    def test_flags_require_exact_opt_in(self):
        self.assertEqual(release.policy(), STRICT)
        for variable in release.FLAGS.values():
            with patch.dict(os.environ, {variable: '1'}):
                self.assertEqual(sum(release.policy().values()), 1)
            for value in ('true', 'yes', '', '2'):
                with patch.dict(os.environ, {variable: value}), self.assertRaises(ValueError):
                    release.policy()

    def test_only_reviewed_existing_presentation_tests_are_optional(self):
        for name in release.FUNCTIONAL_TESTS:
            self.assertTrue((ROOT/'tests'/name).is_file())
            self.assertFalse(release.critical_test(name))
        for name in ('menu_help_test.php', 'new_menu_test.php', 'nft_test.php', 'managed_node_vpn_sources_menu_test.php',
                     'masque-native', 'node_setup_test.py', 'backup_roundtrip_test.php', 'access_policy_test.php'):
            self.assertTrue(release.critical_test(name))
            with self.assertRaises(ValueError): release.warning('test', name)

    def test_warning_types_names_and_counts_are_bounded(self):
        for row in (dict(kind='test', name='../version_parse_test.php', count=1),
                    dict(kind='test', name='version_parse_test.php', count=True),
                    dict(kind='vulnerability', name='private\nvalue', count=1),
                    dict(kind='test', name='version_parse_test.php', count=0),
                    dict(kind='test', name='version_parse_test.php', count=100001),
                    dict(kind='unknown', name='x', count=1)):
            with self.assertRaises(ValueError): release.validate_warning(row)
        with self.assertRaises(ValueError): release.announce([], 'untrusted\n::warning::x')

    def test_full_report_inventory_and_previous_attempt_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.reports(root)
            proof = release.collect(root, bundle(), {}, release.stages())
            self.assertEqual(proof['warnings'], [])
            self.assertEqual(len(release.stages()), len(bundles.IMAGES)+5)
            (root/'components.json').unlink()
            with self.assertRaises(ValueError): release.collect(root, bundle(), {}, release.stages())

    def test_foreign_malformed_or_future_report_is_never_admitted(self):
        changes = [dict(source='c'*40), dict(run=124), dict(run=True), dict(attempt=3), dict(attempt=True),
                   dict(schema=True), dict(stage='security-xr'), dict(checks=0), dict(checks=True),
                   dict(policy=STRICT|{'allow_test_failures': True}), dict(policy={k: 0 for k in STRICT})]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.reports(root)
            path = root/'components.json'; original = json.loads(path.read_text())
            for change in changes:
                with self.subTest(change=change):
                    path.write_text(json.dumps(original|change))
                    with self.assertRaises(ValueError): release.collect(root, bundle(), {}, release.stages())

    def test_rerun_failed_accepts_new_scan_with_old_successful_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.reports(root, attempt=1)
            release.write_report('security-php', [], 1, root/'security-php.json')
            old = bundle() | {'attempt': 1}
            release.collect(root, old, {}, release.stages())
            with patch.dict(os.environ, {'GITHUB_RUN_ATTEMPT': '1'}), self.assertRaises(ValueError):
                release.collect(root, old, {}, release.stages())

    def test_warnings_survive_collection_and_cannot_promote_under_strict_policy(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'CI_ALLOW_TEST_FAILURES': '1'}):
            root = Path(directory); self.reports(root)
            row = release.warning('test', 'version_parse_test.php')
            release.write_report('unit-host', [row], 236, root/'unit-host.json')
            proof = release.collect(root, bundle(), {'warnings': [row]}, release.stages())
            self.assertEqual({r['stage'] for r in proof['warnings']}, {'unit-host', 'native'})
            release.validate_proof(proof, bundle(), release.policy())
            with self.assertRaises(ValueError): release.validate_proof(proof, bundle(), STRICT)
            changed = copy.deepcopy(proof); changed['bundle'] = 'f'*64
            with self.assertRaises(ValueError): release.validate_proof(changed, bundle(), release.policy())

    def test_expired_or_removed_waiver_is_not_reused_for_promotion(self):
        row = release.warning('waiver', 'GHSA-r766-rf9f-588h')
        with patch('ci_waivers.load', return_value=[dict(id=row['name'], active=False)]), self.assertRaises(ValueError):
            release.validate_warnings([row], STRICT|{'allow_waivers': True})

    def test_native_warnings_require_flag_and_complete_all_groups(self):
        row = release.warning('test', 'version_parse_test.php')
        counts = dict.fromkeys(hosted.GROUPS, 1)
        with self.assertRaises(ValueError): hosted.evidence(bundle(), counts, 'c'*64, [row])
        native = hosted.evidence(bundle(), counts, 'c'*64, [row], True)
        self.assertEqual(native['status'], 'success_with_warnings')
        statuses = dict.fromkeys(('build', 'tests', 'security', 'native'), 'success')
        with self.assertRaises(ValueError): bundles.admit(bundle(), native, statuses)
        bundles.admit(bundle(), native, statuses, allow_test_failures=True)
        with self.assertRaises(ValueError): bundles.admit(bundle(), native, statuses|{'build': 'failure'}, allow_test_failures=True)
        with self.assertRaises(ValueError): hosted.evidence(bundle(), counts|{'native': 0}, 'c'*64, [row], True)

    def test_vulnerability_exception_never_waives_secrets_or_missing_os_scan(self):
        data = {'Metadata': {'OS': {'Family': 'alpine'}}, 'Results': [{'Class': 'os-pkgs', 'Vulnerabilities': [
            dict(VulnerabilityID='CVE-2026-12345', Severity='HIGH', FixedVersion='2', PkgName='pkg', InstalledVersion='1')]}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'scan.json'; path.write_text(json.dumps(data))
            self.assertEqual(scan.main(path), 1)
            with patch.dict(os.environ, {'CI_ALLOW_VULNERABILITIES': '1'}):
                self.assertEqual(scan.main(path), 0)
                data['Results'][0]['Secrets'] = [dict(RuleID='private-key')]
                path.write_text(json.dumps(data)); self.assertEqual(scan.main(path), 1)
                data['Results'][0]['Class'] = 'lang-pkgs'
                path.write_text(json.dumps(data))
                with self.assertRaises(AssertionError): scan.main(path)

    def test_unit_runner_continues_only_optional_failures_and_hides_raw_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'tests').mkdir()
            for i in range(100): (root/'tests'/('required_'+str(i)+'_test.php')).touch()
            for name in ('version_parse_test.php', 'backup_roundtrip_test.php'): (root/'tests'/name).touch()
            def execute(args, **kwargs):
                failed = Path(args[-1]).name == 'version_parse_test.php'
                return subprocess.CompletedProcess(args, int(failed), b'PRIVATE test output' if failed else b'', b'')
            with patch.object(unit.subprocess, 'run', side_effect=execute), patch('sys.stdout', io.StringIO()) as output:
                result = unit.run(root, root/'logs', True)
                self.assertEqual(result['blocked'], [])
                self.assertEqual(result['warnings'], [release.warning('test', 'version_parse_test.php')])
                self.assertNotIn('PRIVATE', output.getvalue())
                self.assertEqual((root/'logs/version_parse_test.log').stat().st_mode & 0o777, 0o600)
                self.assertEqual(unit.run(root, root/'logs', False)['blocked'], ['version_parse_test.php'])
            with patch.object(unit.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'', b'')):
                self.assertIn('backup_roundtrip_test.php', unit.run(root, root/'logs', True)['blocked'])
            def timeout(args, **kwargs):
                if Path(args[-1]).name == 'version_parse_test.php': raise subprocess.TimeoutExpired(args, 150)
                return subprocess.CompletedProcess(args, 0, b'', b'')
            with patch.object(unit.subprocess, 'run', side_effect=timeout):
                self.assertEqual(unit.run(root, root/'logs', True)['blocked'], ['version_parse_test.php'])

    def test_promotion_policy_failure_never_moves_channel(self):
        proof = dict(schema=1, source=SOURCE, bundle=bundles.fingerprint(bundle()),
                     policy=STRICT|{'allow_vulnerabilities': True},
                     warnings=[dict(stage='security-php', **release.warning('vulnerability', 'CVE-2026-12345'))])
        calls = []
        def command(*args):
            calls.append(args)
            return 'sha256:'+'c'*64
        def fetch(ref, destination, *, admission):
            admission.write_text(json.dumps(proof)); return bundle()
        with patch.dict(os.environ, dict(GITHUB_REF_NAME='master', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_SHA=SOURCE)), \
                patch.object(promote, 'command', side_effect=command), patch.object(promote, 'fetch_reference', side_effect=fetch):
            with self.assertRaises(ValueError): promote.promote()
        self.assertFalse(any('create' in c for c in calls))

    def test_publication_embeds_validated_reports_and_rejects_missing_ones(self):
        statuses = dict.fromkeys(('build', 'tests', 'security', 'native'), 'success')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); reports = root/'reports'; reports.mkdir()
            self.reports(reports)
            manifest, evidence = root/'bundle.json', root/'native.json'
            manifest.write_bytes(bundles.canonical(bundle()))
            evidence.write_text(json.dumps(hosted.evidence(bundle(), dict.fromkeys(hosted.GROUPS, 1), 'c'*64)))
            packed = []
            def command(*args):
                if args[:3] == ('docker', 'buildx', 'build'):
                    envelope = Path(args[-1])
                    proof = json.loads((envelope/'admission.json').read_text())
                    release.validate_proof(proof, bundle(), STRICT)
                    self.assertEqual(bundles.read(envelope/'bundle.json'), bundle())
                    self.assertIn('COPY bundle.json admission.json /', (envelope/'Dockerfile').read_text())
                    packed.append(proof)
                return SOURCE if args[:2] == ('gh', 'api') else ''
            env = dict(CI_REPORT_DIRECTORY=str(reports), EXPECTED_BUNDLE=bundles.fingerprint(bundle()),
                       CHECKS=json.dumps(statuses), GITHUB_REF_NAME='dev', GITHUB_EVENT_NAME='workflow_dispatch',
                       GITHUB_REPOSITORY='axiomshiftbit/vpnbot')
            with patch.dict(os.environ, env), patch.object(publish, 'command', side_effect=command), \
                    patch.object(sys, 'argv', ['ci_publish_bundle.py', str(manifest), str(evidence)]):
                publish.main(); self.assertEqual(len(packed), 1)
                (reports/'unit-host.json').unlink()
                with self.assertRaises(ValueError): publish.main()
                self.assertEqual(len(packed), 1)


if __name__ == '__main__':
    unittest.main()
