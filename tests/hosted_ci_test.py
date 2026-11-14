import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('hosted_ci', ROOT / 'scripts/ci_hosted_test.py')
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)
from image_bundle import IMAGES, REGISTRY
sys.path.pop(0)
spec = importlib.util.spec_from_file_location('hosted_bootstrap', ROOT / 'tests/integration/bootstrap.py')
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class HostedCITests(unittest.TestCase):
    def test_client_downloader_exhaustion_is_not_retried_again(self):
        error = subprocess.CalledProcessError(22, ['sh', 'download-file.sh'])
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(ci.subprocess, 'run', side_effect=error) as run, \
                patch.object(ci.tarfile, 'open') as unpack:
            with self.assertRaises(subprocess.CalledProcessError):
                ci.client_downloads(Path(directory) / 'clients')
        self.assertEqual(run.call_count, 1)
        unpack.assert_not_called()

    def test_client_downloader_timeout_is_fatal_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(ci.subprocess, 'run', side_effect=subprocess.TimeoutExpired('download', 900)) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                ci.download_client('https://example.test/archive', Path(directory) / 'archive')
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.kwargs['timeout'], 900)

    def test_client_checksum_mismatch_is_not_retried_or_extracted(self):
        def wrong_download(url, archive):
            archive.write_bytes(b'wrong contents')

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(ci, 'download_client', side_effect=wrong_download) as download, \
                patch.object(ci.tarfile, 'open') as unpack, patch.object(ci.ci_retry.time, 'sleep') as sleep:
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                ci.client_downloads(Path(directory) / 'clients')
        self.assertEqual(download.call_count, 1)
        unpack.assert_not_called()
        sleep.assert_not_called()

    def test_fresh_users_wait_for_service_initialization_after_frontend_health(self):
        healthy = subprocess.CompletedProcess([], 0, json.dumps([
            {'State': {'Health': {'Status': 'healthy'}}},
            {'State': {'Health': {'Status': 'healthy'}}},
        ]))
        with patch.object(bootstrap.subprocess, 'run', side_effect=[
            healthy, subprocess.CompletedProcess([], 1),
            healthy, subprocess.CompletedProcess([], 0),
        ]) as command, patch.object(bootstrap.time, 'sleep') as sleep:
            bootstrap.wait_frontend()
        sleep.assert_called_once_with(1)
        self.assertEqual(command.call_count, 4)
        self.assertEqual(command.call_args.args[0],
                         ['docker', 'exec', 'service-audit', 'pgrep', '-f', '^php cron[.]php$'])

    def test_failed_service_initialization_cannot_admit_fresh_users(self):
        healthy = subprocess.CompletedProcess([], 0, json.dumps([
            {'State': {'Health': {'Status': 'healthy'}}},
            {'State': {'Health': {'Status': 'healthy'}}},
        ]))
        with patch.object(bootstrap.subprocess, 'run', side_effect=[
            healthy, subprocess.CompletedProcess([], 1),
        ]), patch.object(bootstrap.time, 'monotonic', side_effect=[0, 1, 181]), \
                patch.object(bootstrap.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'initialization timeout'):
                bootstrap.wait_frontend()

    def test_compose_accepts_only_disposable_data_and_loopback_ports(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(bootstrap, 'ROOT', Path(directory)):
            bootstrap.validate_compose_inputs({'services': {'php': {
                'environment': {'TELEGRAM_API': 'tg-audit:8443'},
                'volumes': [{'type': 'bind', 'source': directory + '/stand/bot/config'},
                            {'type': 'bind', 'source': '/etc/localtime'},
                            {'type': 'volume', 'source': 'adguard'}],
                'ports': [{'host_ip': '127.0.0.1'}, {'host_ip': '::1'}],
            }}, 'volumes': {'adguard': {'name': 'vpnbot-audit_adguard'}}})

    def test_compose_rejects_host_paths_including_prefix_and_symlink_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'stand'; root.mkdir()
            (root / 'linked').symlink_to(Path(directory), target_is_directory=True)
            for source in ('/home', str(root) + '-other/config', str(root / '../private'),
                           str(root / 'linked/private')):
                with self.subTest(source=source), patch.object(bootstrap, 'ROOT', root):
                    with self.assertRaisesRegex(ValueError, 'host bind'):
                        bootstrap.validate_compose_inputs({'services': {'php': {
                            'volumes': [{'type': 'bind', 'source': source}],
                        }}})

    def test_compose_rejects_credential_environment_and_external_config(self):
        for key in ('GH_TOKEN', 'GITHUB_TOKEN_AM3ROOT', 'ACTIONS_RUNTIME_TOKEN',
                    'GHCR_TOKEN', 'SSH_AUTH_SOCK', 'DOCKER_AUTH_CONFIG'):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'credential'):
                bootstrap.validate_compose_inputs({'services': {'php': {'environment': {key: 'dummy'}}}})
        for key in ('env_file', 'configs', 'secrets'):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'configuration input'):
                bootstrap.validate_compose_inputs({'services': {'php': {key: ['host-input']}}})

    def test_compose_rejects_host_network_and_public_listeners(self):
        for mode in ('host', 'container:unrelated'):
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, 'network namespace'):
                bootstrap.validate_compose_inputs({'services': {'php': {'network_mode': mode}}})
        for port in ({}, {'host_ip': '0.0.0.0'}, {'host_ip': '::'}, {'host_ip': '203.0.113.10'}):
            with self.subTest(port=port), self.assertRaisesRegex(ValueError, 'loopback'):
                bootstrap.validate_compose_inputs({'services': {'php': {'ports': [port]}}})

    def test_compose_rejects_external_or_host_backed_volumes(self):
        for value in ({'external': True}, {'driver_opts': {'device': '/home', 'o': 'bind'}},
                      {'driver': 'other'}, {'name': 'production-data'}):
            volume = {'name': 'vpnbot-audit_warp'} | value
            with self.subTest(volume=volume), self.assertRaisesRegex(ValueError, 'volume outside'):
                bootstrap.validate_compose_inputs({'volumes': {'warp': volume}})


    def test_failure_log_contains_only_reviewed_protocol_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'tests/integration/fixtures/tests/published-main'
            source.mkdir(parents=True)
            for name in ('openconnect', 'proxies', 'wireguard'):
                (source / (name + '.py')).touch()
            results = root / 'tests/published-main/results.json'
            results.parent.mkdir()
            with patch.object(ci, 'ROOT', root):
                self.assertEqual(ci.failed_protocols(root), [])
                results.write_text(json.dumps([
                    {'case': 'openconnect', 'exit': 1, 'private': 'must not be printed'},
                    {'case': 'proxies', 'exit': 'timeout'},
                    {'case': 'wireguard', 'exit': 0},
                    {'case': 'private profile value', 'exit': 1},
                    {'case': ['invalid'], 'exit': 1}, None,
                ]))
                self.assertEqual(ci.failed_protocols(root), ['openconnect', 'proxies'])
                for invalid in ('not JSON', '{}'):
                    results.write_text(invalid)
                    self.assertEqual(ci.failed_protocols(root), [])

    def test_retried_suites_print_only_suite_names(self):
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory)
            self.assertEqual(ci.retried_suites(results), [])
            (results / 'retries.json').write_text(json.dumps([
                'snolc-native', 'native-before-restore/shadowsocks', 'native-after-restore-nginx-transports',
                'vless://secret@host', 'a b', ['x'], None, 'x' * 41,
            ]))
            self.assertEqual(ci.retried_suites(results), [
                'snolc-native', 'native-before-restore/shadowsocks', 'native-after-restore-nginx-transports'])
            for invalid in ('not JSON', '{}'):
                (results / 'retries.json').write_text(invalid)
                self.assertEqual(ci.retried_suites(results), [])

    def test_first_release_flag_uses_the_candidate_as_its_rollback_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'checkout').mkdir()
            (root / 'checkout/.env').write_text('PROTOCOL_GO_VERSION=1\nMIERU_VERSION=v\nMIERU_SOURCE_SHA256=x\nDNSTT_REF=r\nSINGBOX_VERSION=v\nSINGBOX_SHA256=y\n')
            bundle = {'schema': 1, 'source': 'a' * 40, 'run': 1, 'attempt': 1, 'state_epoch': 1,
                      'images': {name: REGISTRY + name + '@sha256:' + 'b' * 64 for name in IMAGES}}
            manifest = root / 'bundle.json'
            manifest.write_text(json.dumps(bundle))
            for flag, calls in (('1', 0), ('0', 1)):
                with patch.dict(os.environ, {'CI_FIRST_RELEASE': flag, 'GITHUB_REF_NAME': 'dev'}), \
                        patch.object(ci, 'network'), patch.object(ci, 'retrying'), patch.object(ci, 'client_downloads'), \
                        patch.object(ci, 'command', return_value='id'), \
                        patch.object(ci, 'rollback_reference', side_effect=RuntimeError('cannot resolve')) as reference:
                    if calls:
                        with self.assertRaises(RuntimeError): ci.assets(root / 'checkout', manifest)
                    else:
                        ci.assets(root / 'checkout', manifest)
                        pair = json.loads((root / 'rollback-images.json').read_text())
                        self.assertEqual(pair, {name: bundle['images'][name] for name in ('php', 'ng')})
                    self.assertEqual(calls, reference.call_count)
        workflow = (ROOT / '.github/workflows/images.yml').read_text()
        self.assertIn("inputs.first_release && '1' || '0'", workflow)
        self.assertIn("github.ref == 'refs/heads/dev'", workflow.split('CI_FIRST_RELEASE:')[1].splitlines()[0])

    def test_first_stable_release_uses_only_an_existing_admitted_channel(self):
        stable = ci.BUNDLE_REPO + ':bundle-latest'
        dev = ci.BUNDLE_REPO + ':bundle-dev'
        with patch.object(ci.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{}', '')):
            self.assertEqual(ci.rollback_reference('master'), stable)
            self.assertEqual(ci.rollback_reference('dev'), dev)
        for error in ('manifest unknown', 'no such manifest: ' + stable):
            with patch.object(ci.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', error)):
                self.assertEqual(ci.rollback_reference('master'), dev)
                with self.assertRaises(RuntimeError): ci.rollback_reference('dev')
        for error in ('unauthorized', 'denied', 'connection timeout', 'unknown registry failure'):
            with patch.object(ci.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', error)) as run, \
                    patch.object(ci.time, 'sleep') as sleep:
                with self.assertRaises(RuntimeError): ci.rollback_reference('master')
            # Сбой сети повторяется, но другой комплект для отката не выбирается.
            self.assertEqual((run.call_count, sleep.call_count), (4, 3))
        with patch.object(ci.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'manifest unknown')) as run, \
                patch.object(ci.time, 'sleep') as sleep:
            self.assertEqual(ci.rollback_reference('master'), dev)
        self.assertEqual((run.call_count, sleep.call_count), (1, 0))
        with patch.object(ci.subprocess, 'run', side_effect=[subprocess.CompletedProcess([], 1, '', 'connection timeout'),
                                                           subprocess.CompletedProcess([], 0, '{}', '')]), patch.object(ci.time, 'sleep'):
            self.assertEqual(ci.rollback_reference('master'), stable)

    def test_partial_false_or_extra_results_cannot_admit_images(self):
        bundle = dict(schema=1, source='a' * 40, run=1, attempt=1, state_epoch=1,
                      images={name: ci.BUNDLE_REPO.removesuffix('php') + name + '@sha256:' + 'b' * 64
                              for name in IMAGES})
        counts = dict.fromkeys(ci.GROUPS, 1)
        result = ci.evidence(bundle, counts, 'c' * 64)
        self.assertEqual({'source', 'bundle', 'suite', 'status', 'checks'}, set(result))
        for group in ci.GROUPS:
            for value in (0, -1, False, True, '1', None):
                with self.subTest(group=group, value=value), self.assertRaises(ValueError):
                    ci.evidence(bundle, counts | {group: value}, 'c' * 64)
            partial = counts.copy(); del partial[group]
            with self.assertRaises(ValueError): ci.evidence(bundle, partial, 'c' * 64)
        # A raw test profile/log must never become part of the public artifact.
        with self.assertRaises(ValueError): ci.evidence(bundle, counts | {'profile': 'private'}, 'c' * 64)

    def test_full_stand_requires_the_hosted_vm_or_explicit_local_proof(self):
        for env in ({}, {'GITHUB_ACTIONS': 'true'}, {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'self-hosted'}):
            with patch.dict(os.environ, env, clear=True), self.assertRaises(ValueError): ci.host(False)
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted'}, clear=True):
            ci.host(False)

    def test_manual_stand_accepts_only_the_designated_home_host(self):
        with patch.object(ci.Path, 'read_text', return_value='home-build\n'):
            ci.host(True)
        for marker in ('prod-1', 'prod-2', '', 'vpnbot-test', 'home-build-other'):
            with self.subTest(marker=marker), patch.object(ci.Path, 'read_text', return_value=marker):
                with self.assertRaises(ValueError):
                    ci.host(True)

    def test_cleanup_refuses_unknown_state_before_any_docker_command(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(ci, 'ROOT', Path(directory)), patch.object(ci, 'command') as docker:
                with self.assertRaises(ValueError): ci.cleanup()
                docker.assert_not_called()

    def test_cleanup_removes_labelled_probe_network_and_preserves_foreign_resources(self):
        calls = []
        def command(*args):
            calls.append(args)
            if args == ('docker', 'ps', '-aq'): return 'owned foreign'
            if args[:2] == ('docker', 'inspect'):
                name = args[2]
                labels = {'vpnbot.hosted-ci': 'true'} if name == 'owned' else {}
                return json.dumps([{'Name': '/' + name, 'Config': {'Labels': labels}}])
            if args == ('docker', 'network', 'ls', '-q', '--filter', 'label=vpnbot.hosted-ci=true'):
                return 'owned-network'
            return ''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'stand'; root.mkdir()
            (root / 'owner').write_text('vpnbot-hosted-ci\n')
            with patch.object(ci, 'ROOT', root), patch.object(ci, 'command', side_effect=command), \
                    patch.object(ci.subprocess, 'run'):
                ci.cleanup()
            self.assertFalse(root.exists())
        self.assertIn(('docker', 'rm', '-f', 'owned'), calls)
        self.assertIn(('docker', 'network', 'rm', 'owned-network'), calls)
        self.assertNotIn(('docker', 'rm', '-f', 'foreign'), calls)

    def test_changes_to_fixture_code_and_bootstrap_invalidate_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); suite = root / 'tests/integration'; suite.mkdir(parents=True)
            bootstrap = suite / 'bootstrap.py'; bootstrap.write_text('original setup')
            helper = root / 'dockerfile/download-file.sh'; helper.parent.mkdir()
            helper.write_text('original downloader')
            one = ci.identity(root)
            bootstrap.write_text('changed setup')
            self.assertNotEqual(one, ci.identity(root))
            one = ci.identity(root)
            (suite / 'protocol.py').write_text('changed protocol probe')
            self.assertNotEqual(one, ci.identity(root))
            one = ci.identity(root)
            helper.write_text('changed downloader')
            self.assertNotEqual(one, ci.identity(root))
            one = ci.identity(root)
            (helper.parent / 'go-retry.sh').write_text('changed module downloader')
            self.assertNotEqual(one, ci.identity(root))


if __name__ == '__main__':
    unittest.main()
