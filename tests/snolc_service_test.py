import json
import os
from pathlib import Path
import sys
import tempfile
import subprocess
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from snolc_service import SnolcSupervisor
from snolc_config import install, install_patches, toml, main_config, PRIVATE_NETS
from build_patches import build
import protocol_modules
import tomllib


class SnolcTests(unittest.TestCase):
    def test_manual_port_confirmation_preserves_other_services_and_checks_docker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            desired = root / 'config/protocols/snolc/desired.json'
            desired.parent.mkdir(parents=True)
            desired.write_text('{"settings":{"port":24449}}')
            (root / 'config/protocol-services.json').write_text('{"snolc":true}')
            path = root / 'config/protocol-services.status.json'
            old = {'settings': {'tuic': True}, 'bindings': {'tuic': 9443}, 'errors': {'tuic': 'unrelated'}}
            path.write_text(json.dumps(old))
            identity = Mock(returncode=0, stdout=b'abc123\n')
            actual = {'running': True, 'ports': {'24448/tcp': [{'HostPort': '24448'}]}}
            with patch.object(protocol_modules, 'compose', return_value=identity) as compose, \
                    patch.object(protocol_modules.subprocess, 'run') as inspect:
                inspect.return_value = Mock(stdout=json.dumps(actual).encode())
                with self.assertRaises(RuntimeError): protocol_modules.confirm_snolc_port(root)
                self.assertEqual(old, json.loads(path.read_text()))
                actual['ports']['24448/tcp'][0]['HostPort'] = '24449'
                inspect.return_value.stdout = json.dumps(actual).encode()
                protocol_modules.confirm_snolc_port(root)
                status = json.loads(path.read_text())
                self.assertEqual({'tuic': 9443, 'snolc': 24449}, status['bindings'])
                self.assertEqual(old['errors'], status['errors'])
                self.assertFalse(status['ok'])
                self.assertTrue(all(call.args[1] == ['ps', '--status', 'running', '-q', 'snolc'] for call in compose.call_args_list))
                self.assertTrue(all(call.args[0][:2] == ['docker', 'inspect'] for call in inspect.call_args_list))

    def test_client_patch_bundle_updates_loader_digest_and_rejects_corruption(self):
        import hashlib
        import zipfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core, adapter, bundle = root / 'core', root / 'adapter', root / 'bundle.zip'
            core.write_bytes(b'patched core'); adapter.write_bytes(b'patched adapter')
            build(core, adapter, adapter, bundle)
            lock = root / 'runtime/packages/locks/owenewans/adapter-socks5/0.0.4.toml'
            lock.parent.mkdir(parents=True)
            lock.write_text('content_sha256 = "old"\npackage = "adapter"\n')
            policy_lock = lock.parent.parent / 'policy-local/0.0.4.toml'
            policy_lock.parent.mkdir()
            policy_lock.write_text('content_sha256 = "old"\npackage = "policy"\n')
            install_patches(root / 'runtime', bundle)
            self.assertEqual(b'patched core', (root / 'runtime/bin/snolc').read_bytes())
            self.assertEqual(hashlib.sha256(adapter.read_bytes()).hexdigest(), tomllib.loads(lock.read_text())['content_sha256'])
            self.assertEqual(0o500, (root / 'runtime/bin/snolc').stat().st_mode & 0o777)
            with zipfile.ZipFile(bundle) as archive:
                manifest = archive.read('manifest.json')
            with zipfile.ZipFile(bundle, 'w') as archive:
                archive.writestr('manifest.json', manifest)
                archive.writestr('snolc', b'tampered')
                archive.writestr('libsnolc_adapter_socks5.so', adapter.read_bytes())
                archive.writestr('libsnolc_policy_local.so', adapter.read_bytes())
            with self.assertRaises(ValueError): install_patches(root / 'runtime', bundle)
            self.assertEqual(b'patched core', (root / 'runtime/bin/snolc').read_bytes())

    def test_backup_restore_selects_new_ledger_once_and_retains_previous(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            supervisor = SnolcSupervisor(root)
            supervisor.database().write_bytes(b'old quota and revoked credentials')
            supervisor.admin = {'seq': 7, 'users': {'old': {}}}
            state = {'restore_usage': {'id': 'a' * 32, 'users': {}}}
            supervisor.prepare_restore(state)
            self.assertEqual('policy-' + 'a' * 32 + '.redb', supervisor.database().name)
            self.assertFalse(supervisor.database().exists())
            self.assertEqual(7, json.loads((root / 'admin.previous.json').read_text())['seq'])
            self.assertEqual(b'old quota and revoked credentials', (root / 'policy.redb').read_bytes())
            resumed = SnolcSupervisor(root)
            resumed.admin['pending'] = {'durable': 'operation'}
            resumed.prepare_restore(state)
            self.assertIn('pending', resumed.admin, 'A retry must not discard the new ledger journal')

    def test_complete_client_installs_offline_with_licenses_and_verified_modules(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core, adapter, bundle = root / 'core', root / 'adapter', root / 'bundle.zip'
            core.write_bytes(b'patched core'); adapter.write_bytes(b'patched module')
            build(core, adapter, adapter, bundle)
            with patch('socket.create_connection', side_effect=AssertionError('network is forbidden')):
                install_patches(root / 'runtime', bundle, install_base=True)
            self.assertEqual(b'patched core', (root / 'runtime/bin/snolc').read_bytes())
            for name in ('adapter-socks5', 'carrier-ssh', 'protection-noise', 'policy-local'):
                library = root / 'runtime/packages/store' / name / ('libsnolc_' + name.replace('-', '_') + '.so')
                lock = root / 'runtime/packages/locks/owenewans' / name / '0.0.4.toml'
                self.assertEqual(hashlib.sha256(library.read_bytes()).hexdigest(), tomllib.loads(lock.read_text())['content_sha256'])
                for notice in ('LICENSE', 'THIRD_PARTY_NOTICES.txt'):
                    self.assertTrue((root / 'runtime/licenses' / name / notice).stat().st_size)

    def test_rehashed_corrupt_release_cannot_replace_existing_client(self):
        import hashlib
        import zipfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core, adapter, bundle = root / 'core', root / 'adapter', root / 'bundle.zip'
            core.write_bytes(b'patched core'); adapter.write_bytes(b'patched module')
            build(core, adapter, adapter, bundle)
            with zipfile.ZipFile(bundle) as archive:
                files = {name: archive.read(name) for name in archive.namelist()}
            name = 'archives/policy-local-0.0.4-x86_64-unknown-linux-gnu.tar.gz'
            files[name] = b'wrong upstream release'
            manifest = json.loads(files['manifest.json'])
            manifest['sha256'][name] = hashlib.sha256(files[name]).hexdigest()
            files['manifest.json'] = json.dumps(manifest).encode()
            with zipfile.ZipFile(bundle, 'w') as archive:
                for name, data in files.items(): archive.writestr(name, data)
            binary = root / 'runtime/bin/snolc'; binary.parent.mkdir(parents=True)
            binary.write_bytes(b'existing working client')
            with self.assertRaisesRegex(RuntimeError, 'SHA256'):
                install_patches(root / 'runtime', bundle, install_base=True)
            self.assertEqual(b'existing working client', binary.read_bytes())
            self.assertFalse((root / 'runtime/packages').exists())

    def test_client_restarts_stuck_carrier_and_cleans_up_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'core'
            binary.write_text('#!/usr/bin/env python3\nimport os,sys,time\n'
                              'from pathlib import Path\n'
                              'with Path(sys.argv[2]).with_suffix(".pids").open("a") as f:f.write(str(os.getpid())+"\\n")\n'
                              'print(\'Tunnel { state: "established" }\',flush=True)\n'
                              'print(\'ModuleError { message: "connection lost" }\',flush=True)\n'
                              'time.sleep(30)\n')
            binary.chmod(0o700)
            config = root / 'config.toml'; config.write_text('pinned identity')
            source = Path(__file__).resolve().parents[1] / 'app/snolc'
            runner = ('import sys,signal;sys.path.insert(0,sys.argv[1]);from client import run_client;'
                      'signal.signal(signal.SIGTERM,lambda *_:sys.exit(0));run_client(sys.argv[2],sys.argv[3],0.2)')
            process = subprocess.Popen([sys.executable, '-c', runner, str(source), str(binary), str(config)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pids = []
            try:
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    if config.with_suffix('.pids').exists():
                        pids = config.with_suffix('.pids').read_text().splitlines()
                    if len(pids) >= 2: break
                    time.sleep(0.05)
                self.assertGreaterEqual(len(pids), 2)
                self.assertEqual('pinned identity', config.read_text())
            finally:
                process.terminate(); process.wait(timeout=7)
            for pid in pids:
                with self.assertRaises(ProcessLookupError): os.kill(int(pid), 0)

    def test_client_in_long_directory_does_not_require_unix_control_socket(self):
        root = Path('/home') / ('long-folder-' * 20)
        config = main_config(root, root / 'packages', root / 'state', False)
        self.assertEqual({'mode': 'off'}, config['control'])
        self.assertEqual('unix', main_config(root, root / 'packages', root / 'state', True)['control']['mode'])

    def test_toml_roundtrip_does_not_inject_paths_or_keys(self):
        value = {'method': 'credential.add', 'value': '"\n[options]\r\\',
                 'user': {'quota': {'mode': 'limited', 'bytes': 65536}}, 'bool': False, 'list': [1, 2]}
        self.assertEqual(value, tomllib.loads(toml(value)))

    def test_lost_control_response_replays_identical_sequence_and_commits_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            supervisor = SnolcSupervisor(root)
            supervisor.control = Mock(side_effect=RuntimeError('stats_unavailable'))
            effect = {'put': 'a' * 16, 'record': {'reset': 'b' * 16}, 'created': True}
            with self.assertRaises(RuntimeError):
                supervisor.mutate({'method': 'user.create', 'user': {'status': 'disabled'}}, effect)
            original = supervisor.control.call_args.args[0]
            restored = SnolcSupervisor(root)
            restored.control = Mock(return_value={'status': 'ok', 'user_id': 'c' * 32, 'revision': 1})
            restored.finish_pending()
            self.assertEqual(original, restored.control.call_args.args[0])
            self.assertEqual('c' * 32, restored.admin['users']['a' * 16]['native'])
            self.assertEqual(1, restored.admin['seq'])
            self.assertNotIn('pending', json.loads((root / 'admin.json').read_text()))

    def test_missing_or_corrupt_durable_state_never_grants_fresh_quota(self):
        for mode in ('database', 'admin', 'json', 'usage'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                if mode == 'database': (root / 'admin.json').write_text('{"seq":1,"users":{}}')
                if mode == 'admin': (root / 'policy.redb').touch()
                if mode == 'json': (root / 'admin.json').write_text('{')
                if mode == 'usage': (root / 'usage.json').write_text('{"users":{"x":{"upload":-1,"download":0}}}')
                with self.assertRaises(ValueError): SnolcSupervisor(root)

    def test_stats_failure_still_terminates_public_core(self):
        with tempfile.TemporaryDirectory() as directory:
            supervisor = SnolcSupervisor(Path(directory))
            process = Mock(); process.poll.return_value = None
            supervisor.process = process
            supervisor.fingerprint = 'previously-applied-state'
            supervisor.collect = Mock(side_effect=RuntimeError('stats_unavailable'))
            supervisor.stop()
            process.terminate.assert_called_once()
            process.wait.assert_called_once()
            self.assertFalse(supervisor.alive())
            self.assertIsNone(supervisor.fingerprint, 'Restoring the same desired state must retry reconciliation')

    def test_restored_traffic_reduces_native_quota_without_changing_expiration(self):
        user = {'enabled': True, 'quota': 1000, 'expires': 2000000000}
        record = {'base_upload': 100, 'base_download': 300}
        spec = SnolcSupervisor.user_spec(user, record)
        self.assertEqual({'mode': 'limited', 'bytes': 600}, spec['quota'])
        self.assertEqual(2000000000, spec['expiration']['unix_seconds'])
        record['base_download'] = 1000
        self.assertEqual('disabled', SnolcSupervisor.user_spec(user, record)['status'])

    def test_safety_rules_cover_ipv4_ipv6_and_transition_ranges(self):
        import ipaddress
        networks = list(map(ipaddress.ip_network, PRIVATE_NETS))
        for ip in ('127.0.0.1', '10.10.0.8', '169.254.169.254', '100.64.0.1', '::1',
                   '::ffff:127.0.0.1', '64:ff9b::7f00:1', 'fe80::1', 'fc00::1', '2002:7f00:1::'):
            self.assertTrue(any(ipaddress.ip_address(ip) in network for network in networks), ip)
        self.assertFalse(any(ipaddress.ip_address('11.77.0.2') in network for network in networks))

    def test_installer_rejects_modified_archive_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'snolc-0.0.4-x86_64-unknown-linux-gnu.tar.gz').write_bytes(b'wrong release')
            with self.assertRaises(RuntimeError): install(root / 'out', archives=root)
            self.assertFalse((root / 'out/bin/snolc').exists())

    def test_optional_service_uses_only_tcp_and_keeps_state_when_disabled(self):
        self.assertFalse(protocol_modules.DEFAULTS['snolc'])
        self.assertIn('snolc', protocol_modules.SERVICES)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / 'config/protocols/snolc/desired.json'
            path.parent.mkdir(parents=True); path.write_text('{"settings":{"port":24448}}')
            self.assertEqual({'snolc': 24448}, protocol_modules.bindings(root))
        import yaml
        services = yaml.safe_load((Path(__file__).resolve().parents[1] / 'docker-compose.yml').read_text())['services']
        service = services['snolc']
        self.assertEqual(['snolc'], service['profiles'])
        self.assertEqual(['${SNOLC_PORT:-24448}:24448/tcp'], service['ports'])
        self.assertEqual('10.10.0.26', service['networks']['default']['ipv4_address'])
        self.assertEqual(['ALL'], service['cap_drop'])
        self.assertTrue(service['read_only'])


if __name__ == '__main__':
    unittest.main()
