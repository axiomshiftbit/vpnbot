import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value
service = module('protocol_service')
modules = module('protocol_modules')

class ProtocolTests(unittest.TestCase):
    def test_ipsec_filter_preserves_secrets_and_other_connections(self):
        text = 'connections { ikev2 { local { auth = pubkey } } l2tp { version = 1 } custom { key = "{text}" } }\nsecrets { eap-user { secret = "synthetic } secret" } }'
        only_ike = modules.filter_ipsec(text, True, False)
        self.assertIn('ikev2 {', only_ike); self.assertNotIn('l2tp {', only_ike)
        self.assertIn('custom {', only_ike); self.assertIn('secret = "synthetic } secret"', only_ike)
        only_l2tp = modules.filter_ipsec(text, False, True)
        self.assertNotIn('ikev2 {', only_l2tp); self.assertIn('l2tp {', only_l2tp)
        self.assertEqual(text, modules.filter_ipsec(text))
        with self.assertRaises(ValueError): modules.filter_ipsec('connections { ikev2 {', False, True)

    def test_profiles_exclude_disabled_containers(self):
        settings = modules.DEFAULTS | {'oc': False, 'ovpn': False, 'l2tp': False, 'ikev2': False}
        with patch.dict('os.environ', {'VER': 'test'}):
            self.assertEqual('', modules.environment(settings)['COMPOSE_PROFILES'])
            settings['ikev2'] = True
            env = modules.environment(settings)
            self.assertEqual('ipsec', env['COMPOSE_PROFILES'])
            self.assertEqual('1', env['IPSEC_IKEV2_ENABLED']); self.assertEqual('0', env['IPSEC_L2TP_ENABLED'])

    def test_upstream_migration_preserves_customization_and_is_repeatable(self):
        old = 'stream {\n upstream ocserv { server oc:443; }\n upstream openvpn { server ovpn:1194; }\n map $ssl_preread_server_name $sni_name { custom.test other; }\n}'
        new = modules.migrate_upstream(old)
        self.assertIn('server oc:443 resolve;', new); self.assertIn('custom.test other;', new)
        self.assertIn('listen 127.0.0.1:10444 proxy_protocol;', new)
        self.assertEqual(new, modules.migrate_upstream(new))

    def test_usage_deltas_reset_and_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            supervisor = service.Supervisor(directory)
            supervisor.active = ['0123456789abcdef']
            record = {'upload': 10, 'download': 20, 'last': {'upload': 2, 'download': 3}}
            supervisor.usage['users'][supervisor.active[0]] = record
            with patch.object(supervisor, 'alive', return_value=True), patch.object(supervisor, 'counters', return_value={supervisor.active[0]: {'upload': 7, 'download': 13}}):
                supervisor.collect(); supervisor.collect()
            self.assertEqual((15,30), (record['upload'],record['download']))
            persisted = service.Supervisor(directory)
            self.assertEqual(30, persisted.usage['users'][supervisor.active[0]]['download'])
            with patch.object(supervisor, 'alive', return_value=True), patch.object(supervisor, 'counters', return_value={supervisor.active[0]: {'upload': 1, 'download': 2}}): supervisor.collect()
            self.assertEqual((16,32), (record['upload'],record['download']))
            (Path(directory) / 'usage.json').write_text('{broken')
            with self.assertRaises(ValueError): service.Supervisor(directory)

    def test_migration_validates_before_writing_and_keeps_concurrent_edit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'config').mkdir(); (root / 'update').mkdir()
            path = root / 'config/upstream.conf'
            old = 'stream { map $ssl_preread_server_name $sni_name { default other; } }'
            path.write_text(old)
            with patch.object(modules, 'validate_upstream', side_effect=ValueError('invalid')):
                with self.assertRaises(ValueError): modules.prepare_upstream(root)
            self.assertEqual(old, path.read_text())
            def concurrent_edit(_root, _candidate):
                if 'custom' not in path.read_text(): path.write_text(old.replace('default other;', 'default other; custom.test other;'))
            with patch.object(modules, 'validate_upstream', side_effect=concurrent_edit) as validate:
                modules.prepare_upstream(root)
            self.assertEqual(2, validate.call_count)
            self.assertIn('custom.test other;', path.read_text())
            self.assertIn('custom.test other;', (root / 'update/upstream.before-protocols.conf').read_text())

    def test_failed_usage_write_does_not_refresh_quota_clock_or_double_count(self):
        with tempfile.TemporaryDirectory() as directory:
            supervisor = service.Supervisor(directory)
            uid = '0123456789abcdef'
            supervisor.active = [uid]
            supervisor.usage['users'][uid] = {'upload': 0, 'download': 0}
            supervisor.stats_time = 123
            with patch.object(supervisor, 'alive', return_value=True), patch.object(supervisor, 'counters', return_value={uid: {'upload': 10, 'download': 20}}):
                with patch.object(service, 'atomic_json', side_effect=OSError('disk full')):
                    with self.assertRaises(OSError): supervisor.collect()
                self.assertEqual(123, supervisor.stats_time)
                supervisor.collect()
            self.assertGreater(supervisor.stats_time, 123)
            self.assertEqual(20, service.Supervisor(directory).usage['users'][uid]['download'])

    def test_control_state_is_separate_from_writable_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); control = root / 'desired.json'; runtime = root / 'runtime'
            control.write_text(json.dumps({'schema': 1, 'protocol': 'anytls', 'revision': 1, 'enabled': False, 'users': {},
                'config': {'inbounds': [{'type': 'anytls', 'users': []}], 'experimental': {'v2ray_api': {}}}}))
            before = control.read_bytes()
            with patch.dict('os.environ', {'PROTOCOL_DESIRED': str(control)}):
                supervisor = service.Supervisor(runtime); supervisor.tick()
            self.assertEqual(before, control.read_bytes())
            self.assertFalse((runtime / 'desired.json').exists())
            self.assertEqual('disabled', json.loads((runtime / 'status.json').read_text())['phase'])
            self.assertTrue((runtime / 'usage.json').exists())

    def test_empty_stats_response_is_available_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            supervisor = service.Supervisor(directory)
            for payload in ({}, {'stat': None}, {'stat': []}):
                with patch.object(service.subprocess, 'run') as run:
                    run.return_value.stdout = json.dumps(payload)
                    self.assertEqual({}, supervisor.counters())

    def test_only_selected_certificates_are_copied_and_symlinks_cannot_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); certs = root / 'certs'; certs.mkdir()
            (certs / 'public').write_bytes(b'public'); (certs / 'private').write_bytes(b'synthetic-key')
            (certs / 'other-vpn-ca').write_bytes(b'must-not-copy')
            desired = root / 'config/protocols/anytls/desired.json'; desired.parent.mkdir(parents=True)
            desired.write_text(json.dumps({'settings': {'certificate': '/certs/public', 'private_key': '/certs/private'}}))
            modules.sync_certificates(root, modules.DEFAULTS | {'anytls': True})
            destination = root / 'update/protocol-certs/anytls'
            self.assertEqual(['private', 'public'], sorted(p.name for p in destination.iterdir()))
            self.assertEqual(0o600, (destination / 'private').stat().st_mode & 0o777)
            (certs / 'private').unlink(); (root / 'outside').write_text('outside'); (certs / 'private').symlink_to(root / 'outside')
            with self.assertRaises(ValueError): modules.sync_certificates(root, modules.DEFAULTS | {'anytls': True})
            self.assertEqual(b'synthetic-key', (destination / 'private').read_bytes())

    def test_runtime_log_is_bounded_without_changing_its_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            supervisor = service.Supervisor(directory)
            log = Path(directory) / 'core.log'; log.write_bytes(b'A' * (2 * 1024 * 1024))
            inode = log.stat().st_ino
            supervisor.tick()
            self.assertEqual(inode, log.stat().st_ino)
            self.assertEqual(65536, log.stat().st_size)

    def test_busy_port_does_not_block_disabling_another_protocol(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'config').mkdir(); (root / 'update').mkdir()
            old = modules.DEFAULTS | {'tuic': True}
            current = old | {'oc': False}
            (root / 'config/protocol-services.json').write_text(json.dumps(current))
            status = root / 'config/protocol-services.status.json'
            status.write_text(json.dumps({'ok': True, 'settings': old, 'bindings': {'tuic': 9443}}))
            calls = []
            def compose(_settings, arguments, **_kwargs):
                calls.append(arguments)
                return subprocess.CompletedProcess(arguments, 0, b'')
            with patch.object(modules, 'sync_certificates'), patch.object(modules, 'bindings', return_value={'tuic': 24445}), \
                    patch.object(modules, 'check_port', side_effect=RuntimeError('occupied')), patch.object(modules, 'compose', side_effect=compose):
                modules.apply(root)
            actual = json.loads(status.read_text())
            self.assertFalse(actual['ok']); self.assertFalse(actual['settings']['oc'])
            self.assertEqual(9443, actual['bindings']['tuic'])
            self.assertEqual('port_unavailable', actual['errors']['tuic'])
            self.assertIn(['rm', '--force', 'oc'], calls)
            self.assertFalse(any(args[-1] == 'tuic' for args in calls))

    def test_tls_identity_mismatch_is_rejected_before_core_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key = root / 'cert.pem', root / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-subj', '/CN=protocol.test', '-addext', 'subjectAltName=DNS:protocol.test',
                            '-keyout', str(key), '-out', str(cert)], capture_output=True, check=True)
            supervisor = service.Supervisor(root / 'state', binary='/bin/true')
            config = {'inbounds': [{'tls': {'certificate_path': str(cert), 'key_path': str(key)}}]}
            import copy
            generation, fingerprint = supervisor.candidate(copy.deepcopy(config), {'settings': {'sni': 'protocol.test'}})
            self.assertTrue((generation / 'config.json').exists())
            supervisor.fingerprint = fingerprint
            with patch.object(supervisor, 'alive', return_value=True):
                with self.assertRaises(subprocess.CalledProcessError):
                    supervisor.candidate(copy.deepcopy(config), {'settings': {'sni': 'wrong.test'}})
            self.assertTrue((generation / 'config.json').exists())

class SystemdMigrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        self.root = directory / 'installation with spaces'; (self.root / 'update').mkdir(parents=True)
        self.unit = directory / 'vpnbot.service'
        self.old_stop = b'ExecStop=/bin/sh -c "docker compose down --remove-orphans"'
        self.before = (b'[Unit]\n# Example: ' + self.old_stop + b'\n[Service]\nWorkingDirectory='
                       + str(self.root).encode() + b'\nEnvironment=KEEP_CUSTOM=true\n' + self.old_stop
                       + b'\nExecStopPost=/bin/true\n')
        self.unit.write_bytes(self.before); self.unit.chmod(0o640)
        mocked = patch.object(modules, 'SYSTEMD_UNIT', self.unit); mocked.start(); self.addCleanup(mocked.stop)
        self.backup = self.root / 'update/vpnbot.service.before-protocols'

    def test_stock_stop_is_upgraded_without_changing_custom_data(self):
        with patch.object(modules.subprocess, 'run') as reload:
            self.assertTrue(modules.migrate_systemd_stop(self.root))
            self.assertFalse(modules.migrate_systemd_stop(self.root))
        text = self.unit.read_bytes()
        self.assertIn(b'# Example: ' + self.old_stop + b'\n', text)
        self.assertIn(b'Environment=KEEP_CUSTOM=true\n', text)
        self.assertIn(b'ExecStopPost=/bin/true\n', text)
        self.assertIn(b'\nExecStop=/bin/sh -c "docker compose --profile \'*\' down --remove-orphans"\n', text)
        self.assertEqual(self.before, self.backup.read_bytes())
        self.assertEqual(0o600, self.backup.stat().st_mode & 0o777)
        self.assertEqual(0o640, self.unit.stat().st_mode & 0o777)
        reload.assert_called_once_with(['systemctl', 'daemon-reload'], capture_output=True, check=True, timeout=30)

    def test_foreign_custom_and_symlink_units_are_preserved(self):
        with patch.object(modules.subprocess, 'run') as reload:
            foreign = self.before.replace(str(self.root).encode(), b'/different/installation')
            self.unit.write_bytes(foreign)
            self.assertFalse(modules.migrate_systemd_stop(self.root)); self.assertEqual(foreign, self.unit.read_bytes())
            custom = self.before.replace(b'\n' + self.old_stop + b'\n', b'\nExecStop=/usr/local/bin/custom-stop\n')
            self.unit.write_bytes(custom)
            self.assertFalse(modules.migrate_systemd_stop(self.root)); self.assertEqual(custom, self.unit.read_bytes())
            target = self.root / 'custom.service'; target.write_bytes(self.before)
            self.unit.unlink(); self.unit.symlink_to(target)
            self.assertFalse(modules.migrate_systemd_stop(self.root)); self.assertEqual(self.before, target.read_bytes())
            reload.assert_not_called()

    def test_daemon_reload_failure_restores_original_unit(self):
        failure = subprocess.CalledProcessError(1, ['systemctl', 'daemon-reload'])
        with patch.object(modules.subprocess, 'run', side_effect=[failure, subprocess.CompletedProcess([], 0)]):
            with self.assertRaises(subprocess.CalledProcessError): modules.migrate_systemd_stop(self.root)
        self.assertEqual(self.before, self.unit.read_bytes())
        self.assertEqual(self.before, self.backup.read_bytes())
        self.assertFalse(list(self.unit.parent.glob('*.tmp')))

    def test_failed_unit_replace_keeps_working_unit(self):
        replace = modules.os.replace
        def fail_unit(source, target):
            if target == self.unit: raise OSError('ENOSPC')
            return replace(source, target)
        with patch.object(modules.os, 'replace', side_effect=fail_unit), patch.object(modules.subprocess, 'run') as reload:
            with self.assertRaises(OSError): modules.migrate_systemd_stop(self.root)
            reload.assert_not_called()
        self.assertEqual(self.before, self.unit.read_bytes())
        self.assertFalse(list(self.unit.parent.glob('*.tmp')))

    def test_concurrent_unit_edit_is_not_overwritten(self):
        replace = modules.os.replace
        edited = self.before + b'# concurrent administrator edit\n'
        def edit_after_backup(source, target):
            result = replace(source, target)
            if target == self.backup: self.unit.write_bytes(edited)
            return result
        with patch.object(modules.os, 'replace', side_effect=edit_after_backup), patch.object(modules.subprocess, 'run') as reload:
            with self.assertRaises(RuntimeError): modules.migrate_systemd_stop(self.root)
            reload.assert_not_called()
        self.assertEqual(edited, self.unit.read_bytes())


if __name__ == '__main__': unittest.main()
