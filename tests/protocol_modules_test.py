import importlib.util
import itertools
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('protocol_modules', ROOT / 'scripts/protocol_modules.py')
modules = importlib.util.module_from_spec(spec)
spec.loader.exec_module(modules)


class ProtocolModulesTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / 'config').mkdir()
        (self.root / 'update').mkdir()
        self.desired = self.root / 'config/protocol-services.json'
        self.status = self.root / 'config/protocol-services.status.json'
        self.ports = {'mieru': 24445, 'tuic': 9443, 'shadowtls': 24447, 'snolc': 24448, 'masque': 24449}
        for name, options in [('bindings', {'return_value': self.ports}), ('sync_certificates', {}),
                              ('check_port', {}), ('prepare_upstream', {})]:
            stub = patch.object(modules, name, **options)
            stub.start(); self.addCleanup(stub.stop)
        stub = patch.object(modules, 'container_states', side_effect=lambda current: {
            service: 'running' for service in modules.SERVICES if modules.enabled(current, service)})
        stub.start(); self.addCleanup(stub.stop)

    def test_missing_enabled_containers_are_recreated_after_external_deployment(self):
        current = modules.DEFAULTS.copy()
        self.state(current)
        with patch.object(modules, 'container_states', return_value={'telemt': 'running'}), \
             patch.object(modules, 'compose', return_value=subprocess.CompletedProcess([], 0)) as compose:
            modules.apply(self.root)
        restarted = [call.args[1][-1] for call in compose.call_args_list if call.args[1][:1] == ['up']]
        self.assertEqual(set(restarted), {s for s in modules.SERVICES if modules.enabled(current, s)} - {'telemt'})
        state = json.loads(self.status.read_text())
        self.assertTrue(state['ok'])
        self.assertEqual(current, state['settings'])
        self.assertGreater(state['checked_at'], 0)

    def test_periodic_reconciliation_does_not_probe_docker_each_second(self):
        current = modules.DEFAULTS.copy()
        self.state(current)
        modules.apply(self.root)
        with patch.object(modules, 'container_states') as snapshot:
            modules.apply(self.root)
            snapshot.assert_not_called()

    def test_disabled_but_externally_started_container_is_removed(self):
        current = dict.fromkeys(modules.DEFAULTS, False)
        self.state(current)
        with patch.object(modules, 'container_states', return_value={'telemt': 'running'}), \
             patch.object(modules, 'compose', return_value=subprocess.CompletedProcess([], 0)) as compose:
            modules.apply(self.root)
        self.assertEqual([['stop', '--timeout', '45', 'telemt'], ['rm', '--force', 'telemt']],
                         [call.args[1] for call in compose.call_args_list])

    def test_inventory_failure_does_not_recreate_or_stop_services(self):
        self.state(modules.DEFAULTS.copy())
        before = self.status.read_bytes()
        with patch.object(modules, 'container_states', side_effect=RuntimeError('Docker unavailable')), \
             patch.object(modules, 'compose') as compose:
            with self.assertRaises(RuntimeError): modules.apply(self.root)
            compose.assert_not_called()
        self.assertEqual(before, self.status.read_bytes())

    def state(self, settings):
        self.desired.write_text(json.dumps(settings))
        self.status.write_text(json.dumps({'ok': True, 'settings': settings, 'bindings': self.ports}))

    def test_fresh_install_starts_only_telemt_and_never_overwrites(self):
        self.assertTrue(modules.fresh_minimal(self.root))
        saved = json.loads(self.desired.read_text())
        self.assertEqual(saved, {name: name == 'telemt' for name in modules.DEFAULTS})
        self.assertEqual(self.desired.stat().st_mode & 0o777, 0o600)
        current = modules.settings(self.root)
        self.assertEqual([s for s in modules.SERVICES if modules.enabled(current, s)], ['telemt'])
        self.assertEqual(modules.environment(current)['COMPOSE_PROFILES'], 'telemt')
        # Повторный вызов и переустановка не меняют выбор администратора.
        self.desired.write_text(json.dumps({'oc': True}))
        self.assertFalse(modules.fresh_minimal(self.root))
        self.assertEqual(json.loads(self.desired.read_text()), {'oc': True})
        self.assertEqual(list(self.root.glob('config/*.tmp')), [])
        # Установка без файла (до модулей) по-прежнему работает со штатным набором.
        self.desired.unlink()
        self.assertEqual(modules.settings(self.root), modules.DEFAULTS)
        # Включённый позже модуль поднимается штатным apply.
        modules.fresh_minimal(self.root)
        self.state(modules.settings(self.root))
        enabled = modules.settings(self.root) | {'oc': True, 'hy': True}
        self.desired.write_text(json.dumps(enabled))
        with patch.object(modules, 'container_states', return_value={'telemt': 'running'}), \
             patch.object(modules, 'compose', return_value=subprocess.CompletedProcess([], 0)) as compose:
            modules.apply(self.root)
        started = [call.args[1] for call in compose.call_args_list if call.args[1][:1] == ['up']]
        self.assertEqual(sorted(args[-1] for args in started), ['hy', 'oc'])

    def test_init_writes_minimal_modules_only_for_a_new_installation(self):
        source = (ROOT / 'scripts/init.sh').read_text()
        branch = source[source.index('if [ -s ./app/config.php ]; then'):source.index('make u\n')]
        kept, created = branch.split('else', 1)
        self.assertNotIn('fresh-minimal', kept)
        self.assertIn('python3 scripts/protocol_modules.py fresh-minimal', created)
        self.assertLess(created.index('cat > ./app/config.php'), created.index('fresh-minimal'))

    def test_php_and_host_agree_on_defaults_and_ipsec_dependencies(self):
        code = 'require $argv[1]; echo json_encode(ProtocolModules::DEFAULTS);'
        result = subprocess.run(['php', '-r', code, str(ROOT / 'app/ProtocolModules.php')],
                                capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout), modules.DEFAULTS)
        for ipsec, ikev2, l2tp in itertools.product((False, True), repeat=3):
            settings = modules.DEFAULTS | {'ipsec': ipsec, 'ikev2': ikev2, 'l2tp': l2tp}
            with self.subTest(ipsec=ipsec, ikev2=ikev2, l2tp=l2tp), patch.dict('os.environ', {'VER': 'test'}):
                env = modules.environment(settings)
                self.assertEqual(ipsec and (ikev2 or l2tp), 'ipsec' in env['COMPOSE_PROFILES'].split(','))
                self.assertEqual(str(int(ipsec and ikev2)), env['IPSEC_IKEV2_ENABLED'])
                self.assertEqual(str(int(ipsec and l2tp)), env['IPSEC_L2TP_ENABLED'])

    def test_every_optional_container_stops_removes_and_restarts_without_touching_saved_data(self):
        saved = self.root / 'config/saved-data'
        saved.write_bytes(b'synthetic credentials and settings\x00')
        for service in modules.SERVICES:
            with self.subTest(service=service):
                enabled = modules.DEFAULTS | {service: True}
                self.state(enabled)
                with patch.object(modules, 'compose', return_value=subprocess.CompletedProcess([], 0)) as compose:
                    self.desired.write_text(json.dumps(enabled | {service: False}))
                    modules.apply(self.root)
                    self.assertEqual([['stop', '--timeout', '45' if service == 'telemt' else '10', service], ['rm', '--force', service]],
                                     [call.args[1] for call in compose.call_args_list])
                    self.assertFalse(json.loads(self.status.read_text())['settings'][service])
                    compose.reset_mock(); modules.apply(self.root)
                    compose.assert_not_called()
                    self.desired.write_text(json.dumps(enabled)); modules.apply(self.root)
                    calls = [call.args[1] for call in compose.call_args_list]
                    self.assertEqual(['up', '-d', '--no-deps', service], calls[0])
                    self.assertEqual(2 if service == 'oc' else 1, len(calls))
                    self.assertTrue(json.loads(self.status.read_text())['ok'])
                    self.assertEqual(b'synthetic credentials and settings\x00', saved.read_bytes())

    def test_failed_stop_or_remove_is_reported_and_retried(self):
        for failed_action in ('stop', 'rm'):
            with self.subTest(failed_action=failed_action):
                self.state(modules.DEFAULTS)
                self.desired.write_text(json.dumps(modules.DEFAULTS | {'ovpn': False}))
                with patch.object(modules, 'compose') as compose:
                    compose.side_effect = lambda _s, args, **_kw: subprocess.CompletedProcess(args, int(args[0] == failed_action))
                    modules.apply(self.root)
                    status = json.loads(self.status.read_text())
                    self.assertFalse(status['ok'])
                    self.assertTrue(status['settings']['ovpn'])
                    self.assertEqual({'ovpn': 'operation_failed'}, status['errors'])
                    if failed_action == 'stop': self.assertEqual(1, compose.call_count)
                    compose.reset_mock(); compose.side_effect = None
                    compose.return_value = subprocess.CompletedProcess([], 0)
                    modules.apply(self.root)
                    self.assertEqual([['stop', '--timeout', '10', 'ovpn'], ['rm', '--force', 'ovpn']],
                                     [call.args[1] for call in compose.call_args_list])
                    self.assertTrue(json.loads(self.status.read_text())['ok'])

    def test_interrupted_operation_is_reconciled_even_after_user_reverses_toggle(self):
        for initially_enabled in (False, True):
            with self.subTest(initially_enabled=initially_enabled):
                before = modules.DEFAULTS | {'ovpn': initially_enabled}
                self.state(before)
                self.desired.write_text(json.dumps(before | {'ovpn': not initially_enabled}))
                # Docker changed reality; the worker died before recording the result.
                with patch.object(modules, 'compose', side_effect=InterruptedError('worker interrupted')):
                    with self.assertRaises(InterruptedError): modules.apply(self.root)
                self.desired.write_text(json.dumps(before))
                with patch.object(modules, 'compose', return_value=subprocess.CompletedProcess([], 0)) as compose:
                    modules.apply(self.root)
                    expected = ([['up', '-d', '--no-deps', 'ovpn']] if initially_enabled else
                                [['stop', '--timeout', '10', 'ovpn'], ['rm', '--force', 'ovpn']])
                    self.assertEqual(expected, [call.args[1] for call in compose.call_args_list])
                    self.assertTrue(json.loads(self.status.read_text())['ok'])

    def test_failed_final_status_write_does_not_leave_enabled_container_after_reversal(self):
        before = modules.DEFAULTS | {'ovpn': False}
        self.state(before)
        self.desired.write_text(json.dumps(before | {'ovpn': True}))
        write_status = modules.write_status

        def fail_final(path, value):
            if value['ok']: raise OSError('disk full')
            write_status(path, value)

        with patch.object(modules, 'write_status', side_effect=fail_final), \
                patch.object(modules, 'compose', return_value=subprocess.CompletedProcess([], 0)):
            with self.assertRaises(OSError): modules.apply(self.root)
        self.desired.write_text(json.dumps(before))
        with patch.object(modules, 'compose', return_value=subprocess.CompletedProcess([], 0)) as compose:
            modules.apply(self.root)
            self.assertEqual([['stop', '--timeout', '10', 'ovpn'], ['rm', '--force', 'ovpn']],
                             [call.args[1] for call in compose.call_args_list])

    def test_failed_intent_write_does_not_change_running_containers(self):
        self.state(modules.DEFAULTS)
        before = self.status.read_bytes()
        self.desired.write_text(json.dumps(modules.DEFAULTS | {'ovpn': False}))
        with patch.object(modules, 'write_status', side_effect=OSError('disk full')), \
                patch.object(modules, 'compose') as compose:
            with self.assertRaises(OSError): modules.apply(self.root)
            compose.assert_not_called()
        self.assertEqual(before, self.status.read_bytes())

    def test_another_interruption_does_not_forget_an_earlier_pending_service(self):
        before = modules.DEFAULTS | {'ovpn': False}
        self.state(before)
        self.desired.write_text(json.dumps(before | {'ovpn': True}))
        with patch.object(modules, 'compose', side_effect=InterruptedError('after enabling ovpn')):
            with self.assertRaises(InterruptedError): modules.apply(self.root)
        # Reverse OpenVPN and change an earlier service in the worker's order.
        current = before | {'oc': False}
        self.desired.write_text(json.dumps(current))
        with patch.object(modules, 'compose', side_effect=InterruptedError('before retrying ovpn')):
            with self.assertRaises(InterruptedError): modules.apply(self.root)
        with patch.object(modules, 'compose', return_value=subprocess.CompletedProcess([], 0)) as compose:
            modules.apply(self.root)
            self.assertIn(['rm', '--force', 'ovpn'], [call.args[1] for call in compose.call_args_list])
            self.assertEqual(current, json.loads(self.status.read_text())['settings'])

    def test_ipsec_children_reconfigure_only_shared_container(self):
        before = modules.DEFAULTS.copy()
        self.state(before)
        for changes, running in [({'ikev2': False}, True), ({'l2tp': False}, False),
                                 ({'ikev2': True}, True), ({'ipsec': False}, False),
                                 ({'l2tp': True}, False), ({'ipsec': True}, True)]:
            before |= changes
            self.desired.write_text(json.dumps(before))
            with self.subTest(changes=changes), patch.object(modules, 'compose', return_value=subprocess.CompletedProcess([], 0)) as compose:
                modules.apply(self.root)
                expected = ([['up', '-d', '--no-deps', 'ipsec']] if running else
                            [['stop', '--timeout', '10', 'ipsec'], ['rm', '--force', 'ipsec']])
                self.assertEqual(expected, [call.args[1] for call in compose.call_args_list])
                self.assertEqual(before, json.loads(self.status.read_text())['settings'])


if __name__ == '__main__':
    unittest.main()
