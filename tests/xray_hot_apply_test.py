import copy
import importlib.util
import json
import itertools
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('hot', Path(__file__).resolve().parents[1] / 'scripts/xray_hot_apply.py')
hot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hot)


def config():
    return {'inbounds': [
        {'tag': 'api', 'listen': '127.0.0.1', 'port': 8080, 'protocol': 'dokodemo-door'},
        {'tag': 'vless', 'protocol': 'vless', 'port': 443,
         'settings': {'clients': [{'id': 'test-id', 'email': 'old@example.test'}], 'decryption': 'none'}}],
        'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}, {'tag': 'block', 'protocol': 'blackhole'}],
        'routing': {'domainStrategy': 'AsIs', 'rules': [
            {'type': 'field', 'inboundTag': ['api'], 'outboundTag': 'api'},
            {'type': 'field', 'ip': ['127.0.0.0/8'], 'outboundTag': 'block'}]},
        'api': {'tag': 'api', 'services': ['StatsService', 'HandlerService', 'RoutingService']},
        'stats': {}, 'policy': {'levels': {'0': {'statsUserUplink': True}}}}


class HotPlanTest(unittest.TestCase):
    def test_node_ipv6_user_revocation_covers_both_listeners(self):
        old = config()
        old['policy']['levels']['0']['statsUserOnline'] = True
        node = copy.deepcopy(old['inbounds'][1])
        node.update(tag='node6-reality', listen='fd42:7662:6::9')
        old['inbounds'].append(node)
        new = copy.deepcopy(old)
        for inbound in new['inbounds'][1:]:
            inbound['settings']['clients'][0]['id'] = 'rotated'
        plan = hot.plan(old, new)
        self.assertEqual({r['tag'] for r in plan['revoke']}, {'vless', 'node6-reality'})
        self.assertEqual({r['tag'] for r in plan['inbounds']}, {'vless', 'node6-reality'})

    def test_noop(self):
        self.assertEqual(hot.plan(config(), config()), {'outbounds': [], 'inbounds': [], 'routing': None, 'revoke': []})

    def test_additions_and_routing_leave_input_unchanged(self):
        old = config()
        new = copy.deepcopy(old)
        new['inbounds'][1]['settings']['clients'].append({'id': 'new-id', 'email': 'new@example.test'})
        new['outbounds'].append({'tag': 'new', 'protocol': 'blackhole'})
        new['routing']['rules'].append({'type': 'field', 'domain': ['example.test'], 'outboundTag': 'new'})
        saved = copy.deepcopy(new)
        result = hot.plan(old, new)
        self.assertEqual(len(result['inbounds'][0]['settings']['clients']), 1)
        self.assertEqual(result['outbounds'], [new['outbounds'][2]])
        self.assertEqual(result['routing'], new['routing'])
        self.assertEqual(new, saved)
        self.assertEqual(old, config())

    def test_unsupported_changes(self):
        mutations = [
            lambda c: c['outbounds'].pop(),
            lambda c: c['outbounds'][1].update(protocol='freedom'),
            lambda c: c['outbounds'].reverse(),
            lambda c: c['inbounds'].pop(),
            lambda c: c['inbounds'][1].update(port=8443),
            lambda c: c['inbounds'][1]['settings']['clients'].clear(),
            # Без statsUserOnline отзыв не проверить: только перезапуск.
            lambda c: c['inbounds'][1]['settings']['clients'][0].update(id='changed'),
            lambda c: c['inbounds'][1]['settings']['clients'][0].update(level=1),
            lambda c: c['routing'].update(domainStrategy='IPIfNonMatch'),
            lambda c: c['routing'].update(script='custom script'),
            lambda c: c['routing']['rules'].pop(0),
            lambda c: c.update(dns={'servers': ['1.1.1.1']}),
            lambda c: c.update(observatory={'subjectSelector': ['new']}),
            lambda c: c['policy'].update(system={'statsOutboundUplink': True}),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(change=index):
                new = config()
                mutate(new)
                with self.assertRaises(ValueError):
                    hot.plan(config(), new)

    def test_bot_only_fields_need_nothing(self):
        for field, value in [('time', 1893456000), ('traffic', 10**9), ('subtoken', 'f' * 32), ('off', 'real-id'),
                             ('exit', ['n1']), ('hwid_limit', 2), ('hwid_disabled', 1), ('singtemplate', 'x'),
                             ('managed_protocols', {'anytls': 0}), ('ext', [{'url': 'https://e.test'}])]:
            with self.subTest(field=field):
                new = config()
                new['inbounds'][1]['settings']['clients'][0][field] = value
                self.assertEqual(hot.plan(config(), new), {'outbounds': [], 'inbounds': [], 'routing': None, 'revoke': []})

    def test_revocation_with_online_statistics(self):
        def online_config():
            c = config()
            c['policy']['levels']['0']['statsUserOnline'] = True
            c['inbounds'][1]['settings']['clients'].append({'id': 'second', 'email': 'second@example.test'})
            return c
        new = online_config()
        new['inbounds'][1]['settings']['clients'].pop(0)
        result = hot.plan(online_config(), new)
        self.assertEqual(result['revoke'], [{'tag': 'vless', 'email': 'old@example.test'}])
        self.assertEqual(result['inbounds'], [])
        # Смена учётных данных: отозвать и добавить заново под тем же email.
        for field, value in [('id', 'rotated'), ('flow', 'xtls-rprx-vision'), ('password', 'p'), ('reverse', {'tag': 'r'})]:
            with self.subTest(field=field):
                new = online_config()
                new['inbounds'][1]['settings']['clients'][0][field] = value
                result = hot.plan(online_config(), new)
                self.assertEqual(result['revoke'], [{'tag': 'vless', 'email': 'old@example.test'}])
                self.assertEqual(result['inbounds'][0]['settings']['clients'], [new['inbounds'][1]['settings']['clients'][0]])
        # Отключение ботом: настоящий id уходит в off, в id — случайный.
        new = online_config()
        new['inbounds'][1]['settings']['clients'][0].update(off='test-id', id='throwaway')
        self.assertEqual(hot.plan(online_config(), new)['revoke'], [{'tag': 'vless', 'email': 'old@example.test'}])
        refused = {
            'rename keeps the restart (per-email statistics)': lambda c: c['inbounds'][1]['settings']['clients'][0].update(email='renamed@example.test'),
            'loopback inbound (XDRIVE) is not counted online': lambda c: (c['inbounds'][1].update(listen='127.0.0.1'), c['inbounds'][1]['settings']['clients'].pop(0)),
            'user level without statsUserOnline': lambda c: c['inbounds'][1]['settings']['clients'].pop(0),
        }
        for label, mutate in refused.items():
            with self.subTest(label=label):
                old, new = online_config(), online_config()
                if 'loopback' in label:
                    old['inbounds'][1]['listen'] = '127.0.0.1'
                if 'level' in label:
                    for c in (old, new):
                        c['inbounds'][1]['settings']['clients'][0]['level'] = 3
                mutate(new)
                with self.assertRaises(ValueError):
                    hot.plan(old, new)
        old, new = online_config(), online_config()
        for c in (old, new):
            c['api']['services'].remove('StatsService')
        new['inbounds'][1]['settings']['clients'].pop(0)
        with self.assertRaises(ValueError):
            hot.plan(old, new)

    def test_remove_user_requires_complete_count(self):
        for output, ok in ((b'remove user: a Removed 1 user(s) in total.\n', True),
                           (b'remove user: a rpc error: code = Unknown desc = proxy/vless: User a not found. Removed 0 user(s) in total.\n', False),
                           (b'', False), (b'Removed 2 user(s) in total.\n', False)):
            with self.subTest(output=output), patch.object(hot.subprocess, 'run', return_value=
                    subprocess.CompletedProcess([], 0, stdout=output)):
                if ok:
                    hot.api('rmu', '-tag=vless', '--', 'a')
                else:
                    with self.assertRaises(ValueError):
                        hot.api('rmu', '-tag=vless', '--', 'a')
        with patch.object(hot.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, stdout=b'Removed 1 user(s) in total.\n')) as run:
            hot.api('rmu', '-tag=vless', '--', '-server=198.51.100.1:80')
            self.assertEqual(run.call_args[0][0][-2:], ['--', '-server=198.51.100.1:80'], 'email after --, never a flag')

    def test_online_parsing(self):
        cases = [
            (1, b'failed to get stats: rpc error: code = NotFound desc = user>>>a>>>online not found.', 0),
            (0, b'{"stat": {"name": "user>>>a>>>online", "value": 2}}', 2),
            (0, b'{"stat": {"name": "user>>>a>>>online"}}', 0),
            (1, b'failed to dial 127.0.0.1:8080', None),
            (0, b'{"stat": {"name": "user>>>b>>>online", "value": 0}}', None),
            (0, b'{"stat": {"name": "user>>>a>>>online", "value": -1}}', None),
        ]
        for rc, output, expected in cases:
            with self.subTest(output=output), patch.object(hot.subprocess, 'run', return_value=
                    subprocess.CompletedProcess([], rc, stdout=output)):
                if expected is None:
                    with self.assertRaises(ValueError):
                        hot.online('a')
                else:
                    self.assertEqual(hot.online('a'), expected)

    def test_apply_revokes_first_and_restarts_for_online_users(self):
        old = config()
        old['policy']['levels']['0']['statsUserOnline'] = True
        new = copy.deepcopy(old)
        new['inbounds'][1]['settings']['clients'][0]['id'] = 'rotated'
        new['outbounds'].append({'tag': 'extra', 'protocol': 'blackhole'})
        for sessions in (0, 1):
            with self.subTest(sessions=sessions), tempfile.TemporaryDirectory() as directory:
                state, conf = Path(directory) / 'state', Path(directory) / 'xray.json'
                state.mkdir(mode=0o700)
                conf.write_text(json.dumps(new))
                calls = []
                identity = {'pid': 1, 'start': '1', 'binary': '/x'}
                with patch.object(hot, 'STATE', state), patch.object(hot, 'CONFIG', conf), \
                        patch.object(hot, 'atomic_router', return_value=True), \
                        patch.object(hot, 'read_private', return_value={**identity, 'digest': hot.digest(old)}), \
                        patch.object(hot, 'process_identity', return_value=identity), \
                        patch.object(hot, 'owns_api', return_value=True), \
                        patch.object(hot, 'api', side_effect=lambda command, *a: calls.append(command)), \
                        patch.object(hot, 'online', side_effect=lambda email: calls.append('online') or sessions):
                    (state / 'state.json').write_text('{}')
                    if sessions:
                        with self.assertRaises(ValueError):
                            hot.apply(old, new)
                        self.assertFalse((state / 'state.json').exists(), 'no trusted marker after a refused update')
                    else:
                        hot.apply(old, new)
                        self.assertTrue((state / 'state.json').exists())
                self.assertEqual(calls, ['rmu', 'ado', 'adu', 'online'])

    def test_sync_moves_marker_only_for_bot_fields(self):
        old = config()
        bot_only = copy.deepcopy(old)
        bot_only['inbounds'][1]['settings']['clients'][0]['time'] = 1893456000
        core = copy.deepcopy(old)
        core['inbounds'][1]['settings']['clients'].append({'id': 'n', 'email': 'n@example.test'})
        identity = {'pid': 1, 'start': '1', 'binary': '/x'}
        for target, marked, ok in ((bot_only, old, True), (core, old, False), (bot_only, core, False)):
            with self.subTest(ok=ok), tempfile.TemporaryDirectory() as directory:
                state, conf = Path(directory) / 'state', Path(directory) / 'xray.json'
                state.mkdir(mode=0o700)
                conf.write_text(json.dumps(target))
                marker = {**identity, 'digest': hot.digest(marked)}
                with patch.object(hot, 'STATE', state), patch.object(hot, 'CONFIG', conf), \
                        patch.object(hot, 'read_private', return_value=marker), \
                        patch.object(hot, 'process_identity', return_value=identity), \
                        patch.object(hot, 'owns_api', return_value=True), \
                        patch.object(hot, 'save_state') as save:
                    if ok:
                        hot.sync(old, target)
                        save.assert_called_once_with(identity, target)
                    else:
                        with self.assertRaises(ValueError):
                            hot.sync(old, target)
                        save.assert_not_called()

    def test_ambiguous_identifiers(self):
        for field in ('inbounds', 'outbounds'):
            with self.subTest(field=field):
                new = config()
                new[field].append(copy.deepcopy(new[field][0]))
                with self.assertRaises(ValueError):
                    hot.plan(config(), new)
        for email in ('', 'old@example.test'):
            new = config()
            new['inbounds'][1]['settings']['clients'].append({'email': email, 'id': 'another'})
            with self.assertRaises(ValueError):
                hot.plan(config(), new)

    def test_api_must_remain_private_and_enabled(self):
        for address in ('0.0.0.0', '::', '10.10.0.9'):
            old = config()
            old['inbounds'][0]['listen'] = address
            with self.assertRaises(ValueError):
                hot.plan(old, copy.deepcopy(old))
        old = config()
        old['api']['services'].remove('RoutingService')
        with self.assertRaises(ValueError):
            hot.plan(old, copy.deepcopy(old))

    def test_canonical_php_objects(self):
        old, new = config(), config()
        new['stats'] = []
        new['policy']['levels'] = [new['policy']['levels']['0']]
        self.assertEqual(hot.digest(old), hot.digest(new))
        self.assertEqual(hot.plan(old, new)['outbounds'], [])

    def test_add_user_requires_complete_count_even_when_cli_exits_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / 'users.json'
            payload.write_text(json.dumps({'inbounds': [{'settings': {'clients': [{}, {}]}}]}))
            for output in (b'', b'failed to add user\n', b'\nAdded 1 user(s) in total.\n',
                           b'\nAdded 2 user(s) in total.\nfailed later\n'):
                with self.subTest(output=output), patch.object(hot.subprocess, 'run', return_value=
                        subprocess.CompletedProcess([], 0, stdout=output)):
                    with self.assertRaises(ValueError):
                        hot.api('adu', payload)
            with patch.object(hot.subprocess, 'run', return_value=
                    subprocess.CompletedProcess([], 0, stdout=b'adding users\nAdded 2 user(s) in total.\n')):
                hot.api('adu', payload)

    def test_only_verified_atomic_router_versions_are_allowed(self):
        for version, expected in [('26.7.28', False), ('26.9.30', True), ('26.10.29', True), ('26.10.31', True),
                                  ('26.10.28-1202', True), ('26.10.28-unknown', False),
                                  ('27.1.1', False)]:
            with self.subTest(version=version), patch.object(hot.subprocess, 'run', return_value=
                    subprocess.CompletedProcess([], 0, stdout=f'Xray {version} (Xray)\n'.encode())):
                self.assertEqual(hot.atomic_router(), expected)

    def test_mark_waits_for_child_exec_without_accepting_pid_reuse(self):
        identity = {'pid': 123, 'start': '10', 'binary': '/usr/bin/xray'}
        with patch.object(hot, 'CONFIG') as cfg, patch.object(hot, 'save_state') as save, \
                patch.object(hot, 'api'), patch.object(hot, 'owns_api', return_value=True), \
                patch.object(hot.time, 'sleep'):
            cfg.read_text.return_value = '{}'
            with patch.object(hot, 'process_identity', side_effect=[ValueError('not exec yet'), identity, identity]):
                hot.mark(123)
            save.assert_called_once_with(identity, {})
            save.reset_mock()
            identities = itertools.chain([identity], itertools.repeat({**identity, 'start': '11'}))
            with patch.object(hot, 'process_identity', side_effect=lambda pid: next(identities)):
                with self.assertRaises(ValueError):
                    hot.mark(123)
            save.assert_not_called()


if __name__ == '__main__':
    unittest.main()
