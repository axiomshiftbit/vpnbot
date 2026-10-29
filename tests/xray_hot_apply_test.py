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
    def test_noop(self):
        self.assertEqual(hot.plan(config(), config()), {'outbounds': [], 'inbounds': [], 'routing': None})

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
            lambda c: c['inbounds'][1]['settings']['clients'][0].update(id='changed'),
            lambda c: c['inbounds'][1]['settings']['clients'][0].update(off=True),
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
        for version, expected in [('26.7.28', False), ('26.9.30', True), ('26.10.29', True),
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
