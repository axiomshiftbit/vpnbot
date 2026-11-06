import base64
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import signal
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import node_runtime
from node_config_test import HOST, OPTIONS, KEYS


class MetadataTest(unittest.TestCase):
    def test_public_status_has_versions_certificate_without_private_material(self):
        value = {'options': copy.deepcopy(OPTIONS), 'identity': KEYS,
                 'images': {'xr': 'fixture-image'}, 'peers': [],
                 'tls': {'fullchain.pem': base64.b64encode(b'PUBLIC CERTIFICATE').decode(),
                         'privkey.pem': base64.b64encode(b'PRIVATE-FIXTURE-DO-NOT-READ').decode()}}
        class Store:
            def load(self): return value
            def current(self): return 'a'*32
            def pending(self): return None
        class Runtime(node_runtime.Runtime):
            def container(self, name=node_runtime.CONTAINER): return {'State': {'Running': True}}
        with tempfile.TemporaryDirectory() as temp:
            store = Store(); store.root = Path(temp)
            calls = []
            def command(args, **kwargs):
                calls.append((list(map(str, args)), kwargs.get('data')))
                if args[0] == 'openssl':
                    return subprocess.CompletedProcess(args, 0, b'notAfter=Jan  1 00:00:00 2030 GMT\nX509v3 Subject Alternative Name:\n    DNS:node.example.test, DNS:alt.example.test\n', b'')
                return subprocess.CompletedProcess(args, 0, b'Xray 26.10.31 (Xray, Penetrates Everything.)\n', b'')
            with patch.object(node_runtime, 'command', command):
                status = Runtime(store, HOST).status()
            self.assertEqual(set(status.get('cores', {})), {'origin', 'origin2', 'origin3', 'fork'})
            self.assertEqual(status.get('certificate', {}).get('expires'), 1893456000)
            self.assertEqual(status['certificate']['domains'], ['node.example.test', 'alt.example.test'])
            self.assertNotIn('PRIVATE-FIXTURE-DO-NOT-READ', str(calls))
            self.assertNotIn('identity', status)
            self.assertNotIn('tls', status)

    def test_legacy_awg_status_can_be_submitted_unchanged(self):
        from unittest.mock import Mock
        import node_awg, node_config
        key=base64.urlsafe_b64encode(b'a'*32).decode().rstrip('=')
        identity=node_awg.generate(lambda: {'private':key,'public':key})
        for version in node_awg.VERSIONS:
            store=Mock()
            store.load.return_value={'options':OPTIONS | {'amnezia':{'version':version,'enabled':True}},
                'identity':KEYS | {'amnezia':identity},'peers':[],'tls':{}}
            runtime=node_runtime.Runtime(store,HOST)
            with patch.object(runtime,'container',return_value={'State':{'Running':True}}), patch.object(runtime,'core_versions',return_value={}):
                status=runtime.status()
            node_config.settings(status['options'])
            self.assertNotIn('HeaderProtectionKey',status['options']['amnezia']['parameters'])

    def test_watch_state_matches_status_without_metadata_commands(self):
        # watch runs every 15 s: it must not pay for four core version execs
        # and the certificate parse, yet decide exactly like status().
        import itertools
        from unittest.mock import Mock
        names = (node_runtime.CONTAINER, node_runtime.COVER_CONTAINER, node_runtime.AWG_CONTAINER)
        for cover, awg, *states in itertools.product((False, True), (False, True), (None, False, True), (None, False, True), (None, False, True)):
            store = Mock()
            store.load.return_value = {'options': OPTIONS | {'cover': cover, 'amnezia': {'enabled': awg}},
                                       'identity': KEYS, 'peers': [], 'tls': {}}
            runtime = node_runtime.Runtime(store, HOST)
            containers = {name: None if state is None else {'State': {'Running': state}} for name, state in zip(names, states)}
            with patch.object(runtime, 'container', side_effect=lambda name=node_runtime.CONTAINER: containers[name]), \
                    patch.object(runtime, 'core_versions', side_effect=AssertionError('no version execs in watch')), \
                    patch.object(runtime, 'certificate_summary', side_effect=AssertionError('no certificate parse in watch')), \
                    patch.object(node_runtime, 'command', side_effect=AssertionError('no host commands in watch')):
                running = runtime.running()
            with patch.object(runtime, 'container', side_effect=lambda name=node_runtime.CONTAINER: containers[name]), \
                    patch.object(runtime, 'core_versions', return_value={}), patch.object(runtime, 'certificate_summary', return_value={}), \
                    patch.object(node_runtime.config.node_awg, 'settings', return_value={}):
                self.assertEqual(running, runtime.status()['running'], (cover, awg, states))
        source = (Path(__file__).resolve().parents[1]/'scripts/node_manager.py').read_text()
        self.assertIn('elif not manager.runtime.running():', source)
        self.assertNotIn("runtime.status()['running']", source)

    def test_core_versions_are_reused_only_for_the_same_container_start(self):
        import node_state
        with tempfile.TemporaryDirectory() as temp:
            rt = node_runtime.Runtime(node_state.Store(Path(temp)/'state'), HOST)
            calls = []
            answer = {'value': b'Xray 26.10.31 (Xray, Penetrates Everything.)\n'}
            def command(args, **kwargs):
                calls.append(args)
                if '/usr/bin/xray-3' in args and answer.get('fail3'):
                    raise subprocess.TimeoutExpired('fixture', 1)
                return subprocess.CompletedProcess(args, 0, answer['value'], b'')
            first = {'Id': 'a'*64, 'State': {'Running': True, 'StartedAt': '2026-11-06T07:00:00Z'}}
            with patch.object(node_runtime, 'command', command):
                expected = {core: '26.10.31' for core in node_runtime.config.CORES}
                self.assertEqual(rt.core_versions(first), expected)
                self.assertEqual(len(calls), 4)
                self.assertEqual(rt.core_versions(first), expected)
                self.assertEqual(len(calls), 4, 'same container start: no version execs')
                restarted = copy.deepcopy(first); restarted['State']['StartedAt'] = '2026-11-06T08:00:00Z'
                answer['value'] = b'Xray 26.11.1 (Xray, Penetrates Everything.)\n'
                self.assertEqual(set(rt.core_versions(restarted).values()), {'26.11.1'})
                self.assertEqual(len(calls), 8, 'a restarted container is measured again')
                other = copy.deepcopy(restarted); other['Id'] = 'b'*64; answer['fail3'] = True
                self.assertNotIn('origin3', rt.core_versions(other))
                self.assertEqual(len(rt.core_versions(other)), 3)
                self.assertEqual(len(calls), 16, 'an incomplete answer is not reused')
                (Path(temp)/'state/core-versions.json').write_bytes(b'{"container":')
                answer.pop('fail3')
                self.assertEqual(len(rt.core_versions(other)), 4, 'a damaged cache is ignored')
                self.assertEqual(rt.core_versions({'State': {'Running': True}}), {core: '26.11.1' for core in node_runtime.config.CORES})
                before = len(calls)
                rt.core_versions({'State': {'Running': True}})
                self.assertEqual(len(calls), before+4, 'no container identity: never cached')

    def test_metadata_timeouts_do_not_hide_service_status(self):
        rt = node_runtime.Runtime(None, HOST)
        with patch.object(node_runtime, 'command', side_effect=subprocess.TimeoutExpired('fixture', 3)):
            self.assertEqual(rt.core_versions({'State': {'Running': True}}), {})
            self.assertEqual(rt.certificate_summary({'fullchain.pem': base64.b64encode(b'CERT').decode()}), {})

    def test_global_rpc_deadline_is_not_an_optional_metadata_failure(self):
        rt = node_runtime.Runtime(None, HOST)
        with patch.object(node_runtime, 'command', side_effect=TimeoutError('RPC deadline')):
            with self.assertRaises(TimeoutError): rt.core_versions({'State': {'Running': True}})
            with self.assertRaises(TimeoutError): rt.certificate_summary({'fullchain.pem': base64.b64encode(b'CERT').decode()})

    def test_hung_version_commands_cannot_consume_rpc_deadline(self):
        rt = node_runtime.Runtime(None, HOST)
        def hanging(args, **kwargs):
            time.sleep(kwargs['timeout'])
            raise subprocess.TimeoutExpired('fixture', kwargs['timeout'])
        previous = signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('RPC deadline')))
        signal.alarm(12)
        started=time.monotonic()
        try:
            with patch.object(node_runtime, 'command', hanging):
                self.assertEqual(rt.core_versions({'State': {'Running': True}}), {})
                self.assertEqual(rt.certificate_summary({'fullchain.pem': base64.b64encode(b'CERT').decode()}), {})
            self.assertLess(time.monotonic()-started,11,'optional metadata must fit inside the RPC deadline')
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)


if __name__ == '__main__': unittest.main()
