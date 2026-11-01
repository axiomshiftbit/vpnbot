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
