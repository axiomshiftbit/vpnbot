import copy
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from masque_service import MasqueSupervisor
from protocol_service import atomic_json


class MasqueTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        code = '''require $argv[1]; require $argv[2];
            $s = new ManagedProtocol('masque', $argv[3]);
            $s->configure(['host'=>'vpn.example.test','sni'=>'vpn.example.test'],true);
            managedProtocolFixtureUser($s,'Test'); readfile($s->directory().'/desired.json');'''
        self.state = json.loads(subprocess.check_output(['php', '-r', code, str(ROOT/'app/ManagedProtocol.php'),
            str(ROOT/'tests/managed_protocol_fixture.php'), str(self.root/'protocols')]))
        self.uid = next(iter(self.state['users']))
        self.supervisor = MasqueSupervisor(self.root/'runtime')

    def test_php_config_and_credentials_match_native_api(self):
        config, users = self.supervisor.prepare(self.state)
        self.assertIsInstance(config['stats'], dict)
        self.assertIsInstance(config['policy']['levels'], dict)
        self.assertEqual([{'email': self.uid, 'pass': users[self.uid]['password'], 'level': 0}], config['inbounds'][0]['settings']['users'])
        self.assertTrue(self.supervisor.credentials_allowed(self.supervisor.authentication(config), users))
        rotated = copy.deepcopy(users); rotated[self.uid]['password'] = 'A'*43
        self.assertFalse(self.supervisor.credentials_allowed(self.supervisor.authentication(config), rotated))
        self.assertFalse(self.supervisor.credentials_allowed(self.supervisor.authentication(config), {}))

    def test_expiry_quota_and_reset_use_durable_totals(self):
        s = self.supervisor; s.prepare(self.state)
        record = s.usage['users'][self.uid]; record.update(upload=40, download=60)
        self.state['users'][self.uid]['quota'] = 100
        self.assertFalse(s.prepare(self.state)[1])
        atomic_json(s.root/'usage.json', s.usage)
        restored = MasqueSupervisor(s.root)
        self.assertFalse(restored.prepare(self.state)[1])
        self.state['users'][self.uid]['reset'] = 'f'*16
        self.assertTrue(restored.prepare(self.state)[1])
        self.state['users'][self.uid]['expires'] = int(time.time())-1
        self.assertFalse(restored.prepare(self.state)[1])
        self.state['users'][self.uid]['expires'] = None; self.state['users'][self.uid]['enabled'] = False
        self.assertFalse(restored.prepare(self.state)[1])

    def test_private_api_and_input_validation(self):
        for key, value in [('port', 10086), ('listen', '0.0.0.0'), ('tag', 'public')]:
            bad = copy.deepcopy(self.state); bad['config']['inbounds'][1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.supervisor.prepare(bad)
        self.state['users'][self.uid]['password'] = 'bad'
        with self.assertRaises(ValueError): self.supervisor.prepare(self.state)

    def test_actual_xray_stats_wire_format(self):
        result = subprocess.CompletedProcess([], 0, json.dumps({'stat': [
            {'name': f'user>>>{self.uid}>>>traffic>>>uplink', 'value': '125'},
            {'name': f'user>>>{self.uid}>>>traffic>>>downlink', 'value': 256}]}).encode())
        with patch('masque_service.subprocess.run', return_value=result) as run:
            self.assertEqual({self.uid: {'upload': 125, 'download': 256}}, self.supervisor.counters())
            self.assertIn('--server=127.0.0.1:10085', run.call_args.args[0])
            self.assertNotIn('--reset', run.call_args.args[0])

    def test_tls_pair_checked_even_when_core_accepts_config(self):
        for name in ('correct', 'other'):
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                '-nodes', '-days', '1', '-subj', '/CN=vpn.example.test', '-addext', 'subjectAltName=DNS:vpn.example.test',
                '-keyout', str(self.root/(name+'.key')), '-out', str(self.root/(name+'.pem'))],
                check=True, capture_output=True)
        config, _ = self.supervisor.prepare(self.state)
        cert = config['inbounds'][0]['streamSettings']['tlsSettings']['certificates'][0]
        cert.update(certificateFile=str(self.root/'correct.pem'), keyFile=str(self.root/'other.key'))
        self.supervisor.binary = '/bin/true'  # Simulate a core that accepts an unusable TLS pair.
        with patch.object(self.supervisor, 'check_ports'):
            with self.assertRaisesRegex(RuntimeError, '^tls_key_mismatch$'):
                self.supervisor.candidate(config, self.state)
            self.assertEqual([], list(self.supervisor.root.glob('generation-*')))
            cert['keyFile'] = str(self.root/'correct.key')
            directory, _ = self.supervisor.candidate(config, self.state)
            self.assertTrue((directory/'config.json').is_file())

    def test_api_preflight_never_has_public_listener(self):
        generation = self.root/'generation'; generation.mkdir()
        atomic_json(generation/'config.json', self.state['config'])
        class Process:
            def poll(self): return None
            def terminate(self): pass
            def wait(self, timeout): return 0
        self.supervisor.prepare(self.state)
        with patch.object(self.supervisor, 'launch', return_value=Process()), \
             patch.object(self.supervisor, 'wait_api', side_effect=RuntimeError('stats_unavailable')):
            with self.assertRaises(RuntimeError): self.supervisor.start(generation, self.state['users'])
        config = json.loads((generation/'api-check.json').read_text())
        self.assertEqual(['api'], [i['tag'] for i in config['inbounds']])
        self.supervisor.process = None
        if self.supervisor.log: self.supervisor.log.close()

    def test_corrupt_usage_cannot_grant_fresh_quota(self):
        (self.supervisor.root/'usage.json').write_text('{broken')
        with self.assertRaises(ValueError): MasqueSupervisor(self.supervisor.root)


if __name__ == '__main__': unittest.main()
