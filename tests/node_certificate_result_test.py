"""Certificate jobs distinguish issuance, no-op and failures without restarting on no-op."""
import base64
import copy
import unittest
import node_manager_test as fixtures

class CertificateResultTest(unittest.TestCase):
    setUp = fixtures.NodeManager.setUp
    def certificate_state(self):
        value = copy.deepcopy(self.store.load())
        value['options'].update(transport='ws', domain='node.example.test')
        value['tls'] = {k:base64.b64encode(v).decode() for k,v in
                        [('fullchain.pem', b'-----BEGIN CERTIFICATE-----old'), ('privkey.pem', b'-----BEGIN PRIVATE KEY-----synthetic')]}
        generation = self.store.create(value)
        self.store.activate(generation)
        return value, generation

    def test_renew_same_certificate_does_not_restart_or_claim_renewal(self):
        value, generation = self.certificate_state()
        self.backend.certificate = lambda *a: dict(value['tls'])
        result = self.manager.execute({'operation':'renew', 'value':None})
        self.assertEqual(result.get('certificate_result'), 'unchanged')
        self.assertEqual(self.store.current(), generation)
        self.assertIsNone(self.store.pending())
        self.assertEqual(self.backend.applied, [])

    def test_new_certificate_is_pending_until_traffic_confirmation(self):
        value, generation = self.certificate_state()
        new = value['tls'] | {'fullchain.pem':base64.b64encode(b'-----BEGIN CERTIFICATE-----new').decode()}
        self.backend.certificate = lambda *a: new
        result = self.manager.execute({'operation':'renew', 'value':None})
        self.assertEqual(result.get('certificate_result'), 'renewed')
        self.assertTrue(result.get('pending'))
        self.assertEqual(result['pending']['before'], generation)

    def test_ca_failure_keeps_current_generation(self):
        _, generation = self.certificate_state()
        def failed(*a): raise RuntimeError('synthetic CA failure')
        self.backend.certificate = failed
        with self.assertRaises(RuntimeError): self.manager.execute({'operation':'renew', 'value':None})
        self.assertEqual(self.store.current(), generation)
        self.assertIsNone(self.store.pending())

    def test_forced_issuance_uses_explicit_force_flag(self):
        value, _ = self.certificate_state()
        calls=[]
        def issue(*args, **kwargs):
            calls.append(kwargs)
            return value['tls']
        self.backend.certificate=issue
        result=self.manager.execute({'operation':'renew_force','value':None})
        self.assertEqual(calls,[{'force':True}])
        self.assertEqual(result['certificate_result'],'unchanged')

    def test_active_tls_cannot_be_deleted(self):
        _, generation=self.certificate_state()
        with self.assertRaises(ValueError):self.manager.execute({'operation':'certificate_delete','value':None})
        self.assertEqual(self.store.current(),generation)
        self.assertIsNone(self.store.pending())

    def test_delete_inactive_certificate_keeps_recoverable_previous_state(self):
        value, _=self.certificate_state()
        value['options']['transport']='reality'
        first=self.store.create(value);self.store.activate(first)
        self.backend.delete_certificate=lambda:None
        result=self.manager.execute({'operation':'certificate_delete','value':None})
        self.assertEqual(result['certificate_result'],'deleted')
        self.assertEqual(self.store.load()['tls'],{})
        self.assertEqual(self.store.load(result['pending']['before'])['tls'],value['tls'])

    def test_timer_accepts_an_unchanged_certificate_without_pending_job(self):
        from unittest.mock import patch
        from node_config_test import HOST
        self.certificate_state()
        deploy=self.store.root/'deployment.json'
        deploy.write_bytes(fixtures.state.encode(HOST))
        with patch.object(fixtures.manager,'ROOT',self.store.root), patch.object(fixtures.manager,'DEPLOYMENT',deploy), \
                patch.object(fixtures.manager.sys,'argv',['node_manager.py','renew']), \
                patch.object(fixtures.manager.os,'geteuid',return_value=0), \
                patch.object(fixtures.state,'trusted'), \
                patch.object(fixtures.manager.Manager,'execute',return_value={'certificate_result':'unchanged'}):
            fixtures.manager.main()
        self.assertIsNone(self.store.pending())

if __name__ == '__main__': unittest.main()
