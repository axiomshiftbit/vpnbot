#!/usr/bin/env python3
import base64
import copy
import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import node_config, node_wg, node_awg
from node_config_test import OPTIONS, HOST, KEYS


class ExternalChannels(unittest.TestCase):
    def setUp(self):
        def pair():
            key=base64.urlsafe_b64encode(b'a'*32).decode().rstrip('=')
            return {'private':key,'public':key}
        self.keys=KEYS | {'wireguard':node_wg.generate(pair), 'amnezia':node_awg.generate(pair)}
        self.peer={'id':'22222222-2222-4222-8222-222222222222','name':'panel','enabled':True,'channel':'wireguard'}
        self.entry={'slot':1,'channel':'wireguard','private':base64.b64encode(b'b'*32).decode(),
                    'public':base64.b64encode(b'c'*32).decode(),'psk':base64.b64encode(b'd'*32).decode()}
        self.keys['external']={self.peer['id']:self.entry}
        self.options=OPTIONS | {'wireguard':{'enabled':True},'amnezia':{'enabled':True}}

    def test_external_wireguard_has_independent_key_and_narrow_source(self):
        profile=node_config.export_profile(self.options,HOST,self.keys,self.peer)
        self.assertEqual(profile['channel'],'wireguard')
        settings=profile['outbound']['settings']
        self.assertEqual(settings['secretKey'],self.entry['private'])
        self.assertNotEqual(settings['secretKey'],self.keys['wireguard']['client_private'])
        self.assertEqual(settings['address'],['fd42:7662:77::3/128'])
        cfg=node_config.core_config(self.options,HOST,self.keys,[self.peer])
        wg=next(i for i in cfg['inbounds'] if i['protocol']=='wireguard')
        self.assertNotIn(self.peer['id'],[x['id'] for x in cfg['inbounds'][0]['settings']['clients']])
        peers=wg['settings']['peers']
        self.assertEqual(len(peers),2)
        self.assertEqual(peers[1]['allowedIPs'],['10.77.77.3/32','fd42:7662:77::3/128'])
        disabled=self.peer | {'enabled':False}
        cfg=node_config.core_config(self.options,HOST,self.keys,[disabled])
        self.assertEqual(len(next(i for i in cfg['inbounds'] if i['protocol']=='wireguard')['settings']['peers']),1)
        with self.assertRaises(ValueError):node_config.export_profile(self.options,HOST,self.keys,disabled)

    def test_slots_and_types_cannot_spoof_controller_or_other_peer(self):
        for slot in (0,33,True,'1'):
            with self.subTest(slot=slot),self.assertRaises(ValueError):
                node_wg.external({self.peer['id']:self.entry | {'slot':slot}})
        duplicate={self.peer['id']:self.entry,'33333333-3333-4333-8333-333333333333':self.entry}
        with self.assertRaises(ValueError):node_wg.external(duplicate)
        for channel in ('shell','../wireguard',True):
            with self.assertRaises(ValueError):node_config.peers([self.peer | {'channel':channel}])

    def test_external_awg_keeps_vless_target_and_separate_client(self):
        self.peer['channel']='amnezia'; self.entry['channel']='amnezia'
        profile=node_config.export_profile(self.options,HOST,self.keys,self.peer)
        self.assertEqual(profile['channel'],'amnezia')
        self.assertEqual(profile['amnezia']['slot'],1)
        self.assertEqual(profile['amnezia']['private'],self.entry['private'])
        server=node_awg.server(self.options['amnezia'],self.keys['amnezia'],[self.entry])
        self.assertIn('AllowedIPs = 10.77.78.3/32\n',server)
        self.assertEqual(server.count('[Peer]'),2)
        self.assertEqual(server.count('Target = 127.0.0.1:8443'),1)
        self.assertIn('Address = 10.77.78.3/32',node_awg.client(profile['amnezia'],0))
        self.assertNotIn('server_private',profile['amnezia'])

    def test_backup_restore_keeps_keys_and_rejects_incomplete_external_identity(self):
        import node_state
        from node_state_test import VALUE
        value=copy.deepcopy(VALUE) | {'options':self.options,'identity':self.keys,'peers':[self.peer]}
        restored=node_state.snapshot(node_state.decode(node_state.encode(value)))
        self.assertEqual(restored['identity'],self.keys)
        self.assertEqual(node_config.export_profile(restored['options'],HOST,restored['identity'],self.peer),
                         node_config.export_profile(self.options,HOST,self.keys,self.peer))
        invalid=copy.deepcopy(value);invalid['identity'].pop('external')
        with self.assertRaises(ValueError):node_state.snapshot(invalid)
        invalid=copy.deepcopy(value);invalid['identity']['external'][self.peer['id']]['channel']='amnezia'
        with self.assertRaises(ValueError):node_state.snapshot(invalid)

    def test_key_reconciliation_preserves_existing_and_revokes_removed(self):
        from node_runtime import Runtime
        from unittest.mock import patch
        value={'identity':copy.deepcopy(self.keys),'options':self.options,'images':{'xr':'fixture'},'peers':[self.peer]}
        runtime=Runtime(None,HOST)
        with patch.object(runtime,'identity',side_effect=AssertionError('existing keys regenerated')):
            runtime.ensure_external_keys(value)
        self.assertEqual(value['identity']['external'][self.peer['id']],self.entry)
        value['peers']=[];runtime.ensure_external_keys(value)
        self.assertNotIn('external',value['identity'])
        self.assertEqual(value['identity']['wireguard'],self.keys['wireguard'])


if __name__=='__main__':unittest.main()
