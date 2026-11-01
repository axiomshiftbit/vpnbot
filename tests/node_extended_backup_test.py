import base64
import copy
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import node_state, node_awg, node_config
from node_state_test import VALUE

class ExtendedBackup(unittest.TestCase):
    def test_restore_preserves_aliases_xhttp_and_custom_amnezia(self):
        value=copy.deepcopy(VALUE)
        value['options'].update(domain='node.example.test',domain_aliases=['alt.example.test'],
            xray={'xhttp':{'extra':{'xmux':{'maxConcurrency':'8-16'}}}},
            amnezia={'enabled':True,'active':False,'mtu':1280,'keepalive':'18-24','template':'mobile_3',
                     'rotation_days':7,'generated_at':1700000000,'parameters':{'Jc':5,'I1':'<r 32>'}})
        value['identity']['amnezia']=node_awg.generate(lambda:{k:base64.urlsafe_b64encode(b'a'*32).decode().rstrip('=') for k in ['private','public']})
        original=node_state.snapshot(value)
        with tempfile.TemporaryDirectory() as tmp:
            first=node_state.Store(Path(tmp)/'first');g=first.create(original);first.activate(g)
            restored=node_state.Store(Path(tmp)/'restored');g=restored.create(node_state.decode(node_state.encode(first.load())));restored.activate(g)
            self.assertEqual(restored.load(),original)
            options=restored.load()['options'];keys=restored.load()['identity']['amnezia']
            profile=node_awg.profile(options['amnezia'],'1.1.1.1',keys)
            self.assertEqual(profile['parameters']['Jc'],5)
            self.assertIn('I1 = <r 32>',node_awg.client(profile,0))
            self.assertEqual(options['domain_aliases'],['alt.example.test'])

if __name__=='__main__': unittest.main()
