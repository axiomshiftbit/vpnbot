import base64
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import node_wg, node_awg, node_xray, node_runtime
from node_config_test import OPTIONS, KEYS, HOST

class ProtocolControls(unittest.TestCase):
    def test_wireguard_keepalive_is_configurable_and_bounded(self):
        key=base64.b64encode(b'a'*32).decode()
        keys={k:key for k in ['server_private','server_public','client_private','client_public','psk']}
        out=node_wg.outbound({'keepalive':17},'1.1.1.1',keys)
        self.assertEqual(out['settings']['peers'][0]['keepAlive'],17)
        for v in [-1,65536,True,'25\nPostUp=id']:
            with self.assertRaises(ValueError): node_wg.settings({'keepalive':v})

    def test_amnezia_overrides_reach_both_ends_without_disabling_defenses(self):
        keys=node_awg.generate(lambda:{k:base64.urlsafe_b64encode(b'a'*32).decode().rstrip('=') for k in ['private','public']})
        opts={'enabled':True,'keepalive':'18-24','parameters':{'Jc':5,'Jmin':70,'Jmax':900,'H1':'1','I1':'<b 0xaabb><r 16>'}}
        profile=node_awg.profile(opts,'1.1.1.1',keys)
        server=node_awg.server(opts,keys); client=node_awg.client(profile,0)
        for text in [server,client]:
            self.assertIn('I1 = <b 0xaabb><r 16>\n',text); self.assertIn('Jc = 5\n',text); self.assertIn('H1 = 1-1\n',text)
            self.assertIn('DisableCookies = off\n',text)
        self.assertIn('PersistentKeepalive = 18-24\n',client)
        for params in [{'HeaderProtectionKey':'bad'},{'PostUp':'id'},{'Jc':99},{'I1':'<r 1001>'},{'I1':'<b 0x123>'},{'I1':'<t><t>'},{'H1':'1-2\nPostUp=id'}]:
            with self.assertRaises(ValueError): node_awg.settings({'parameters':params})

    def test_disabled_crypto_rotation_cannot_report_success(self):
        rt=node_runtime.Runtime(None,HOST)
        value={'options':OPTIONS,'identity':copy.deepcopy(KEYS),'images':{}}
        for target in ['encryption','mldsa','wireguard','amnezia']:
            with self.subTest(target=target), self.assertRaises(ValueError): rt.ensure_keys(value,rotate=target)

    def test_xhttp_extra_matches_client_uri_and_is_closed_schema(self):
        opts=copy.deepcopy(OPTIONS)|{'transport':'xhttp','xray':{'xhttp':{'extra':{'xmux':{'maxConcurrency':'8-16'},'noGRPCHeader':True}}}}
        params=node_xray.link_parameters(opts,KEYS)
        import json
        self.assertEqual(json.loads(params['extra'])['xmux']['maxConcurrency'],'8-16')
        for extra in [{'downloadSettings':{}},{'xmux':{'maxConcurrency':'8-16','maxConnections':2}},{'xPaddingBytes':'1\nBad'}]:
            with self.assertRaises(ValueError): node_xray.settings({'xhttp':{'extra':extra}},'origin','xhttp')

if __name__=='__main__': unittest.main()
