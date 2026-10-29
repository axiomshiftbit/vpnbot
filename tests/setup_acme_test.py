import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import contextlib
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('setup', ROOT / 'scripts/setup_acme.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


def fixture(redirect=False):
    public, upstream = '203.0.113.10', '10.10.0.2'
    m, p = setup.match, setup.payload
    objects = [{'set': {'family':'ip','table':'filter','name':'acme_http_fwd',
                        'type':['ipv4_addr','inet_service'],'flags':['timeout'],'size':8}},
               {'chain':{'family':'ip','table':'filter','name':'forward','type':'filter',
                         'hook':'forward','prio':0,'policy':'drop'}},
               {'rule':{'family':'ip','table':'filter','chain':'forward','comment':'acme-window',
                        'expr':[m({'meta':{'key':'iifname'}},'net0'),m({'ct':{'key':'status'}},'dnat','in'),
                                m({'meta':{'key':'mark'}},3,'!='),m({'ct':{'key':'ip daddr','dir':'original'}},public),
                                m({'ct':{'key':'proto-dst','dir':'original'}},80),
                                m({'concat':[p('ip','daddr'),p('tcp','dport')]},'@acme_http_fwd'),{'accept':None}]}}]
    if redirect:
        objects.append({'set':{'family':'ip','table':'dockernat','name':'acme_http_redirect',
                               'type':'inet_service','flags':['timeout'],'size':8}})
    for name in ('prerouting','output'):
        objects.append({'chain':{'family':'ip','table':'dockernat','name':name,'type':'nat','hook':name,'prio':-100}})
        if redirect:
            objects.append({'rule':{'family':'ip','table':'dockernat','chain':name,'comment':'acme-window-redirect',
                                    'expr':[m(p('ip','daddr'),public),m(p('tcp','dport'),'@acme_http_redirect'),
                                            {'dnat':{'addr':'10.10.2.5','port':80}}]}})
        objects.append({'rule':{'family':'ip','table':'dockernat','chain':name,
                                'expr':[m(p('ip','daddr'),public),m(p('tcp','dport'),80),
                                        {'dnat':{'addr':upstream,'port':80}}]}})
    return {'nftables':objects}


class SetupAcmeTest(unittest.TestCase):
    def test_auto_detects_both_firewall_shapes(self):
        for redirect in (False,True):
            with self.subTest(redirect=redirect):
                result=setup.nft_shape(fixture(redirect))
                self.assertEqual('203.0.113.10',result['public_ip'])
                self.assertEqual('net0',result['wan'])
                self.assertEqual('10.10.0.2:80',result['upstream'])
                self.assertEqual('10.10.2.5' if redirect else None,result['redirect_ip'])

    def test_every_window_constraint_is_required(self):
        for index in range(7):
            doc=fixture();doc['nftables'][2]['rule']['expr'].pop(index)
            with self.subTest(index=index),self.assertRaises(setup.Refuse):setup.nft_shape(doc)
        for index,value in ((0,'other*'),(2,0),(3,'not-an-ip'),(4,443),(5,'@other')):
            doc=fixture();doc['nftables'][2]['rule']['expr'][index]['match']['right']=value
            with self.subTest(index=index),self.assertRaises(setup.Refuse):setup.nft_shape(doc)

    def test_window_must_be_closed_and_timeout_limited(self):
        for change in ({'flags':[]},{'size':0},{'size':1000000},{'elem':['open']},{'type':'inet_service'}):
            doc=fixture();doc['nftables'][0]['set'].update(change)
            with self.subTest(change=change),self.assertRaises(setup.Refuse):setup.nft_shape(doc)

    def test_ensure_can_inspect_an_active_window_but_keeps_constraints(self):
        doc=fixture();doc['nftables'][0]['set']['elem']=['active']
        self.assertEqual(setup.nft_shape(fixture()),setup.nft_shape(doc,allow_open=True))
        doc['nftables'][0]['set']['flags']=[]
        with self.assertRaises(setup.Refuse):setup.nft_shape(doc,allow_open=True)

    def test_ensure_does_not_lock_or_interrupt_current_renewal(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            state=Path(tmp)/'state'
            stack.enter_context(patch.object(setup,'STATE',state))
            stack.enter_context(patch.object(setup.sys,'argv',['setup_acme.py','ensure']))
            stack.enter_context(patch.object(setup.os,'geteuid',return_value=0))
            stack.enter_context(patch.object(setup.shutil,'which',return_value='/bin/tool'))
            stack.enter_context(patch.object(setup.signal,'signal'))
            stack.enter_context(patch.object(setup,'trusted',side_effect=lambda p,**kw:Path(p)))
            stack.enter_context(patch.object(setup,'safe_destination'))
            locks=[]
            @contextlib.contextmanager
            def lock(path,wait=0):
                locks.append(path);yield
            stack.enter_context(patch.object(setup,'lock',side_effect=lock))
            stack.enter_context(patch.object(setup,'inspect_firewall',return_value={'public_ip':'203.0.113.10'}))
            stack.enter_context(patch.object(setup,'check_bot',return_value=[]))
            stack.enter_context(patch.object(setup,'dns_check'))
            stack.enter_context(patch.object(setup,'configuration',return_value={}))
            stack.enter_context(patch.object(setup,'installed_current',return_value=True))
            installer=stack.enter_context(patch.object(setup,'install'))
            agent=stack.enter_context(patch.object(setup,'agent_module'))
            setup.main()
            installer.assert_not_called();agent.assert_not_called()
            self.assertNotIn(state/'lock',locks)

    def test_nat_consistency_and_target_port(self):
        for change in ({'addr':'10.10.0.99'},{'port':81}):
            doc=fixture();doc['nftables'][-1]['rule']['expr'][-1]['dnat'].update(change)
            with self.subTest(change=change),self.assertRaises(setup.Refuse):setup.nft_shape(doc)

    def test_duplicate_window_and_nat_refused(self):
        for index in (2,-1):
            doc=fixture();doc['nftables'].append(copy.deepcopy(doc['nftables'][index]))
            with self.subTest(index=index),self.assertRaises(setup.Refuse):setup.nft_shape(doc)

    def test_existing_configuration_and_auto_off_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'config.json'
            original={'public_ip':'203.0.113.10','bot_dir':'/root/vpnbot','targets':[
                {'name':'vpnbot','kind':'vpnbot','upstream':'10.10.0.2:80','auto':False}]}
            path.write_text(json.dumps(original));before=path.read_bytes()
            with patch.object(setup,'CONFIG',path),patch.object(setup,'trusted'):
                self.assertEqual(original,setup.configuration(Path('/root/vpnbot'),setup.nft_shape(fixture())))
                self.assertEqual(before,path.read_bytes())
                with self.assertRaises(setup.Refuse):
                    setup.configuration(Path('/root/other'),setup.nft_shape(fixture()))

    def test_check_before_letsencrypt_returns_no_domains(self):
        from subprocess import CompletedProcess
        mounts=json.dumps([{'Destination':'/acme/request','Source':'/root/vpnbot/acme/request','RW':True},
                           {'Destination':'/acme/state','Source':'/root/vpnbot/acme/state','RW':False}])
        outputs=[CompletedProcess([],0,'10.10.0.2'),CompletedProcess([],0,mounts),CompletedProcess([],3,'')]
        with patch.object(setup,'trusted'),patch.object(setup,'container',side_effect=['ng','php']),patch.object(setup,'run',side_effect=outputs):
            self.assertEqual([],setup.check_bot(Path('/root/vpnbot'),setup.nft_shape(fixture())))


if __name__=='__main__':unittest.main()
