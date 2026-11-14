import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('origin', ROOT / 'scripts/container_origin_guard.py')
origin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(origin)


class OriginTest(unittest.TestCase):
    def endpoint(self, **overrides):
        return dict(host='veth42', index=42, bridge='br-vpnbot0', mac='02:00:00:00:00:07',
                    ipv4=['10.10.0.7'], ipv6=[], routed=[]) | overrides

    def test_unknown_endpoints_always_drop(self):
        rules = origin.render(origin.BRIDGES, [])
        self.assertIn('priority -450', rules)
        self.assertIn('chain dispatch {\n  jump denied', rules)
        self.assertIn('counter drop', rules)
        self.assertNotIn('ct state established', rules)

    def test_identity_is_bound_to_bridge_ifindex_name_and_mac(self):
        rules = origin.render(origin.BRIDGES, [self.endpoint()])
        self.assertIn('meta ibrname "br-vpnbot0" meta iif 42 iifname "veth42" jump endpoint0', rules)
        self.assertIn('ether saddr != 02:00:00:00:00:07 jump denied', rules)
        self.assertIn('arp saddr ether != 02:00:00:00:00:07 jump denied', rules)

    def test_bad_metadata_cannot_inject_nft(self):
        for value in ('x"; accept', '', 'x'*16, '*', 'br-\nfoo'):
            with self.subTest(value=value), self.assertRaises(origin.Refuse):
                origin.render([value], [])
        for kwargs in ({'mac':'ff:ff:ff:ff:ff:ff'}, {'mac':'00:00:00:00:00:00;accept'}, {'index':0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(origin.Refuse):
                origin.render(origin.BRIDGES, [self.endpoint(**kwargs)])

    def test_duplicate_port_refused(self):
        with self.assertRaises(origin.Refuse):
            origin.render(origin.BRIDGES, [self.endpoint(), self.endpoint(ipv4=['10.10.0.8'])])

    def test_ipv6_linklocal_is_derived_from_expected_mac(self):
        self.assertEqual('fe80::ff:fe00:7', origin.mac_linklocal('02:00:00:00:00:07'))
        text = origin.render(origin.BRIDGES, [self.endpoint(ipv6=['fd42:7662:6::7'])])
        self.assertIn('fd42:7662:6::7', text)
        self.assertIn('fe80::ff:fe00:7', text)
        self.assertIn('nd-neighbor-advert jump denied', text)
        self.assertIn('nd-router-advert, nd-redirect', text)

    def test_boot_baseline_has_no_endpoint_permissions(self):
        text = origin.baseline(origin.BRIDGES)
        self.assertNotIn('jump endpoint', text)
        self.assertIn('/run/vpnbot-origin/active*.nft', text)

    def test_routed_clients_are_not_unconditionally_trusted(self):
        text = origin.render(origin.BRIDGES, [self.endpoint(routed=['10.0.1.0/24'])])
        self.assertIn('ip saddr { 10.10.0.7, 10.0.1.0/24 } accept', text)
        self.assertNotIn('0.0.0.0/0', text)

    def test_client_environment_projection_does_not_dump_secrets(self):
        with patch.object(origin, 'run', return_value='10.0.1.1/24\n') as call:
            self.assertEqual(['10.0.1.0/24'], origin.client_networks({'service':'wg','id':'a'*64}))
        self.assertNotIn('{{json .Config.Env}}', call.call_args.args[0])
        self.assertIn('ADDRESS', ' '.join(call.call_args.args[0]))
        for net in ('0.0.0.0/0', '10.0.0.0/8', '203.0.113.0/24', 'fd00::/64'):
            with patch.object(origin, 'run', return_value=net), self.assertRaises(origin.Refuse):
                origin.client_networks({'service':'wg','id':'a'*64})

    def test_restarting_peer_does_not_starve_a_healthy_endpoint(self):
        good={'id':'good','root':'/root/bot','service':'php','privileged':False,
              'running':True,'pid':100,'sandbox':'/var/run/docker/netns/a','project':'bot',
              'networks':{'bot_default':{'MacAddress':'02:00:00:00:00:07',
                          'IPAddress':'10.10.0.7','GlobalIPv6Address':''}}}
        bad=good|{'id':'bad','service':'ng','pid':0,'sandbox':''}
        outputs=[json.dumps([{'ifindex':42,'ifname':'veth42','master':'br-vpnbot0'}]),
                 json.dumps([{'link_index':42}]),
                 json.dumps({'id':'b'*64,'driver':'bridge','project':'bot','role':'default',
                             'options':{'com.docker.network.bridge.name':'br-vpnbot0'},
                             'ipam':[{'Subnet':'10.10.0.0/24'}]})]
        for changed in (False,True):
            after=([good|{'pid':101}] if changed else [good])+[bad]
            with patch.object(origin,'containers',side_effect=[[good,bad],after]),patch.object(origin,'client_networks',return_value=[]),patch.object(origin,'run',side_effect=outputs):
                _,endpoints=origin.inventory({'bot_dir':'/root/bot','bridges':list(origin.BRIDGES)})
                self.assertEqual(0 if changed else 1,len(endpoints))
                if endpoints:self.assertEqual(42,endpoints[0]['index'])

    def test_restarting_peer_is_not_pending_but_unverified_endpoints_are(self):
        # Неработающий контейнер придёт событием start; работающий, но не
        # подтверждённый endpoint требует быстрого повтора (RETRY).
        good={'id':'good','root':'/root/bot','service':'php','privileged':False,
              'running':True,'pid':100,'sandbox':'/var/run/docker/netns/a','project':'bot',
              'networks':{'bot_default':{'MacAddress':'02:00:00:00:00:07',
                          'IPAddress':'10.10.0.7','GlobalIPv6Address':''}}}
        net=json.dumps({'id':'b'*64,'driver':'bridge','project':'bot','role':'default',
                        'options':{'com.docker.network.bridge.name':'br-vpnbot0'},'ipam':[{'Subnet':'10.10.0.0/24'}]})
        host=json.dumps([{'ifindex':42,'ifname':'veth42','master':'br-vpnbot0'}])
        cases={'healthy':([good],[good],[host,json.dumps([{'link_index':42}]),net],0,1),
               'restarting':([good|{'pid':0,'sandbox':''}],None,[host],0,0),
               'nsenter failed':([good],[good],[host,origin.Refuse('x')],1,0),
               'veth not on bridge':([good],[good],[host,json.dumps([{'link_index':7}]),net],1,0),
               'no MAC yet':([good|{'networks':{'bot_default':{'MacAddress':'','IPAddress':'10.10.0.7','GlobalIPv6Address':''}}}],
                             None,[host,json.dumps([{'link_index':42}]),net],1,0),
               'identity changed':([good],[good|{'pid':101}],[host,json.dumps([{'link_index':42}]),net],1,0)}
        for name,(first,after,outputs,pending_count,endpoint_count) in cases.items():
            with self.subTest(name),patch.object(origin,'containers',side_effect=[first,after or first]),\
                    patch.object(origin,'client_networks',return_value=[]),patch.object(origin,'run',side_effect=outputs):
                pending=[]
                _,endpoints=origin.inventory({'bot_dir':'/root/bot','bridges':list(origin.BRIDGES)},pending)
                self.assertEqual(pending_count,len(pending))
                self.assertEqual(endpoint_count,len(endpoints))

    def test_events_ignore_healthcheck_exec(self):
        args=origin.EVENTS
        filters={args[i+1] for i,x in enumerate(args) if x=='--filter'}
        self.assertEqual({'type=container','type=network'},{f for f in filters if f.startswith('type=')})
        events={f[6:] for f in filters if f.startswith('event=')}
        self.assertTrue({'start','restart','die','stop','destroy','connect','disconnect'}<=events)
        self.assertFalse({e for e in events if e.startswith(('exec','health'))})


class WatchLoopTest(unittest.TestCase):
    """watch() на поддельных часах: когда идёт полная сверка, а когда — одна nft."""

    class Stop(BaseException):
        pass

    def run_watch(self, script, applied=lambda: True, sync_result=lambda n: False, until=200):
        clock=[1000.0]; log=[]; procs=[]
        test=self
        class Proc:
            def __init__(self,*a,**k):
                self.r,self.w=os.pipe();self.stdout=os.fdopen(self.r,'rb');self.dead=False;procs.append(self)
            def poll(self):return 1 if self.dead else None
            def terminate(self):pass
            def wait(self,timeout=None):os.close(self.w);self.stdout.close();return 0
        class Selector:
            def register(self,*a):pass
            def unregister(self,*a):pass
            def close(self):pass
            def select(self,timeout):
                for at,kind in list(script):
                    if at<=clock[0]+timeout:
                        script.remove((at,kind));clock[0]=max(clock[0],at)
                        if kind=='event':return [1]
                        if kind=='die':procs[-1].dead=True;return []
                        if kind=='drop':state['applied']=False;continue
                clock[0]+=timeout
                if clock[0]-1000>until:raise test.Stop
                return []
        state={'applied':True}
        def fake_applied(*a):
            log.append(('check',clock[0]-1000));return state['applied'] and applied()
        def fake_sync(cfg,report=None):
            log.append(('sync',clock[0]-1000));state['applied']=True
            n=len([x for x in log if x[0]=='sync'])
            outcome=sync_result(n)
            if outcome=='error':raise origin.Refuse('boom')
            report.update(pending=bool(outcome),check=('t',[],[]));return 1
        with patch.object(origin.subprocess,'Popen',Proc),patch.object(origin.selectors,'DefaultSelector',Selector),\
                patch.object(origin.time,'monotonic',lambda:clock[0]),patch.object(origin.time,'sleep',lambda s:clock.__setitem__(0,clock[0]+s)),\
                patch.object(origin.os,'read',lambda fd,n:b'container start\n'),patch.object(origin.os,'set_blocking',lambda *a:None),\
                patch.object(origin,'load',return_value={}),patch.object(origin,'sync',fake_sync),\
                patch.object(origin,'applied',fake_applied),patch.object(origin.hashlib,'sha256',lambda b:origin.hashlib.md5(b)),\
                patch.object(origin,'RUNTIME',Path(os.devnull).parent),patch('builtins.print'):
            with patch.object(Path,'read_bytes',lambda self:b''),self.assertRaises(self.Stop):
                origin.watch()
        return [round(t,2) for k,t in log if k=='sync'],[t for k,t in log if k=='check'],len(procs)

    def test_idle_full_sync_every_minute_cheap_check_every_two_seconds(self):
        syncs,checks,_=self.run_watch([],until=125)
        self.assertEqual([0,60,120],[int(x) for x in syncs])
        self.assertGreaterEqual(len(checks),55)
        ticks=sorted(checks+syncs)  # В момент полной сверки отдельная проверка не нужна.
        self.assertTrue(all(b-a<=origin.RETRY+0.01 for a,b in zip(ticks,ticks[1:])))

    def test_relevant_event_triggers_immediate_sync(self):
        syncs,_,_=self.run_watch([(1010.5,'event')],until=30)
        self.assertEqual(2,len(syncs));self.assertAlmostEqual(10.55,syncs[1],places=2)

    def test_removed_or_replaced_table_is_restored_within_retry(self):
        syncs,_,_=self.run_watch([(1007.0,'drop')],until=30)
        self.assertEqual(2,len(syncs));self.assertLessEqual(syncs[1]-7,origin.RETRY+0.01)

    def test_unverified_endpoint_is_retried_quickly(self):
        syncs,_,_=self.run_watch([],sync_result=lambda n:n<=3,until=20)
        self.assertEqual([0,2,4],[int(x) for x in syncs[:3]])
        self.assertEqual(4,len(syncs))  # После подтверждения — снова раз в FULL_SYNC.

    def test_error_retries_full_sync_not_cheap_check(self):
        syncs,_,_=self.run_watch([],sync_result=lambda n:'error' if n==1 else False,until=20)
        self.assertEqual(2,len(syncs));self.assertLessEqual(syncs[1],origin.RETRY+0.31)

    def test_restarted_event_stream_forces_full_sync(self):
        syncs,_,procs=self.run_watch([(1015.0,'die')],until=30)
        self.assertEqual(2,procs);self.assertEqual(2,len(syncs));self.assertLessEqual(syncs[1]-15,origin.RETRY+0.01)


if __name__ == '__main__':
    unittest.main()
