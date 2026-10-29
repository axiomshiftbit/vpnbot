import importlib.util
import ipaddress
import json
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


if __name__ == '__main__':
    unittest.main()
