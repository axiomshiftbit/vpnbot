"""IPv6 opt-in не меняет старые установки и не принимает опасные настройки."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'


def module(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


ipv6 = module('ipv6_egress')
bundle = module('image_bundle')


class Ipv6EgressTests(unittest.TestCase):
    def test_public_and_interface_validation(self):
        value = {'enabled': True, 'public': '2001:4860::1', 'interface': 'ens3'}
        self.assertEqual(ipv6.validate(value), value)
        for address in ('127.0.0.1', '::', '::1', 'fd42::1', 'fe80::1', 'ff02::1', '::ffff:8.8.8.8', '64:ff9b::808:808', '2001:db8::1', '2001:4860::1%eth0', int('20014860000000000000000000000001', 16), None):
            with self.subTest(address=address), self.assertRaises(ValueError):
                ipv6.validate({**value, 'public': address})
        for interface in ('', '../eth0', 'eth0;id', 'x' * 16, None):
            with self.subTest(interface=interface), self.assertRaises(ValueError):
                ipv6.validate({**value, 'interface': interface})
        for enabled in (False, 'true', 1, None):
            with self.subTest(enabled=enabled), self.assertRaises(ValueError):
                ipv6.validate({**value, 'enabled': enabled})

    def test_legacy_and_opt_in_compose(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(bundle.compose_files(root, {}), [])
            (root / 'config').mkdir()
            marker = root / 'config/ipv6-egress.json'
            marker.write_text(json.dumps({'enabled': True, 'public': '2001:4860::1', 'interface': 'eth0'}))
            (root / 'docker-compose.override.yml').write_text('{}')
            self.assertEqual(bundle.compose_files(root, {}), ['-f', 'docker-compose.yml', '-f', 'docker-compose.override.yml', '-f', str(root / 'docker-compose.ipv6.yml')])
            files = bundle.compose_files(root, {'COMPOSE_FILE': 'a.yml:b.yml'})
            self.assertEqual(files[:4], ['-f', 'a.yml', '-f', 'b.yml'])
            # A damaged marker keeps the network and must not stop every service.
            marker.write_text('{bad')
            self.assertEqual(bundle.compose_files(root, {})[-1], str(root / 'docker-compose.ipv6.yml'))
            marker.unlink()
            self.assertEqual(bundle.compose_files(root, {}), [])

    def test_preparation_requires_protected_default_and_matching_snat(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'config').mkdir()
            path = root / 'config/xray.json'
            direct = {'protocol': 'freedom', 'tag': 'direct', 'settings': {}}
            path.write_text(json.dumps({'outbounds': [direct]}))
            with self.assertRaises(ValueError):
                ipv6.check_xray(root)
            direct['settings'] = {'domainStrategy': 'ForceIPv4', 'finalRules': [{'action': 'block', 'ip': ['::/0']}]}
            path.write_text(json.dumps({'outbounds': [direct]}))
            ipv6.check_xray(root)
            direct['streamSettings'] = {'sockopt': {'domainStrategy': 'ForceIPv4'}}
            del direct['settings']['domainStrategy']
            path.write_text(json.dumps({'outbounds': [direct]}))
            ipv6.check_xray(root)
            for settings in ({'domainStrategy': 'AsIs'}, {'finalRules': []}):
                unsafe = {**direct, 'settings': {**direct['settings'], **settings}}
                path.write_text(json.dumps({'outbounds': [unsafe]}))
                with self.subTest(settings=settings), self.assertRaises(ValueError):
                    ipv6.check_xray(root)
        shapes = {'input': ('filter', 'input', 0, 'drop'), 'forward': ('filter', 'forward', 0, 'drop'),
                  'postrouting': ('nat', 'postrouting', 100, 'accept'), 'egress_guard': ('filter', 'postrouting', 110, 'accept')}
        objects = [{'chain': dict(zip(('name', 'type', 'hook', 'prio', 'policy'), (name, *shape)))} for name, shape in shapes.items()]
        source = {'payload': {'protocol': 'ip6', 'field': 'saddr'}}
        wan = {'match': {'op': '==', 'left': {'meta': {'key': 'oifname'}}, 'right': 'eth0'}}
        objects.extend([
            {'rule': {'chain': 'postrouting', 'expr': [wan,
                {'match': {'op': '==', 'left': source, 'right': ipv6.SOURCE}},
                {'snat': {'addr': {'map': {'key': source, 'data': '@egress6_snat'}}}}]}},
            {'rule': {'chain': 'egress_guard', 'expr': [wan,
                {'match': {'op': '==', 'left': source, 'right': {'prefix': {'addr': 'fc00::', 'len': 7}}}},
                {'counter': {'packets': 0, 'bytes': 0}}, {'drop': None}]}},
        ])
        # The dedicated container's path through the closed forward chain (audit 26.11.2026, C23).
        meta = lambda key, value: {'match': {'op': '==', 'left': {'meta': {'key': key}}, 'right': value}}
        daddr = {'payload': {'protocol': 'ip6', 'field': 'daddr'}}
        objects.extend([
            {'rule': {'chain': 'forward', 'expr': [meta('iifname', 'eth0'), meta('oifname', 'br-vpnbot6'),
                {'match': {'op': '==', 'left': daddr, 'right': ipv6.SOURCE}},
                {'match': {'op': 'in', 'left': {'ct': {'key': 'state'}}, 'right': 'established'}}, {'accept': None}]}},
            {'rule': {'chain': 'forward', 'expr': [meta('iifname', 'br-vpnbot6'), meta('oifname', 'eth0'),
                {'match': {'op': '==', 'left': source, 'right': ipv6.SOURCE}}, {'counter': None}, {'accept': None}]}},
        ])
        mapping = {'map': {'name': 'egress6_snat', 'elem': [[ipv6.SOURCE, '2001:4860::1']]}}
        objects.append(mapping)
        with patch.object(ipv6.subprocess, 'run', return_value=SimpleNamespace(stdout=json.dumps({'nftables': objects}))):
            ipv6.check_firewall('2001:4860::1', 'eth0')
            with self.assertRaises(ValueError):
                ipv6.check_firewall('2001:4860::2', 'eth0')
        with patch.object(ipv6.subprocess, 'run', return_value=SimpleNamespace(stdout=json.dumps({'nftables': objects}))):
            with self.assertRaises(ValueError):
                ipv6.check_firewall('2001:4860::1', 'ens3')
        for name in ('postrouting', 'egress_guard'):
            missing = [item for item in objects if item.get('rule', {}).get('chain') != name]
            with patch.object(ipv6.subprocess, 'run', return_value=SimpleNamespace(stdout=json.dumps({'nftables': missing}))):
                with self.assertRaises(ValueError):
                    ipv6.check_firewall('2001:4860::1', 'eth0')
        objects[0]['chain']['policy'] = 'accept'
        with patch.object(ipv6.subprocess, 'run', return_value=SimpleNamespace(stdout=json.dumps({'nftables': objects}))):
            with self.assertRaises(ValueError):
                ipv6.check_firewall('2001:4860::1', 'eth0')


if __name__ == '__main__':
    unittest.main()
