"""Control-plane settings and data-plane identities must stay independent."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from node_config_test import HOST, node
import node_adguard as ad

LINKS = {name: {'gateway': f'172.29.{n}.1', 'service': f'172.29.{n}.2'}
         for n, name in enumerate(('node', 'warp'), 20)}


class NodeAdguard(unittest.TestCase):
    def test_isolated_panel_helper_handles_managed_settings(self):
        request = {'method': 'PUT', 'path': '/control/querylog/config/update',
                   'type': 'application/json', 'body': ''}
        with tempfile.TemporaryDirectory() as cwd:
            helper = subprocess.run([sys.executable, '-I', ad.__file__, 'panel'],
                                    input=json.dumps(['fixture', request]), capture_output=True,
                                    text=True, cwd=cwd, timeout=5)
        self.assertEqual(helper.returncode, 0)
        self.assertEqual(json.loads(helper.stdout)['status'], 409)

    def test_existing_bridge_requires_both_isolation_options(self):
        def describe(args):
            if 'ls' in args:
                return SimpleNamespace(stdout='\n'.join(ad.CONTAINER+'-'+m for m in ad.BRIDGES).encode())
            mode = args[-1].removeprefix(ad.CONTAINER+'-')
            options = {'com.docker.network.bridge.name':ad.BRIDGES[mode],
                       'com.docker.network.bridge.enable_icc':'false',
                       'com.docker.network.bridge.enable_ip_masquerade':'false'}
            options.pop(missing)
            net = {'Driver':'bridge','Internal':True,'EnableIPv6':False,'Labels':{ad.LABEL:mode},'Options':options,
                   'IPAM':{'Config':[{'Subnet':'172.28.0.0/24','Gateway':'172.28.0.1'}]}}
            return SimpleNamespace(stdout=json.dumps([net]).encode())
        for missing in ('com.docker.network.bridge.enable_icc','com.docker.network.bridge.enable_ip_masquerade'):
            with self.subTest(option=missing), self.assertRaises(ValueError):
                ad.networks(describe)

    def test_activation_rejects_a_filter_that_exited_during_startup(self):
        from node_runtime import Runtime
        value = {'options':{'transport':'reality','adguard':{'enabled':True}},'images':{'ad':'fixture'}}
        backend = Runtime(Mock(), HOST)
        backend.store.load.return_value = value
        with patch.object(backend, 'prepare'), patch.object(backend, 'load_firewall'), patch.object(backend, 'stop'), \
                patch.object(backend, 'docker_arguments', return_value=[]), patch('node_runtime.command'), \
                patch.object(backend, 'container', side_effect=lambda name='core': {'State':{'Running':name != ad.CONTAINER}}), \
                patch.object(ad, 'start'), patch.object(ad, 'networks', return_value=LINKS), patch('time.sleep'), \
                patch('socket.create_connection'), self.assertRaises(RuntimeError):
            backend.apply('fixture')

    def test_only_wg_inlets_use_wireguard_client_names(self):
        core = {'inbounds': [{'tag': tag} for tag in ('node', 'node-wg4', 'node-wg6')],
                'outbounds': [{'tag': 'direct'}]}
        options = {'adguard': {'controller': True, 'peers': []}, 'family': 4}
        ad.route(core, {'options': options, 'peers': [], 'identity': {}}, LINKS)
        grants = [r for r in core['routing']['rules'] if 'controller-wg' in r.get('user', [])]
        self.assertEqual({tag for r in grants for tag in r['inboundTag']}, {'node-wg4', 'node-wg6'})

    def test_existing_filter_requires_its_original_credential(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root/'adguard/conf'
            directory.mkdir(parents=True)
            (directory/'AdGuardHome.yaml').write_text('{}')
            with patch('os.chown'), self.assertRaises(ValueError):
                ad.prepare(root, LINKS)
            self.assertFalse((root/'adguard/credential').exists())

    def test_panel_preserves_managed_settings_and_allows_filtering(self):
        with patch('http.client.HTTPConnection') as http:
            reply = http.return_value.getresponse.return_value
            reply.read.return_value = b'{}'
            reply.getheader.return_value = 'application/json'
            reply.status = 200
            for path, method, payload, allowed in [
                ('status', 'GET', {}, True), ('version.json', 'POST', {}, True), ('filtering/set_rules', 'POST', {'rules':['||ads.example.test^']}, True),
                ('profile/update', 'PUT', {'language': 'ru', 'theme': 'dark'}, True),
                ('access/set', 'POST', {'allowed_clients':[]}, False),
                ('clients/delete', 'POST', {'name':'warp'}, False),
                ('dns_config', 'POST', {'cache_enabled':True}, False),
                ('dhcp/set_config', 'POST', {'enabled':True}, False),
                ('querylog/config/update', 'PUT', {'enabled':True,'interval':90}, False),
                ('tls/configure', 'POST', {}, False),
                ('filtering/add_url', 'POST', {'name':'ads','url':'https://filters.example.test/ads.txt'}, True),
                ('filtering/set_url', 'POST', {'url':'https://filters.example.test/ads.txt','data':{'url':'/work/list'}}, False),
            ]:
                with self.subTest(path=path):
                    http.reset_mock()
                    body = base64.b64encode(json.dumps(payload).encode()).decode() if method != 'GET' else ''
                    out = ad.panel_http('fixture', {'path':'/control/'+path,'method':method,'type':'application/json','body':body})
                    self.assertEqual((out['status'], http.called), (200,True) if allowed else (409,False))

    def test_warp_health_dns_is_independent_of_client_grants(self):
        from node_warp_test import OPTIONS4, IDENTITY, PEER, HOST
        options = OPTIONS4 | {'adguard': {'enabled': True, 'peers': [], 'controller': False}}
        profile = node.export_profile(options, HOST, IDENTITY)
        self.assertNotIn('warp_probe_uuid', node.export_profile(options, HOST, IDENTITY, PEER))
        self.assertNotEqual(profile.get('warp_probe_uuid'), profile['warp_uuid'])
        core = node.core_config(options, HOST, IDENTITY, [PEER], {'protocol': 'wireguard'})
        ad.route(core, {'options': options, 'peers': [PEER], 'identity': IDENTITY}, LINKS)
        users = {c['id']: c['email'] for c in core['inbounds'][0]['settings']['clients']}
        def udp53(identity):
            for rule in core['routing']['rules']:
                if 'node' not in rule.get('inboundTag', []) or rule.get('port', '53') != '53': continue
                if 'udp' not in rule.get('network', 'udp') or users[identity] not in rule.get('user', [users[identity]]): continue
                return rule['outboundTag']
        self.assertEqual(udp53(profile.get('warp_probe_uuid', profile['warp_uuid'])), 'warp')
        self.assertEqual(udp53(profile['warp_uuid']), 'block')
