import importlib.util
import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('nginx_protocols', ROOT / 'scripts/protocol_modules.py')
modules = importlib.util.module_from_spec(spec); spec.loader.exec_module(modules)


class XrayNginxRoutesTest(unittest.TestCase):
    def render(self, text, config):
        cold = modules.xray_nginx_routes(text, config)
        live = subprocess.run(['php', '-r',
            'require "app/bot.php"; $d=json_decode(file_get_contents("php://stdin"),true); echo Bot::xrayNginxRoutes($d[0],$d[1]);'],
            cwd=ROOT, input=json.dumps([text, config]), text=True, capture_output=True, check=True).stdout
        self.assertEqual(cold, live, 'Холодная миграция и работающий бот должны давать одинаковые маршруты')
        self.assertEqual(cold, modules.xray_nginx_routes(cold, config))
        return cold

    def test_transitions_use_actual_inbound_not_saved_menu_flag(self):
        for filename in ('nginx.conf', 'nginx_default.conf'):
            original = (ROOT / 'config' / filename).read_text()
            text = original
            for network in ('ws', 'grpc', 'ws', 'xhttp', 'grpc', 'tcp', 'ws'):
                with self.subTest(file=filename, network=network):
                    config = {'inbounds': [{'port': 443, 'streamSettings': {'network': network}}]}
                    text = self.render(text, config)
                    blocks = re.findall(r'location /(ws|grpc) \{(.*?)\n[ \t]*(?:#[ \t]*)?\}', text, re.S)
                    self.assertEqual(4, len(blocks))
                    for route, body in blocks:
                        active = network == 'grpc' if route == 'grpc' else network in ('ws', 'xhttp')
                        self.assertEqual(not active, 'return 404; # vpnbot-inactive-xray-route' in body)
                    self.assertEqual(original, re.sub(r'(?m)^[ \t]*(?:#[ \t]*)?return 404; # vpnbot-inactive-xray-route\n', '', text))

    def test_wrong_port_tls_and_loopback_do_not_enable_route(self):
        text = 'location /grpcabcdef01 {\n    grpc_pass grpc://xr:443;\n}\n'
        for extra, stream in [({'port': 8443}, {}), ({'listen': '127.0.0.1'}, {}), ({'listen': '::1'}, {}), ({}, {'security': 'tls'})]:
            config = {'inbounds': [{'port': 443, **extra, 'streamSettings': {'network': 'grpc', **stream}}]}
            self.assertIn('return 404;', self.render(text, config))
        self.assertIn('return 404;', self.render(text, {}))
        config = {'inbounds': [{'tag': 'api', 'port': 8080}, {'port': 443, 'streamSettings': {'network': 'grpc'}}]}
        self.assertNotIn('return 404;', self.render(text, config))

    def test_custom_backends_and_other_locations_are_preserved(self):
        text = ('location /grpc-custom {\n    grpc_pass grpc://custom:443;\n}\n'
                'location /ws-custom {\n    proxy_pass http://custom;\n}\n'
                'location /other {\n    grpc_pass grpc://xr:443;\n}\n')
        self.assertEqual(text, self.render(text, {}))


if __name__ == '__main__':
    unittest.main()
