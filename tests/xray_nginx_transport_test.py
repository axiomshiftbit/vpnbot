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
                        if route == 'ws':
                            self.assertEqual(self.handlers(body), ['grpc_pass'] if network == 'xhttp' else ['proxy_pass'])
                    ws = modules.xray_nginx_routes(text, {'inbounds': [{'port': 443, 'streamSettings': {'network': 'ws'}}]})
                    self.assertEqual(original, re.sub(r'(?m)^[ \t]*(?:#[ \t]*)?return 404; # vpnbot-inactive-xray-route\n', '', ws))

    @staticmethod
    def handlers(body):
        # Активная строка обработчика: в закомментированной копии блока у неё
        # один «#» (его снимает uncomment()), у выключенной — два.
        lines = [l for l in body.splitlines() if re.search(r'(proxy|grpc)_pass\s+\S+xr_backend;', l) and 'location ~' not in l]
        depth = min(l.split('_pass')[0].count('#') for l in lines)
        return [re.search(r'(proxy_pass|grpc_pass)', l)[1] for l in lines if l.split('_pass')[0].count('#') == depth]

    def test_installation_before_markers_gets_both_handlers(self):
        # Установка до HTTP/2: одна строка proxy_pass без меток, в активной и в
        # закомментированной (#-domain) копии. Миграция добавляет grpc_pass и
        # grpc_set_header с тем же отступом и включает нужный обработчик.
        old = ('        location /ws {\n            proxy_pass http://xr_backend;\n            proxy_set_header Host $host;\n        }\n'
               '    #     location /ws {\n    #         proxy_pass http://xr_backend;\n    #     }\n')
        xhttp = {'inbounds': [{'port': 443, 'streamSettings': {'network': 'xhttp'}}]}
        text = self.render(old, xhttp)
        self.assertEqual(text,
            '        location /ws {\n'
            '            # proxy_pass http://xr_backend; # vpnbot-xray-h1\n'
            '            grpc_pass grpc://xr_backend; # vpnbot-xhttp-h2\n'
            '            grpc_set_header Host $host;\n'
            '            grpc_set_header X-Real-IP $remote_addr;\n'
            '            grpc_set_header X-Forwarded-For $remote_addr;\n'
            '            grpc_socket_keepalive on;\n'
            '            grpc_read_timeout 5d;\n'
            '            grpc_send_timeout 5d;\n'
            '            client_body_timeout 5d;\n'
            '            location ~ ^/[^/]+/[^/]+/[^/]+ { grpc_pass grpc://xr_backend; client_body_timeout 60s; } # vpnbot-xhttp-packet-timeout\n'
            '            proxy_set_header Host $host;\n'
            '        }\n'
            '    #     location /ws {\n'
            '    #         # proxy_pass http://xr_backend; # vpnbot-xray-h1\n'
            '    #         grpc_pass grpc://xr_backend; # vpnbot-xhttp-h2\n'
            '    #         grpc_set_header Host $host;\n'
            '    #         grpc_set_header X-Real-IP $remote_addr;\n'
            '    #         grpc_set_header X-Forwarded-For $remote_addr;\n'
            '    #         grpc_socket_keepalive on;\n'
            '    #         grpc_read_timeout 5d;\n'
            '    #         grpc_send_timeout 5d;\n'
            '    #         client_body_timeout 5d;\n'
            '    #         location ~ ^/[^/]+/[^/]+/[^/]+ { grpc_pass grpc://xr_backend; client_body_timeout 60s; } # vpnbot-xhttp-packet-timeout\n'
            '    #     }\n')
        # Обратно на WebSocket: grpc_pass выключен, строки остаются на месте.
        back = self.render(text, {'inbounds': [{'port': 443, 'streamSettings': {'network': 'ws'}}]})
        self.assertEqual(back, text.replace('# proxy_pass', 'proxy_pass').replace('            grpc_pass', '            # grpc_pass')
                         .replace('    #         grpc_pass', '    #         # grpc_pass')
                         .replace('            location ~', '            # location ~').replace('    #         location ~', '    #         # location ~'))
        # Без своего inbound: 404, обработчик — WebSocket (как в шаблоне).
        off = self.render(text, {})
        self.assertIn('return 404;', off)
        self.assertEqual(self.handlers(off.split('    #     location')[0]), ['proxy_pass'])

    def test_template_handler_lines_match_migration(self):
        # Шаблон и миграция задают одни и те же строки; бот берёт их из одного
        # списка с холодной миграцией.
        bot = subprocess.run(['php', '-r', 'require "app/bot.php"; echo json_encode(Bot::NGINX_XHTTP_LINES);'],
                             cwd=ROOT, text=True, capture_output=True, check=True).stdout
        self.assertEqual(list(modules.NGINX_XHTTP_LINES), json.loads(bot))
        for filename in ('nginx.conf', 'nginx_default.conf'):
            text = (ROOT / 'config' / filename).read_text()
            # Активная копия и закомментированная (#-domain) — подряд, как
            # их вставляет миграция; WebSocket включён.
            for prefix in ('            ', '    #         '):
                self.assertIn('\n'.join(prefix + line for line in modules.NGINX_XHTTP_LINES), text, (filename, prefix))

    def test_wrong_port_tls_and_loopback_do_not_enable_route(self):
        text = 'location /grpcabcdef01 {\n    grpc_pass grpc://xr:443;\n}\n'
        for extra, stream in [({'port': 8443}, {}), ({'listen': '127.0.0.1'}, {}), ({'listen': '::1'}, {}), ({}, {'security': 'tls'})]:
            config = {'inbounds': [{'port': 443, **extra, 'streamSettings': {'network': 'grpc', **stream}}]}
            self.assertIn('return 404;', self.render(text, config))
        self.assertIn('return 404;', self.render(text, {}))
        config = {'inbounds': [{'tag': 'api', 'port': 8080}, {'port': 443, 'streamSettings': {'network': 'grpc'}}]}
        self.assertNotIn('return 404;', self.render(text, config))

    def test_packet_body_timeout_is_bounded_after_both_migrations(self):
        old = 'location /wsabcdef01 {\n    proxy_pass http://xr_backend;\n}\n'
        marked = ('location /wsabcdef01 {\n    # proxy_pass http://xr_backend; # vpnbot-xray-h1\n'
                  '    grpc_pass grpc://xr_backend; # vpnbot-xhttp-h2\n    client_body_timeout 5d;\n}\n')
        packet = 'location ~ ^/[^/]+/[^/]+/[^/]+ { grpc_pass grpc://xr_backend; client_body_timeout 60s; } # vpnbot-xhttp-packet-timeout'
        for original in (old, marked):
            for prefix in ('', '# '):
                text = ''.join(prefix + line for line in original.splitlines(keepends=True))
                for network in ('xhttp', 'ws', 'grpc', 'xhttp'):
                    text = self.render(text, {'inbounds': [{'port': 443, 'streamSettings': {'network': network}}]})
                    line = next((line for line in text.splitlines() if 'vpnbot-xhttp-packet-timeout' in line), '')
                    self.assertTrue(line, 'Незавершённый packet-up POST должен иметь прежний тайм-аут 60 с')
                    self.assertEqual(prefix + '    ' + ('' if network == 'xhttp' else '# ') + packet, line)
                    self.assertIn('client_body_timeout 5d;', text)

    def test_custom_backends_and_other_locations_are_preserved(self):
        text = ('location /grpc-custom {\n    grpc_pass grpc://custom:443;\n}\n'
                'location /ws-custom {\n    proxy_pass http://custom;\n}\n'
                'location /other {\n    grpc_pass grpc://xr:443;\n}\n')
        self.assertEqual(text, self.render(text, {}))


if __name__ == '__main__':
    unittest.main()
