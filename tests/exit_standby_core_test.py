"""Delayed exit selection against the real Xray RoutingService and local TCP/UDP backends."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import json
import os
from pathlib import Path
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from node_policy_test import free_port, request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import exit_failover

PRIMARY = 'vpnbot-exit-aaaaaaaa'
FULL = '11111111-1111-4111-8111-111111111111'
LISTED = '22222222-2222-4222-8222-222222222222'
OTHER = '33333333-3333-4333-8333-333333333333'


def local_api(core, port, args):
    args = [f'127.0.0.1:{port}' if arg == '127.0.0.1:8080' else arg for arg in args]
    return subprocess.check_output([core, 'api', *args], stderr=subprocess.DEVNULL, timeout=4)


class Backend(socketserver.BaseRequestHandler):
    def handle(self):
        if isinstance(self.request, tuple):
            data, sock = self.request
            if self.server.up:
                sock.sendto(self.server.label + data, self.client_address)
        else:
            with self.request as conn:
                data = conn.recv(2048)
                if self.server.up and data:
                    if data.startswith((b'GET ', b'HEAD ')):
                        conn.sendall(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                    else:
                        conn.sendall(self.server.label + data)


class StandbyTest(unittest.TestCase):
    def test_delay_and_recovery_decisions(self):
        for delay in (30, 60, 120, 300):
            policy = exit_failover.Policy(f'vpnbot-exit-timed-aaaaaaaa-main-{delay}-direct', PRIMARY, delay, 'direct')
            response = {'balancer': {'override': {}, 'principleTarget': {'tag': ['']}}}
            writes = []
            def call(args):
                if args[0] == 'bi':
                    return json.dumps(response)
                writes.append(args[-1])
            self.assertEqual(exit_failover.check(policy, None, 100, call), 100)
            exit_failover.check(policy, 100, 100 + delay - 1, call)
            self.assertFalse(writes)
            exit_failover.check(policy, 100, 100 + delay, call)
            response['balancer']['override']['target'] = 'direct'
            exit_failover.check(policy, 100, 101 + delay, call)
            self.assertEqual(writes, ['direct'])
            response['balancer']['principleTarget']['tag'] = [PRIMARY]
            self.assertIsNone(exit_failover.check(policy, 100, 102 + delay, call))
            self.assertEqual(writes, ['direct', '-r'])
            response['balancer']['principleTarget']['tag'] = []
            with self.assertRaises(ValueError): exit_failover.check(policy, None, 200, call)

    @unittest.skipUnless(os.environ.get('VLESS_TEST_XRAY'), 'needs Xray')
    def test_live_paths(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            cases = [(choice, mode) for mode in ('controller', 'guard') for choice in ('main', 'node')]
            list(pool.map(lambda case: self.exercise(*case), cases))

    def exercise(self, choice, mode):
        core = os.environ['VLESS_TEST_XRAY']
        with ExitStack() as stack:
            directory = Path(stack.enter_context(tempfile.TemporaryDirectory()))
            conf = json.loads(subprocess.check_output(['php', str(ROOT/'tests/exit_standby_test.php'), '--fixture', choice, mode]))
            backends = {}
            for label, tag in [('main','direct'), ('primary',PRIMARY), ('backup','vpnbot-exit-bbbbbbbb')]:
                tcp = stack.enter_context(socketserver.ThreadingTCPServer(('127.0.0.1', 0), Backend))
                udp = stack.enter_context(socketserver.ThreadingUDPServer(tcp.server_address, Backend))
                backends[label] = (tcp, udp)
                for server in (tcp, udp):
                    server.up, server.label = True, label.encode()
                    threading.Thread(target=server.serve_forever, daemon=True).start()
                    stack.callback(server.shutdown)
                target = next(o for o in conf['outbounds'] if o['tag'] == tag)
                port = tcp.server_address[1]
                target.clear()
                target.update(tag=tag, protocol='freedom', settings={'redirect': f'127.0.0.1:{port}',
                    'finalRules':[{'action':'allow','ip':['127.0.0.1/32'],'port':str(port)}]})
            listen, api = free_port(), free_port()
            for inlet in conf['inbounds']:
                inlet.update(listen='127.0.0.1', port=listen if inlet['tag']=='in' else free_port())
                if inlet['protocol'] == 'trojan':
                    hop = next(o for o in conf['outbounds'] if o['tag'] == inlet['tag'])
                    hop['settings']['servers'][0]['port'] = inlet['port']
            conf['api'] = {'tag':'api', 'listen':f'127.0.0.1:{api}', 'services':['RoutingService']}
            conf['dns'] = {'hosts':{'sample.test':'198.51.100.10','blocked.sample.test':'198.51.100.10',
                                    'backup-only.test':'198.51.100.10','controller.test':'203.0.113.9','internal.test':'10.10.0.8'},
                           'queryStrategy': 'UseIPv4', 'servers':['127.0.0.1']}
            conf['burstObservatory']['pingConfig'].update(destination='http://sample.test/health', sampling=1, timeout='1s')
            path = directory/'routing.json'
            path.write_text(json.dumps(conf))
            policy, = exit_failover.policies(path)
            proc = subprocess.Popen([core,'run','-config',str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            stack.callback(lambda: (proc.terminate(), proc.wait(timeout=5)))
            def observe():
                r=json.loads(local_api(core, api, ['bi','-json','-s','127.0.0.1:8080',policy.tag]))['balancer']
                return r['principleTarget']['tag'], r['override'].get('target', '')
            def wait(predicate, seconds):
                end=time.monotonic()+seconds
                while time.monotonic()<end:
                    self.assertIsNone(proc.poll(), 'the generated configuration must start')
                    try:
                        if predicate(): return
                    except subprocess.CalledProcessError: pass
                    time.sleep(.25)
                self.fail(f'{choice}: timed out waiting for {predicate.__name__}')
            wait(lambda: observe()[0]==[policy.primary], 25)
            worker = subprocess.Popen([sys.executable, '-B', __file__, '--worker', str(path), core, str(api)])
            stack.callback(lambda: (worker.terminate(), worker.wait(timeout=5)))
            def paths(label):
                for login in (FULL, LISTED):
                    for udp in (False, True):
                        self.assertEqual(request(listen,login,'sample.test',udp),label+b'x', (choice, login == FULL, udp))
            paths(b'primary')
            for server in backends['primary']: server.up=False
            wait(lambda: observe()[0]==[''], 25)
            started=time.monotonic()
            self.assertFalse(request(listen,FULL,'sample.test',False))
            self.assertEqual(request(listen,OTHER,'sample.test',False),b'mainx')
            wait(lambda: observe()[1] == policy.standby, 40)
            self.assertGreaterEqual(time.monotonic()-started,29.5)
            paths(b'main' if choice=='main' else b'backup')
            # Routing reloads may clear the in-process override while the node is down.
            local_api(core, api, ['bo','-s','127.0.0.1:8080','-b',policy.tag,'-r'])
            wait(lambda: observe()[1] == policy.standby, 12)
            denied = ['blocked.sample.test','192.0.2.1']
            if mode == 'controller':
                denied += ['controller.test','internal.test']
            if choice == 'node':
                denied.append('backup-only.test')
            for dest in denied:
                for udp in (False, True):
                    self.assertFalse(request(listen,FULL,dest,udp), (choice, dest, udp))
            if choice=='node':
                for server in backends['backup']: server.up=False
                self.assertFalse(request(listen,FULL,'sample.test',False), 'both down must not use main')
                self.assertEqual(request(listen,OTHER,'sample.test',False),b'mainx')
            for server in backends['primary']: server.up=True
            wait(lambda: observe()[0]==[policy.primary],25)
            wait(lambda: observe()[1]=='', 10)
            paths(b'primary')


if __name__ == '__main__':
    if sys.argv[1:2] == ['--worker']:
        exit_failover.main(Path(sys.argv[2]), lambda args: local_api(sys.argv[3], sys.argv[4], args))
    else:
        unittest.main()
