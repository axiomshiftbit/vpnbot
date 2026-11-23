"""Observe controller and node egress using the controller's generated Xray rules."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest

from node_policy_test import Echo, free_port, request


@unittest.skipUnless(os.environ.get('VLESS_TEST_XRAY') and shutil.which('php'), 'requires PHP and Xray')
class MainExitLists(unittest.TestCase):
    def test_personal_split(self):
        source = Path(__file__).resolve().parents[1]
        generate = """
ob_start(); require 'tests/exit_nodes_test.php'; ob_end_clean();
$x = $base;
$x['inbounds'][0]['settings']['clients'] = array_slice($x['inbounds'][0]['settings']['clients'],0,2);
foreach ($x['inbounds'][0]['settings']['clients'] as &$person) $person['exit_full'] = $id;
unset($person);
$x['inbounds'][0]['settings']['clients'][0]['exit_main'] = ['local'];
$x['routing']['domainStrategy'] = 'IPIfNonMatch';
$x['routing']['rules'][] = ['type'=>'field','ruleTag'=>'vpnbot:routes:block:ip','ip'=>['9.9.9.9'],'outboundTag'=>'block'];
$p = ['exits'=>[$id=>['link'=>$link,'quic'=>'pass','enabled'=>(int)$argv[1]]],
      'node_policy_lists'=>['local'=>['domain'=>['full:bank.test','domain:banks.test','keyword:billing',
       'regexp:^pay[0-9]+\\.test$','full:denied.test','full:ads.example'],'ip'=>['11.77.0.0/24','2606:4700::/32']]]];
$bot->ensureExitNodes($x,$p); $bot->ensureWgGuard($x);
echo json_encode(['rules'=>$x['routing']['rules'], 'hops'=>array_values(array_filter($x['outbounds'],
static fn($o)=>$o['protocol']==='loopback')), 'node'=>Bot::EXIT_TAG.$id], JSON_THROW_ON_ERROR);
"""
        labels = ('main', 'node')
        with ExitStack() as stack:
            endpoints = {}
            for label in labels:
                tcp = stack.enter_context(socketserver.ThreadingTCPServer(('127.0.0.1', 0), Echo))
                udp = stack.enter_context(socketserver.ThreadingUDPServer(tcp.server_address, Echo))
                for srv in (tcp, udp):
                    srv.label = label.encode()
                    threading.Thread(target=srv.serve_forever, daemon=True).start()
                    stack.callback(srv.shutdown)
                endpoints[label] = tcp.server_address[1]
            for enabled in (True, False):
                data = json.loads(subprocess.check_output(['php', '-r', generate, str(int(enabled))], cwd=source))
                port = free_port()
                alice, bob = ('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222')
                config = {
                    'inbounds': [{'listen':'127.0.0.1', 'port':port, 'tag':'vless_reality', 'protocol':'vless',
                                  'settings':{'decryption':'none', 'clients':[{'email':'alice','id':alice},{'email':'bob','id':bob}]}}],
                    'outbounds':[{'tag':'block','protocol':'blackhole'}, *data['hops']],
                    'routing':{'domainStrategy':'IPIfNonMatch', 'rules':data['rules']},
                    'dns':{'servers':['127.0.0.1'], 'hosts':{
                        **{domain:'1.1.1.1' for domain in ('bank.test','sub.banks.test','billing.test','pay25.test',
                             'notbank.test','payx.test','other.test','ads.example')},'denied.test':'9.9.9.9'}},
                }
                for label, tag in zip(labels, ('direct', data['node'])):
                    config['outbounds'].append({'tag':tag,'protocol':'freedom','settings':{
                        'redirect':f'127.0.0.1:{endpoints[label]}','finalRules':[{'action':'allow','ip':['127.0.0.1/32']}]}})
                with tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / 'xr.json'
                    path.write_text(json.dumps(config))
                    proc = subprocess.Popen([os.environ['VLESS_TEST_XRAY'],'run','-c',str(path)],
                                            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    try:
                        for _ in range(80):
                            self.assertIsNone(proc.poll())
                            try:
                                socket.create_connection(('127.0.0.1',port),.1).close()
                                break
                            except OSError:
                                time.sleep(.025)
                        for udp in (False,True):
                            with self.subTest(enabled=enabled, udp=udp, ipv6=True):
                                self.assertFalse(request(port, alice, '2606:4700::1111', udp))
                            for user in (alice,bob):
                                for dest in ('bank.test','sub.banks.test','billing.test','pay25.test','11.77.0.8',
                                             'other.test','notbank.test','payx.test','1.1.1.1','denied.test','ads.example','9.9.9.9'):
                                    outcome = b'nodex' if enabled else None
                                    if dest in ('denied.test','ads.example','9.9.9.9'):
                                        outcome = None
                                    elif user == alice and dest in ('bank.test','sub.banks.test','billing.test','pay25.test','11.77.0.8'):
                                        outcome = b'mainx'
                                    with self.subTest(enabled=enabled, udp=udp, alice=user==alice, dest=dest):
                                        self.assertEqual(request(port,user,dest,udp) or None,outcome)
                    finally:
                        proc.terminate()
                        proc.wait(timeout=5)

    def test_mixed_group_selects_available_external_member(self):
        # The observatory dials a handler directly. Exercise an actual successful
        # HTTP response before trusting the balancer with the client's TCP/UDP.
        generate = """
ob_start(); require 'tests/exit_nodes_test.php'; ob_end_clean();
$guardPac['exits'][$gid]['choice']='auto';
$guardPac['exits'][$gid]['quic']='pass';
$c=$guardSeed; $bot->ensureExitNodes($c,$guardPac);
$bridge=static fn($o)=>str_starts_with($o['tag']??'','vpnbot-exit-group-member-');
echo json_encode(['routing'=>$c['routing'], 'observe'=>$c['burstObservatory']['subjectSelector'],
 'in'=>array_values(array_filter($c['inbounds'],$bridge)),
 'out'=>array_values(array_filter($c['outbounds'],static fn($o)=>$bridge($o)||$o['protocol']==='loopback')),
 'managed'=>Bot::EXIT_TAG.$id, 'external'=>Bot::EXIT_TAG.$second], JSON_THROW_ON_ERROR);
"""
        class Responder(socketserver.BaseRequestHandler):
            def handle(self):
                if isinstance(self.request, tuple):
                    data, sock = self.request
                    sock.sendto(b'external' + data, self.client_address)
                else:
                    data = self.request.recv(4096)
                    reply = b'HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n' if data.startswith((b'HEAD ', b'GET ')) else b'external' + data
                    self.request.sendall(reply)

        source = Path(__file__).resolve().parents[1]
        data = json.loads(subprocess.check_output(['php', '-r', generate], cwd=source))
        login = '11111111-1111-4111-8111-111111111111'
        with ExitStack() as stack:
            tcp = stack.enter_context(socketserver.ThreadingTCPServer(('127.0.0.1', 0), Responder))
            udp = stack.enter_context(socketserver.ThreadingUDPServer(tcp.server_address, Responder))
            for srv in [tcp, udp]:
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                stack.callback(srv.shutdown)
            port = free_port()
            for inlet in data['in']:
                # Per-test ports allow another instance to run in the same namespace.
                inlet['port'] = free_port()
                next(o for o in data['out'] if o['tag'] == inlet['tag'])['settings']['servers'][0]['port'] = inlet['port']
            cfg = {'inbounds': [*data['in'], {'protocol':'vless','tag':'vless_reality','listen':'127.0.0.1','port':port,
                    'settings':{'decryption':'none','clients':[{'id':login,'email':'alice'}]}}],
                   'outbounds': [{'tag':'block','protocol':'blackhole'},{'tag':data['managed'],'protocol':'blackhole'},
                       {'tag':data['external'],'protocol':'freedom','settings':{'redirect':f'127.0.0.1:{tcp.server_address[1]}',
                           'finalRules':[{'action':'allow','ip':['127.0.0.1/32'],'port':str(tcp.server_address[1])}]}}, *data['out']],
                   'routing':data['routing'],'dns':{'hosts':{'health.test':'1.1.1.1','denied.test':'11.77.1.0'},'servers':['127.0.0.1']},
                   'burstObservatory':{'subjectSelector':data['observe'],'pingConfig':{'destination':'http://health.test/ping',
                       'interval':'10s','sampling':1,'timeout':'2s'}}}
            directory = Path(stack.enter_context(tempfile.TemporaryDirectory()))
            path = directory / 'xr.json'
            path.write_text(json.dumps(cfg))
            core = subprocess.Popen([os.environ['VLESS_TEST_XRAY'],'run','-c',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            stack.callback(core.wait,5)
            stack.callback(core.terminate)
            until = time.monotonic() + 18
            while time.monotonic() < until:
                self.assertIsNone(core.poll())
                if request(port,login,'1.1.1.1',False) == b'externalx':
                    break
                time.sleep(.2)
            for udp in (False,True):
                with self.subTest(udp=udp):
                    self.assertEqual(request(port,login,'1.1.1.1',udp), b'externalx')
                    self.assertFalse(request(port,login,'11.77.1.0',udp))
                    self.assertFalse(request(port,login,'denied.test',udp))
