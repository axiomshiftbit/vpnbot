#!/usr/bin/env python3
"""Real Xray VLESS traffic and loss of a reset acknowledgement, with a private Unix stats socket."""
import argparse
import contextlib
import json
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import node_counters
import node_state


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def running(binary, config, path, listener):
    path.write_text(json.dumps(config))
    with subprocess.Popen([binary, 'run', '-c', path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as child:
        try:
            for _ in range(150):
                if child.poll() is not None: raise RuntimeError('test core exited before listening')
                try:
                    with socket.create_connection(('127.0.0.1', listener), timeout=.1): break
                except OSError: time.sleep(.025)
            else: raise RuntimeError('test core startup timeout')
            yield child
        finally:
            child.terminate()
            child.wait(timeout=5)


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)


def exercise(binary, directory):
    store = node_state.Store(directory / 'state')
    peer = {'id': str(uuid.uuid4()), 'name': 'panel', 'enabled': True}
    target = node_counters.key(peer)
    inbound, tunnel = port(), port()
    with socketserver.ThreadingTCPServer(('127.0.0.1', 0), Echo) as echo:
        threading.Thread(target=echo.serve_forever, daemon=True).start()
        server = {'inbounds': [{'tag': 'node', 'listen': '127.0.0.1', 'port': inbound, 'protocol': 'vless',
                                'settings': {'decryption': 'none', 'clients': [{'id': peer['id'], 'email': peer['name']}]}}],
                  'outbounds': [{'tag': 'direct', 'protocol': 'freedom', 'settings': {'finalRules': [
                      {'action': 'allow', 'ip': ['127.0.0.1/32'], 'port': str(echo.server_address[1])}]}}]}
        node_counters.enable(server)
        sock = directory/'stats.sock'
        server['inbounds'][-1]['listen'] = str(sock)
        client = {'inbounds': [{'listen': '127.0.0.1', 'port': tunnel, 'protocol': 'dokodemo-door',
                                'settings': {'address': '127.0.0.1', 'port': echo.server_address[1], 'network': 'tcp'}}],
                  'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{'address': '127.0.0.1', 'port': inbound,
                                 'users': [{'id': peer['id'], 'encryption': 'none'}]}]}}]}
        def transfer(count):
            body = b'z' * count
            with socket.create_connection(('127.0.0.1', tunnel), timeout=4) as s:
                s.sendall(body)
                received = bytearray()
                while len(received) < count:
                    chunk = s.recv(count-len(received))
                    if not chunk: raise RuntimeError('truncated data')
                    received.extend(chunk)
                assert received == body
        def read():
            raw = subprocess.run([binary, 'api', 'statsquery', '--server=unix://'+str(sock), '--timeout=3'],
                                 capture_output=True, check=True, timeout=5)
            return str(child.pid), json.loads(raw.stdout)
        def sample(operation=0):
            return node_counters.sample(store,[peer],read,target if operation else None,operation)
        with running(binary,client,directory/'client.json',tunnel):
            with running(binary,server,directory/'server.json',inbound) as child:
                transfer(16384); initial = sample()[target]
                assert initial['uplink'] >= 16384 and initial['downlink'] >= 16384, 'real traffic count'
                sample(10); transfer(8192)
                before=sample()[target]; sample(10); after=sample()[target]
                assert before == after and after['uplink'] >= 8192 and after['downlink'] >= 8192, 'lost ack'
            try: sample(11)
            except subprocess.CalledProcessError: pass
            else: raise AssertionError('offline reset accepted without a sample')
            with running(binary,server,directory/'server.json',inbound) as child:
                transfer(4096); restored=sample()[target]
                assert restored['uplink'] >= after['uplink'] + 4096, 'counter after core restart'
                sample(11); transfer(2048); sample(10)
                assert sample()[target]['downlink'] >= 2048, 'late reset preserved traffic'
        echo.shutdown()


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    args=parser.parse_args()
    with tempfile.TemporaryDirectory() as directory: exercise(args.binary.resolve(),Path(directory))
    print('peer counter integration OK')
