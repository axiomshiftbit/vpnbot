#!/usr/bin/env python3
"""Авторитетный fixture для одного имени; нет forwarding и выхода в интернет."""
import argparse
import ipaddress
import json
from pathlib import Path
import signal
import socketserver
import struct
import threading

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bind', default='127.0.0.1')
    p.add_argument('--port', type=int, default=1053)
    p.add_argument('--name', default='storage.audit.test')
    p.add_argument('--public-answers', type=int, default=1)
    p.add_argument('--private-after', action='store_true')
    a = p.parse_args()
    marker = Path('/run/vpnbot-synthetic-audit')
    if not marker.is_file() or marker.is_symlink() or marker.read_text().strip() != 'SYNTHETIC-ONLY':
        p.error('нужен маркер синтетического стенда')
    ip = ipaddress.ip_address(a.bind)
    if not (ip.is_loopback or ip in ipaddress.ip_network('11.77.78.0/24') or ip in ipaddress.ip_network('172.30.79.0/24')):
        p.error('адрес вне тестовых сетей')
    if not a.name.endswith('.audit.test') or a.public_answers < 1 or not 1 <= a.port <= 65535:
        p.error('неверные тестовые параметры')
    state = {'a_queries': 0, 'public_answers': 0, 'private_answers': 0}
    lock = threading.RLock()
    def response(data):
        if len(data) < 12 or len(data) > 4096:
            return b''
        ident, _, qd, *_ = struct.unpack('!6H', data[:12])
        if qd != 1:
            return b''
        offset, labels = 12, []
        try:
            while data[offset]:
                size = data[offset]
                if size > 63:
                    return b''
                offset += 1
                labels.append(data[offset:offset + size].decode('ascii').lower())
                offset += size
            offset += 1
            qtype, qclass = struct.unpack('!HH', data[offset:offset + 4])
        except (IndexError, UnicodeError, struct.error):
            return b''
        question = data[12:offset + 4]
        answer, rcode = b'', 0
        if '.'.join(labels) != a.name or qclass != 1:
            rcode = 3
        elif qtype == 1:
            with lock:
                state['a_queries'] += 1
                private = a.private_after and state['a_queries'] > a.public_answers
                state['private_answers' if private else 'public_answers'] += 1
            address = ipaddress.ip_address('172.30.79.3' if private else '11.77.78.2').packed
            answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + address
        return struct.pack('!6H', ident, 0x8580 | rcode, 1, int(bool(answer)), 0, 0) + question + answer
    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            out = response(data)
            if out:
                sock.sendto(out, self.client_address)
    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            def exact(size):
                body = b''
                while len(body) < size:
                    more = self.request.recv(size - len(body))
                    if not more:
                        raise EOFError()
                    body += more
                return body
            try:
                size = struct.unpack('!H', exact(2))[0]
                if size > 4096:
                    return
                out = response(exact(size))
                self.request.sendall(struct.pack('!H', len(out)) + out)
            except (OSError, EOFError):
                pass
    def reset(*_):
        with lock:
            print(json.dumps({'dns_counts_before_reset': state.copy()}), flush=True)
            state.update({k: 0 for k in state})
    signal.signal(signal.SIGUSR1, reset)
    udp = socketserver.UDPServer((a.bind, a.port), UDP)
    tcp = socketserver.TCPServer((a.bind, a.port), TCP)
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    print(json.dumps({'ready': True, 'port': a.port, 'mode': 'rebind' if a.private_after else 'constant'}), flush=True)
    udp.serve_forever()

if __name__ == '__main__':
    main()
