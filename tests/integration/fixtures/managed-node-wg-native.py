#!/usr/bin/env python3
"""Real userspace WireGuard TCP/UDP and ACLs, entirely in an isolated netns."""
import base64
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

if os.geteuid() != 0 or os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
    raise SystemExit('Disposable network namespace required')
os.umask(0o077)
source, cores = Path(os.environ['NODE_SOURCE_DIR']), Path(os.environ['CORE_TEST_DIR'])
sys.path.insert(0, str(source/'scripts'))
import node_config as config
import node_wg as wg
root = Path(tempfile.mkdtemp(prefix='node-wg-', dir='/run'))
processes, servers = [], []
env = os.environ | {'GODEBUG': 'multipathtcp=0'}
checks = 0

def run(args, **kwargs):
    return subprocess.run(list(map(str, args)), capture_output=True, timeout=15, **kwargs)

def check(name, yes):
    global checks
    print(('PASS ' if yes else 'FAIL ')+name, flush=True)
    if not yes: raise RuntimeError(name)
    checks += 1

def pair():
    body = run([cores/'x31', 'x25519'], check=True).stdout.decode()
    values = dict((k.lower().replace(' ', ''), v) for k,v in re.findall(r'^([^:]+):\s*(\S+)', body, re.M))
    return dict(private=values['privatekey'], public=values.get('password(publickey)') or values.get('password') or values.get('publickey'))

def start(binary, name, value):
    path = root/(name+'.json');path.write_text(json.dumps(value))
    check(name+' validates', run([binary, 'run', '-test', '-c', path], env=env).returncode == 0)
    p = subprocess.Popen([str(binary), 'run', '-c', str(path)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    processes.append(p);time.sleep(.25)
    check(name+' runs', p.poll() is None)
    return p

def stop(p):
    p.terminate();p.wait(timeout=5);processes.remove(p)

class HTTP(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.send_header('Content-Length', '7');self.end_headers();self.wfile.write(b'wg-pass')
    def log_message(self, *args): pass

class HTTPServer(ThreadingHTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self);self.server_name='fixture';self.server_port=self.server_address[1]
class HTTP6(HTTPServer): address_family = socket.AF_INET6
class UDP(socketserver.BaseRequestHandler):
    def handle(self): self.request[1].sendto(self.request[0], self.client_address)
class UDP6(socketserver.ThreadingUDPServer): address_family = socket.AF_INET6

class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            offset = 12
            while data[offset]: offset += data[offset]+1
            offset += 1
            kind = struct.unpack('!H', data[offset:offset+2])[0]
            question = data[12:offset+4]
            address = '11.77.0.128' if kind == 1 else '2620:fe::fe'
            packed = socket.inet_pton(socket.AF_INET if kind == 1 else socket.AF_INET6, address)
            answer = b'\xc0\x0c'+struct.pack('!HHIH',kind,1,60,len(packed))+packed
            sock.sendto(data[:2]+b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'+question+answer, self.client_address)
        except (IndexError, ValueError, struct.error): pass

def tcp(address):
    address = '['+address+']' if ':' in address else address
    r = run(['curl', '--noproxy', '', '-sS', '--socks5-hostname', '127.0.0.1:10875', '--max-time', '2', 'http://'+address+':18087/'])
    return r.returncode == 0 and r.stdout == b'wg-pass'

def udp(address):
    with socket.create_connection(('127.0.0.1', 10875), timeout=2) as control:
        control.settimeout(2);control.sendall(b'\x05\x01\x00')
        if control.recv(2) != b'\x05\x00': return False
        control.sendall(b'\x05\x03\x00\x01'+b'\0'*6)
        response = control.recv(256)
        if len(response) < 10 or response[1] != 0 or response[3] != 1: return False
        port = struct.unpack('!H', response[8:10])[0]
        family = socket.AF_INET6 if ':' in address else socket.AF_INET
        header = b'\0\0\0'+(b'\x04' if family == socket.AF_INET6 else b'\x01')+socket.inet_pton(family,address)+struct.pack('!H',18088)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2);sock.sendto(header+b'wg-udp-pass', ('127.0.0.1',port))
            return sock.recv(1024).endswith(b'wg-udp-pass')

try:
    run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    for address in ['11.77.0.4/32', '11.77.0.128/32', '1.1.1.1/32', '9.9.9.9/32',
                    '2606:4700:4700::4/128', '2606:4700:4700::1111/128', '2620:fe::fe/128']:
        run(['ip', 'addr', 'add', address, 'dev', 'lo']+(['nodad'] if ':' in address else []), check=True)
    for address in ('11.77.0.128', '2620:fe::fe', '127.0.0.1', '::1'):
        for kind, port, handler in [(HTTP6 if ':' in address else HTTPServer, 18087, HTTP),
                                    (UDP6 if ':' in address else socketserver.ThreadingUDPServer, 18088, UDP)]:
            server = kind((address, port), handler);servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
    for address in ('1.1.1.1','9.9.9.9','2606:4700:4700::1111','2620:fe::fe'):
        kind = UDP6 if ':' in address else socketserver.ThreadingUDPServer
        server = kind((address, 53), DNS);servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    public_host = dict(public4='11.77.0.4',public6='2606:4700:4700::4',sources=['11.77.0.2'],admins=['11.77.0.2'],
                       routers=[],ssh_ports=[2222],interface='lo',uid=995,gid=995)
    keys = pair() | dict(uuid=str(uuid.uuid4()), short_id=os.urandom(8).hex(), path=os.urandom(16).hex(), wireguard=wg.generate(pair))
    for core, binary in [('origin', 'x31'), ('fork', 'fork'), ('origin2', 'origin2'), ('origin3', 'origin3')]:
        for family in (4, 6):
            for connection in (4, 6):
                name = f'{core}-wg{connection}-egress{family}'
                options = dict(transport='reality',core=core,family=family,connect_family=connection,domain='',mask='mask.example.test',
                               wireguard=dict(enabled=True,active=True,mtu=1280,keepalive=17))
                value = config.core_config(options, public_host, keys)
                # Test the actual optional inbound and the unchanged egress ACL.
                value['inbounds'] = value['inbounds'][1:]
                server = start(cores/binary, name+'-server', value)
                client = config.export_profile(options, public_host, keys)['outbound']
                client['settings']['peers'][0]['endpoint'] = client['settings']['peers'][0]['endpoint'].rsplit(':',1)[0]+':51830'
                client_config = dict(log={'loglevel':'none'},inbounds=[dict(listen='127.0.0.1',port=10875,protocol='socks',settings={'udp':True})],outbounds=[client])
                p = start(cores/binary, name+'-client', client_config)
                target = '11.77.0.128' if family == 4 else '2620:fe::fe'
                check(name+' TCP traffic', tcp(target))
                check(name+' UDP traffic', udp(target))
                check(name+' DNS through tunnel', tcp('fixture.example.test'))
                check(name+' private destination denied', not tcp('127.0.0.1' if family == 4 else '::1'))
                stop(p)
                client_config['outbounds'][0]['settings']['peers'][0]['preSharedKey'] = base64.b64encode(os.urandom(32)).decode()
                p = start(cores/binary, name+'-wrong-key', client_config)
                check(name+' wrong key denied', not tcp(target))
                stop(p);stop(server)
    print(f'PASS {checks} native WireGuard checks', flush=True)
finally:
    for p in processes: p.terminate();p.wait(timeout=5)
    for server in servers: server.shutdown();server.server_close()
    shutil.rmtree(root)
