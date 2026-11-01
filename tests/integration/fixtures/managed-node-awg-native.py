#!/usr/bin/env python3
"""Real Amnezia carrier, restricted supervisor, TLS transports and core ACLs."""
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
root = Path(tempfile.mkdtemp(prefix='node-awg-', dir='/var/tmp'))
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
    value['log'] = {'loglevel': 'debug'}
    path = root/(name+'.json');path.write_text(json.dumps(value))
    check(name+' validates', run([binary, 'run', '-test', '-c', path], env=env).returncode == 0)
    with (root/(name+'.stderr')).open('wb') as output:
        p = subprocess.Popen([str(binary), 'run', '-c', str(path)], env=env, stdout=output, stderr=subprocess.STDOUT)
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
    limit = '2' if address in ('127.0.0.1', '::1') else '12'
    address = '['+address+']' if ':' in address else address
    # Match the real controller's 12-second traffic probe, including a cold
    # AWG handshake. Internal-address denial still uses a short deadline.
    started = time.monotonic()
    r = run(['curl', '--noproxy', '', '-sS', '--socks5-hostname', '127.0.0.1:10875', '--max-time', limit, 'http://'+address+':18087/'])
    elapsed = time.monotonic()-started
    if limit != '2' and elapsed > 2:
        print('DIAGNOSTIC cold TCP request seconds '+str(round(elapsed, 3)), flush=True)
    if r.returncode != 0:
        print('DIAGNOSTIC TCP curl code '+str(r.returncode),flush=True)
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

import ssl
import node_awg_client as supervisor
import node_awg as awg
proxy=Path(os.environ['AWG_PROXY'])
def helper(name, text):
    path=root/(name+'.conf');path.write_text(text)
    err=root/(name+'.stderr'); output=err.open('wb')
    p=subprocess.Popen([str(proxy), '-s', '-c', str(path)],stdout=subprocess.DEVNULL,stderr=output,env=env)
    output.close()
    processes.append(p);time.sleep(.3)
    if p.poll() is not None:
        body=err.read_text(errors='replace')
        for category in ('keepalive', 'ListenPort', 'address already in use', 'DNS', 'key', 'invalid', 'failed', 'permission', 'port', 'BindAddress'):
            if category.lower() in body.lower(): print('DIAGNOSTIC category '+category,flush=True)
        print('DIAGNOSTIC exit '+str(p.returncode)+' bytes '+str(len(body)),flush=True)
    check(name+' runs',p.poll() is None)
    return p


try:
    run(['ip','link','set','lo','up'],check=True)
    for address in ['11.77.0.4/32','11.77.0.128/32','1.1.1.1/32','9.9.9.9/32',
                    '2606:4700:4700::4/128','2606:4700:4700::1111/128','2620:fe::fe/128']:
        run(['ip','addr','add',address,'dev','lo']+(['nodad'] if ':' in address else []),check=True)
    for address in ('11.77.0.128','2620:fe::fe','127.0.0.1','::1'):
        for kind,port,handler in [(HTTP6 if ':' in address else HTTPServer,18087,HTTP),
                                  (UDP6 if ':' in address else socketserver.ThreadingUDPServer,18088,UDP)]:
            server=kind((address,port),handler)
            servers.append(server)
            threading.Thread(target=server.serve_forever,daemon=True).start()
    for address in ('1.1.1.1','9.9.9.9','2606:4700:4700::1111','2620:fe::fe'):
        server=(UDP6 if ':' in address else socketserver.ThreadingUDPServer)((address,53),DNS)
        servers.append(server)
        threading.Thread(target=server.serve_forever,daemon=True).start()
    # A TLS 1.3 cover with a sufficiently long certificate for REALITY.
    names='DNS:node.example.test,'+','.join(f'DNS:padding-{n:03d}-abcdefghijklmnopqrstuvwxyz.test' for n in range(100))
    run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=node.example.test',
         '-addext','subjectAltName='+names,'-keyout',root/'tls.key','-out',root/'tls.pem'],check=True)
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version=ssl.TLSVersion.TLSv1_3
    tls.set_alpn_protocols(['h2','http/1.1'])
    tls.load_cert_chain(root/'tls.pem',root/'tls.key')
    mask=socket.socket(socket.AF_INET)
    mask.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    mask.bind(('11.77.0.128',18443))
    mask.listen(32)
    def serve_mask(conn):
        try:
            conn.settimeout(3)
            with tls.wrap_socket(conn,server_side=True) as wrapped:
                wrapped.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nMASK')
        except OSError:
            pass
        finally:
            conn.close()
    def mask_loop():
        while True:
            try:
                conn,_=mask.accept()
            except OSError:
                return
            threading.Thread(target=serve_mask,args=(conn,),daemon=True).start()
    threading.Thread(target=mask_loop,daemon=True).start()
    host=dict(public4='11.77.0.4',public6='2606:4700:4700::4',sources=['11.77.0.2'],admins=['11.77.0.2'],
              routers=[],ssh_ports=[2222],interface='lo',uid=995,gid=995,awg_uid=994)
    keys=pair() | dict(uuid=str(uuid.uuid4()),short_id=os.urandom(8).hex(),path=os.urandom(16).hex(),amnezia=awg.generate(pair))
    root.chmod(0o711)
    supervisor.ROOT=root/'carriers'
    shutil.copyfile(proxy,root/'wireproxy')
    (root/'wireproxy').chmod(0o755)
    supervisor.BINARY=str(root/'wireproxy')
    original_popen=subprocess.Popen
    def diagnostic_popen(args, **kwargs):
        if args[0]==supervisor.BINARY:
            with (root/'supervisor.stderr').open('ab') as output:
                kwargs['stderr']=output
                try:
                    return original_popen(args, **kwargs)
                except (OSError, subprocess.SubprocessError) as error:
                    print('DIAGNOSTIC helper spawn '+type(error).__name__+' errno '+str(getattr(error,'errno',None)),flush=True)
                    raise
        return original_popen(args, **kwargs)
    subprocess.Popen=diagnostic_popen
    carriers=supervisor.Carriers()
    for core,binary in [('origin','x31'),('fork','fork'),('origin2','origin2'),('origin3','origin3')]:
        for transport in ('reality','ws','grpc','xhttp'):
            for family in (4,6):
                for connection in (4,6):
                    if os.environ.get('AWG_SINGLE') and (core,transport,family,connection)!=('origin','reality',4,4):
                        continue
                    if os.environ.get('AWG_CASE') and os.environ['AWG_CASE']!=f'{core}:{transport}:{family}:{connection}':
                        continue
                    if os.environ.get('AWG_FILTER') and not re.search(os.environ['AWG_FILTER'],f'{core}:{transport}:{family}:{connection}'):
                        continue
                    name=f'{core}-{transport}-awg{connection}-egress{family}'
                    options=dict(transport=transport,core=core,family=family,connect_family=connection,
                                 domain='node.example.test',mask='node.example.test',amnezia={'enabled':True,'active':True,'mtu':1280,'keepalive':'18-24',
                                 'parameters':{'Jc':5,'Jmin':70,'Jmax':900,'H1':'1-100','I1':'<b 0xaabb><r 16>'}})
                    if os.environ.get('AWG_TEMPLATE_FILE'):
                        template=json.loads(Path(os.environ['AWG_TEMPLATE_FILE']).read_text())[int(os.environ.get('AWG_TEMPLATE_INDEX','0'))]
                        options['amnezia'].update(awg.settings(template))
                        options['amnezia']['active']=True
                        name += '-'+template['template']
                    value=config.core_config(options,host,keys)
                    stream=value['inbounds'][0]['streamSettings']
                    if transport=='reality':
                        stream['realitySettings']['dest']='11.77.0.128:18443'
                    else:
                        stream['tlsSettings']['certificates']=[{'certificateFile':str(root/'tls.pem'),'keyFile':str(root/'tls.key')}]
                    xrserver=start(cores/binary,name+'-server',value)
                    # Actual source ACL/NAT is tested separately; this namespace
                    # has only loopback. Preserve the fixed carrier target.
                    awgserver=helper(name+'-carrier',awg.server(options['amnezia'],keys['amnezia']).replace('ListenPort = 51831','ListenPort = 51821'))
                    profile=config.export_profile(options,host,keys)
                    row={'client':profile['amnezia'],'session':os.urandom(8).hex()}
                    carriers.retry.clear()
                    carriers.sync({0:row})
                    time.sleep(.4)
                    check(name+' restricted helper runs',0 in carriers.active and carriers.active[0][1].poll() is None)
                    pid=carriers.active[0][1].pid
                    status=Path(f'/proc/{pid}/status').read_text()
                    check(name+' helper has no capabilities', 'CapEff:\t0000000000000000' in status and 'NoNewPrivs:\t1' in status
                          and re.search(r'^Uid:\s+61000\s+61000\s+61000\s+61000$',status,re.M) is not None)
                    outbound=profile['outbound']
                    outbound['settings'].update(address='127.0.0.1',port=10920)
                    if transport!='reality':
                        outbound['streamSettings']['tlsSettings']['certificates']=[{'usage':'verify','certificateFile':str(root/'tls.pem')}]
                    client=start(cores/binary,name+'-client',dict(log={'loglevel':'none'},
                        inbounds=[dict(listen='127.0.0.1',port=10875,protocol='socks',settings={'udp':True})],outbounds=[outbound]))
                    target='11.77.0.128' if family==4 else '2620:fe::fe'
                    tcp_ok=tcp(target)
                    if not tcp_ok:
                        carriers.sync({})
                        diagnostic=helper(name+'-root-control',awg.client(profile['amnezia'],0))
                        print('DIAGNOSTIC same transport root helper '+str(tcp(target)),flush=True)
                        stop(diagnostic)
                        stop(client)
                        outbound['settings']['port']=8443
                        client=start(cores/binary,name+'-direct-client',dict(log={'loglevel':'none'},
                            inbounds=[dict(listen='127.0.0.1',port=10875,protocol='socks',settings={'udp':True})],outbounds=[outbound]))
                        print('DIAGNOSTIC same transport direct '+str(tcp(target)),flush=True)
                    check(name+' TCP',tcp_ok)
                    check(name+' UDP over VLESS',udp(target))
                    check(name+' DNS through node',tcp('fixture.example.test'))
                    check(name+' private denied',not tcp('127.0.0.1' if family==4 else '::1'))
                    if core=='origin' and transport=='ws' and family==4 and connection==4:
                        process=carriers.active[0][1]
                        process.kill();process.wait(timeout=10)
                        carriers.sync({0:row})
                        time.sleep(5)
                        carriers.sync({0:row})
                        time.sleep(.4)
                        check('supervisor restores crashed helper',tcp(target))
                        bad=copy.deepcopy(row)
                        bad['client']['psk']=base64.b64encode(os.urandom(32)).decode()
                        carriers.retry.clear();carriers.sync({0:bad});time.sleep(.4)
                        check('wrong Amnezia key fails closed',not tcp(target))
                        carriers.retry.clear();carriers.sync({0:row});time.sleep(.4)
                        check('old Amnezia profile restores traffic',tcp(target))
                    stop(client)
                    carriers.sync({})
                    stop(awgserver)
                    stop(xrserver)
    print(f'PASS {checks} native Amnezia checks',flush=True)
except Exception:
    for path in root.glob('*.stderr'):
        if path.name != 'supervisor.stderr' and not path.name.startswith(name):
            continue
        data=path.read_text(errors='replace').lower()
        print('DIAGNOSTIC '+path.name+' bytes '+str(len(data)),flush=True)
        categories=('permission denied','not permitted','certificate','failed to dial','invalid connection',
                    'handshake','broken pipe','timeout','refused','invalid header','too many open files',
                    'unexpected eof','failed to listen','parse','invalid','no such file','network is unreachable',
                    'received request','tunneling request','dialing tcp','accepted','reality','xtls','padding','read','write','error','connection ends')
        for category in categories:
            if category in data:
                print('DIAGNOSTIC '+path.name+' category '+category,flush=True)
    raise
finally:
    if 'carriers' in globals():
        carriers.sync({})
    for process in processes:
        process.terminate();process.wait(timeout=5)
    if 'mask' in globals():mask.close()
    for server in servers:
        server.shutdown();server.server_close()
    shutil.rmtree(root)
