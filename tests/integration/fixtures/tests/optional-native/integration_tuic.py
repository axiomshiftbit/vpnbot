import contextlib,copy,hashlib,json,os,socket,struct,subprocess,time
from pathlib import Path
ROOT=Path('/opt/vpnbot-hosted-ci/tests/optional-native');BOT=Path('/opt/vpnbot-hosted-ci/stand/bot')
WORK=ROOT/'private/integration-tuic';WORK.mkdir(exist_ok=True,mode=0o700)
PROFILES=BOT/'logs/audit-tuic';STATE=BOT/'config/protocols/tuic'
RESULTS=[]
def check(name,ok,**detail):
    RESULTS.append({'name':name,'passed':bool(ok),**detail})
    (ROOT/'results/tuic-integration.json').write_text(json.dumps(RESULTS,indent=2))
    print(('PASS ' if ok else 'FAIL ')+name,flush=True)
    if not ok:raise RuntimeError(name)
def driver(*args):
    r=subprocess.run(['docker','exec','php-audit','php','/tmp/tuic-driver.php',*args],capture_output=True,timeout=30)
    if r.returncode:raise RuntimeError('driver '+args[0])
    return json.loads(r.stdout)
def status():return json.loads((STATE/'runtime/status.json').read_text())
def wait_applied(timeout=15):
    revision=json.loads((STATE/'desired.json').read_text())['revision'];until=time.monotonic()+timeout
    while time.monotonic()<until:
        try:s=status()
        except FileNotFoundError:time.sleep(.2);continue
        if s['revision']==revision and s['phase'] in ('running','idle','disabled'):return s
        time.sleep(.2)
    raise RuntimeError('apply deadline')
def recv(s,n):
    b=b''
    while len(b)<n:
        a=s.recv(n-len(b))
        if not a:raise EOFError('closed')
        b+=a
    return b
class Client:
    def __init__(self,engine='singbox',label='a',modify=None,trust=True):
        self.engine=engine;self.port=11110;self.config=json.loads((PROFILES/f'{label}-{engine}.json').read_text())
        if engine=='singbox':self.config['inbounds'][0]['listen_port']=self.port
        else:self.config['mixed-port']=self.port
        if modify:modify(self.config)
        self.trust=trust
    def __enter__(self):
        path=WORK/(self.engine+'.json');path.write_text(json.dumps(self.config))
        binary='/opt/vpnbot-hosted-ci/clients/'+('sing-box' if self.engine=='singbox' else 'mihomo')
        cmd=[binary,'run','-c',str(path)] if self.engine=='singbox' else [binary,'-d',str(WORK/'mihomo'),' -f'.strip(),str(path)]
        env=os.environ.copy();env['SSL_CERT_FILE']='/opt/vpnbot-hosted-ci/stand/bot/certs/vpnbot-protocol-test/server.pem' if self.trust else '/etc/ssl/certs/ca-certificates.crt'
        self.log=(WORK/'clients.log').open('ab');self.p=subprocess.Popen(cmd,env=env,stdout=self.log,stderr=self.log)
        deadline=time.monotonic()+10
        while self.p.poll() is None and time.monotonic()<deadline:
            try:
                with socket.create_connection(('127.0.0.1',self.port),timeout=.2):return self
            except OSError:time.sleep(.1)
        self.__exit__();raise RuntimeError('client listener did not become ready')
    def __exit__(self,*_):
        self.p.terminate();self.p.wait(timeout=10);self.log.close()
    def request(self,url='http://11.77.0.2:8081/',data=None,https=False):
        args=['curl','--noproxy','','--socks5-hostname',f'127.0.0.1:{self.port}','--max-time','5','-fsS']
        if https:args+=['--cacert','/opt/vpnbot-hosted-ci/stand/bot/certs/vpnbot-protocol-test/server.pem','--connect-to','anytls.test:8443:11.77.0.2:8443']
        if data is not None:args+=['--data-binary','@-']
        r=subprocess.run(args+[url],input=data,capture_output=True)
        return r.returncode==0,r.stdout
    def stream(self):
        c=socket.create_connection(('127.0.0.1',self.port),timeout=5)
        c.sendall(b'\x05\x01\x00');assert recv(c,2)==b'\x05\x00'
        c.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('11.77.0.2')+struct.pack('!H',8081));h=recv(c,4);assert h[1]==0
        recv(c,6 if h[3]==1 else 18)
        c.sendall(b'GET /stream HTTP/1.1\r\nHost: target\r\n\r\n');assert b'200' in c.recv(4096)
        return c
    @contextlib.contextmanager
    def udp(self):
        with socket.create_connection(('127.0.0.1',self.port),timeout=5) as c:
            c.sendall(b'\x05\x01\x00');assert recv(c,2)==b'\x05\x00'
            c.sendall(b'\x05\x03\x00\x01'+b'\0'*6);h=recv(c,4);assert h[1]==0
            recv(c,4 if h[3]==1 else 16);port=struct.unpack('!H',recv(c,2))[0]
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as u:
                u.settimeout(3)
                def request(payload,target_port=9999):
                    u.sendto(b'\0\0\0\x01'+socket.inet_aton('11.77.0.2')+struct.pack('!H',target_port)+payload,('127.0.0.1',port))
                    return u.recv(65535)[10:]
                yield request
