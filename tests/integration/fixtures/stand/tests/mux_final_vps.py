#!/usr/bin/env python3
import concurrent.futures, shutil, copy, importlib.util, json, os, pathlib, socket, struct, subprocess, sys, time
BASE=pathlib.Path(__file__).resolve().parent
OLD=pathlib.Path('/opt/vpnbot-hosted-ci/lab')
spec=importlib.util.spec_from_file_location('oldlab', BASE/'native_lab.py')
lab=importlib.util.module_from_spec(spec); spec.loader.exec_module(lab)
RUN=BASE.parent/'results/sing-mux-final-fix'; RUN.mkdir(exist_ok=True,mode=0o700)
os.umask(0o077)
lab.BIN=OLD/'bin'; lab.LAB=RUN
lab.RESULT_FILE=RUN/'results.json'
lab.ENV=dict(os.environ, SSL_CERT_FILE=str(RUN/'server-public.pem'))
REMOTE='/opt/vpnbot-hosted-ci/stand'

def command(args,timeout=45): return subprocess.run(list(map(str,args)),capture_output=True,timeout=timeout,env=lab.ENV)
def remote(args):
    r=command(['bash','-c',args],180)
    if r.returncode: raise RuntimeError('remote command failed: '+str(r.returncode))
    return r.stdout.decode()
def record(name,actual,expected=True,detail=''): lab.record(name,actual,expected,detail)
def fetch():
    remote('docker exec php-audit php /tmp/audit-driver.php export')
    for kind in ('xray','mihomo','sing-box'):
        shutil.copyfile(pathlib.Path(REMOTE)/('bot/logs/audit-profiles/'+kind+'.json'),RUN/('full-'+kind+'.json'))
    shutil.copyfile(pathlib.Path(REMOTE)/'bot/certs/cert_public',RUN/'server-public.pem')

def profile(kind, port):
    full=json.loads((RUN/f'full-{kind}.json').read_text())
    if kind=='xray':
        node=next(n for n in full['outbounds'] if n['protocol'] in ('vless','trojan')); node['tag']='proxy'
        node['settings']['vnext' if node['protocol']=='vless' else 'servers'][0]['address']='127.0.0.1'
        # Xray 26.10.10+ без useSystemCa доверяет только встроенным корням и не читает SSL_CERT_FILE с CA стенда.
        if isinstance(node.get('streamSettings',{}).get('tlsSettings'),dict):node['streamSettings']['tlsSettings']['useSystemCa']=True
        return {'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'udp':True}}],'outbounds':[node]}
    if kind=='mihomo':
        node=next(n for n in full['proxies'] if n['type'] in ('vless','trojan')); node['name']='proxy'; node['server']='127.0.0.1'
        return {'mixed-port':port,'bind-address':'127.0.0.1','log-level':'warning','mode':'rule','proxies':[node],'rules':['MATCH,proxy']}
    node=next(n for n in full['outbounds'] if n['type'] in ('vless','trojan')); node['tag']='proxy'
    node.pop('domain_resolver',None); node['server']='127.0.0.1'
    return {'log':{'level':'warn'},'inbounds':[{'type':'mixed','listen':'127.0.0.1','listen_port':port}],'outbounds':[node]}

def udp_dns(port, controlled=False, label=''):
    with socket.create_connection(('127.0.0.1',port),timeout=7) as tcp:
        tcp.sendall(b'\x05\x01\x00'); assert lab.read_exact(tcp,2)==b'\x05\x00'
        tcp.sendall(b'\x05\x03\x00\x01'+bytes(6))
        hdr=lab.read_exact(tcp,4); assert hdr[1]==0
        lab.read_exact(tcp,4 if hdr[3]==1 else 16 if hdr[3]==4 else lab.read_exact(tcp,1)[0])
        target=struct.unpack('!H',lab.read_exact(tcp,2))[0]
        ident=os.urandom(2)
        query=ident+b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
            destination=('11.77.0.2',10053) if controlled else ('1.1.1.1',53)
            packet=b'\x00\x00\x00\x01'+socket.inet_aton(destination[0])+struct.pack('!H',destination[1])+query
            attempts=1 if controlled else 3
            deadline=time.monotonic()+10
            for attempt in range(attempts):
                remaining=deadline-time.monotonic()
                if remaining<=0:raise TimeoutError('DNS deadline exceeded')
                udp.settimeout(min(2,remaining) if attempt<attempts-1 else remaining)
                udp.sendto(packet,('127.0.0.1',target))
                ok=False
                try:
                    data,_=udp.recvfrom(4096)
                    off=10 if data[3]==1 else 22 if data[3]==4 else 7+data[4]
                    ok=data[off:off+2]==ident and bool(data[off+2]&128) and (data[off+3]&15)==0
                except socket.timeout:
                    ok=False
                    if attempt==attempts-1:raise
                    continue
                finally:
                    with (RUN/'udp-probes.jsonl').open('a') as log:
                        log.write(json.dumps({'label':label,'controlled':controlled,'time':time.time(),'query_id':int.from_bytes(ident,'big'),'attempt':attempt+1,'passed':ok})+'\n')
                return ok

def bot(*args):
    v=json.loads(remote('docker exec php-audit php /tmp/audit-driver.php '+' '.join(args)))
    record('bot-'+'-'.join(args)+'-warnings',len(v['warnings']),0)
    result=v['result']
    if isinstance(result,dict) and 'error' in result: record('bot-'+'-'.join(args)+'-accepted',not result['error'])
    if isinstance(result,dict) and 'ok' in result: record('bot-'+'-'.join(args)+'-accepted',bool(result['ok']))
    return result

def exchange(label,kind,binary=None,bad=None):
    port=lab.port();c=profile(kind,port)
    if bad=='old-hello':c['proxies'][0]['reality-opts'].pop('support-x25519mlkem768',None)
    if bad=='short-id':c['outbounds'][0]['streamSettings']['realitySettings']['shortId']='ffffffffffffffff'
    f=RUN/(label+'-'+kind+(('-'+bad) if bad else '')+'.json');f.write_text(json.dumps(c))
    parsed=command(lab.config_args(kind,f,True,binary));(f.with_suffix('.check.log')).write_bytes(parsed.stdout+parsed.stderr)
    record(f.stem+'-parse',parsed.returncode,0)
    if parsed.returncode:return
    with f.with_suffix('.log').open('wb') as log:
        proc=subprocess.Popen(list(map(str,lab.config_args(kind,f,binary=binary))),stdout=log,stderr=log,env=lab.ENV)
        try:
            record(f.stem+'-start',lab.ready(proc,port))
            for url in ['http://example.com/','https://example.com/'] if not bad else ['https://example.com/']:
                r=command(['curl','--noproxy','','--socks5-hostname',f'127.0.0.1:{port}','--cacert','/etc/ssl/certs/ca-certificates.crt','-sS','--max-time','6' if bad else '20',url])
                record(f.stem+'-'+url.split(':')[0],r.returncode==0 and b'Example Domain' in r.stdout,not bool(bad))
                if r.returncode:f.with_suffix('.curl.log').write_bytes(r.stderr)
            if not bad:
                # Controlled UDP must work with one datagram. Only Internet
                # DNS uses bounded retransmission, as normal DNS clients do.
                for controlled in (True,False):
                    try:ok=udp_dns(port,controlled=controlled,label=f.stem)
                    except (OSError,AssertionError):ok=False
                    record(f.stem+('-controlled-udp' if controlled else '-udp-dns'),ok)
        finally:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
