"""Настоящие TLS/REALITY/Vision по выходу ExitNodeLink. Только синтетические ключи.

Вызывается exit_node_security_core_test.py: внешняя сеть и NET_ADMIN не нужны.
Проверяются CA/SNI/учётные данные, параметры REALITY, ML-DSA между ядрами
и целостность большого TLS 1.3 ответа внутри Vision.
"""
import copy, hashlib, json, os, select, socket, ssl, subprocess, sys, tempfile, threading, time, urllib.parse
from pathlib import Path

os.umask(0o077)
SOURCE = Path(__file__).resolve().parents[4]
CORE = sys.argv[1]
OLD = sys.argv[2] if len(sys.argv) > 2 else None
UUID = '11111111-2222-4333-8444-555555555555'
PASSWORD = 'fixture-node-password'
SNI = 'node.example.test'
results = []

def run(args, **kw):
    return subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=15,**kw)

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

def ready(p, process):
    for _ in range(50):
        if process.poll() is not None:return False
        try:socket.create_connection(('127.0.0.1',p),.1).close();return True
        except OSError:time.sleep(.1)
    return False

def check(name,value):
    results.append({'case':name,'passed':bool(value)})
    print(json.dumps(results[-1]),flush=True)

def keypair(core, mode):
    r=run([core,mode]);r.check_returncode()
    return dict(line.split(': ',1) for line in r.stdout.splitlines() if ': ' in line)

def parsed(query, server_port, scheme='vless', credential=UUID):
    link=f'{scheme}://{credential}@127.0.0.1:{server_port}?'+urllib.parse.urlencode(query)
    r=run(['php','-r',"require $argv[1] . '/app/ExitNodeLink.php'; echo json_encode(ExitNodeLink::parse(stream_get_contents(STDIN))['outbound']);",str(SOURCE)],input=link)
    if r.returncode:raise RuntimeError('node parser rejected synthetic fixture')
    return json.loads(r.stdout)

with tempfile.TemporaryDirectory() as temp:
    root=Path(temp)
    def start(core,name,config,env=None):
        path=root/(name+'.json');path.write_text(json.dumps(config))
        log=(root/(name+'.log')).open('wb')
        proc=subprocess.Popen([core,'run','-config',str(path)],stdout=log,stderr=log,env=env)
        log.close();return proc
    def stop(proc):
        if proc.poll() is None:proc.kill()
        proc.wait()
    def connects(outbound, client_core=CORE, ca=None):
        outbound=copy.deepcopy(outbound)
        env=dict(os.environ)
        if ca:
            outbound['streamSettings']['tlsSettings']['useSystemCa']=True
            env.update(SSL_CERT_FILE=str(ca),SSL_CERT_DIR=str(root/'empty-ca'))
        p=port()
        c=start(client_core,'client',{'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':p,'protocol':'socks'}],'outbounds':[outbound]},env)
        try:
            if not ready(p,c):return False
            r=run(['curl','-s','--noproxy','','--max-time','4','--socks5-hostname',f'127.0.0.1:{p}',
                   '-o','/dev/null','-w','%{http_code}','http://through-node.example.test/'])
            return r.stdout=='403'
        finally:stop(c)
    def server_config(p, stream, scheme='vless'):
        settings={'decryption':'none','clients':[{'id':UUID}]} if scheme=='vless' else {'clients':[{'password':PASSWORD}]}
        if stream['security']=='reality':settings['clients'][0]['flow']='xtls-rprx-vision'
        return {'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':p,'protocol':scheme,'settings':settings,'streamSettings':stream}],
                'outbounds':[{'protocol':'blackhole','settings':{'response':{'type':'http'}}}]}
    for name in ('cert','other'):
        names=','.join(['DNS:'+SNI]+[f'DNS:padding-{i:03d}-abcdefghijklmnopqrstuvwxyz.example.test' for i in range(100)])
        r=run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','1',
               '-subj','/CN='+SNI,'-addext','subjectAltName='+names,'-keyout',root/(name+'.key'),'-out',root/(name+'.pem')]);r.check_returncode()
    (root/'empty-ca').mkdir()
    for transport in ('ws','xhttp','grpc'):
        scheme='trojan' if transport=='grpc' else 'vless'
        p=port();q={'security':'tls','type':transport,'sni':SNI,'fp':'chrome'}
        extra={'wsSettings':{'path':'/node'}} if transport=='ws' else {'xhttpSettings':{'path':'/node','mode':'auto'}} if transport=='xhttp' else {'grpcSettings':{'serviceName':'node'}}
        q.update({'serviceName':'node'} if transport=='grpc' else {'path':'/node'})
        stream={'network':transport,'security':'tls','tlsSettings':{'certificates':[{'certificateFile':str(root/'cert.pem'),'keyFile':str(root/'cert.key')}]},**extra}
        server=start(CORE,'server',server_config(p,stream,scheme))
        try:
            if not ready(p,server):raise RuntimeError('TLS fixture server did not start')
            out=parsed(q,p,scheme,PASSWORD if scheme=='trojan' else UUID)
            check(transport+'-trusted-certificate',connects(out,ca=root/'cert.pem'))
            check(transport+'-untrusted-certificate-rejected',not connects(out,ca=root/'other.pem'))
            wrong=copy.deepcopy(out);wrong['streamSettings']['tlsSettings']['serverName']='wrong.example.test'
            check(transport+'-wrong-server-name-rejected',not connects(wrong,ca=root/'cert.pem'))
            wrong=parsed(q,p,scheme,'wrong-fixture-password' if scheme=='trojan' else '99999999-2222-4333-8444-555555555555')
            check(transport+'-wrong-user-rejected',not connects(wrong,ca=root/'cert.pem'))
        finally:stop(server)

    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(root/'cert.pem',root/'cert.key');context.set_alpn_protocols(['h2','http/1.1'])
    mask=socket.socket();mask.bind(('127.0.0.1',0));mask.listen(32);mask_port=mask.getsockname()[1]
    def serve_one(conn):
        try:
            conn.settimeout(3)
            with context.wrap_socket(conn,server_side=True) as tls:tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nMASK')
        except OSError:pass
        finally:conn.close()
    def serve():
        while True:
            try:c,_=mask.accept()
            except OSError:return
            threading.Thread(target=serve_one,args=(c,),daemon=True).start()
    threading.Thread(target=serve,daemon=True).start()
    try:
        for core in [CORE]+([OLD] if OLD else []):
            label=Path(core).name;k=keypair(core,'x25519');m=keypair(core,'mldsa65');other=keypair(core,'mldsa65')
            private=k.get('PrivateKey') or k.get('Private key');public=k.get('Password (PublicKey)') or k.get('Password') or k.get('Public key')
            p=port();q={'security':'reality','type':'tcp','sni':SNI,'fp':'chrome','pbk':public,'sid':'abcd1234','flow':'xtls-rprx-vision','pqv':m['Verify']}
            stream={'network':'tcp','security':'reality','realitySettings':{'dest':f'127.0.0.1:{mask_port}','serverNames':[SNI],'privateKey':private,'shortIds':['abcd1234'],'mldsa65Seed':m['Seed']}}
            server=start(core,'server',server_config(p,stream))
            try:
                if not ready(p,server):raise RuntimeError('REALITY fixture server did not start')
                out=parsed(q,p)
                for client in [CORE]+([OLD] if OLD else []):check(label+'-mldsa-client-'+Path(client).name,connects(out,client))
                if core==CORE:
                    for field,value in [('pqv',other['Verify']),('sid','deadbeef'),('sni','wrong.example.test')]:
                        check('reality-wrong-'+field+'-rejected',not connects(parsed(q|{field:value},p)))
                    k2=keypair(CORE,'x25519');check('reality-wrong-pbk-rejected',not connects(parsed(q|{'pbk':k2.get('Password (PublicKey)') or k2.get('Password')},p)))
                    check('reality-wrong-user-rejected',not connects(parsed(q,p,credential='99999999-2222-4333-8444-555555555555')))
                    check('reality-valid-after-negative-tests',connects(out))
            finally:stop(server)
        # TLS 1.3 внутри Vision: настоящий большой ответ, а не HTTP-заглушка.
        payload=os.urandom(2*1024*1024)
        target=socket.socket();target.bind(('127.0.0.1',0));target.listen(16);target_port=target.getsockname()[1]
        def target_one(conn):
            try:
                conn.settimeout(5)
                with context.wrap_socket(conn,server_side=True) as tls:
                    request=b''
                    while b'\r\n\r\n' not in request:
                        part=tls.recv(4096)
                        if not part:return
                        request+=part
                    tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(payload)).encode()+b'\r\nConnection: close\r\n\r\n'+payload)
            except OSError:pass
            finally:conn.close()
        def targets():
            while True:
                try:c,_=target.accept()
                except OSError:return
                threading.Thread(target=target_one,args=(c,),daemon=True).start()
        threading.Thread(target=targets,daemon=True).start()
        # Freedom намеренно блокирует loopback. SOCKS-цель стенда пересылает
        # только в наш TLS-сервер; ни внешняя сеть, ни NET_ADMIN не нужны.
        relay=socket.socket();relay.bind(('127.0.0.1',0));relay.listen(16);relay_port=relay.getsockname()[1]
        def relay_one(conn):
            def read(n):
                data=b''
                while len(data)<n:
                    part=conn.recv(n-len(data))
                    if not part:raise OSError('closed fixture connection')
                    data+=part
                return data
            try:
                conn.settimeout(8);hello=read(2);read(hello[1]);conn.sendall(b'\x05\x00')
                header=read(4);read(read(1)[0] if header[3]==3 else 4 if header[3]==1 else 16);read(2)
                with socket.create_connection(('127.0.0.1',target_port),3) as upstream:
                    conn.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                    while True:
                        active,_,_=select.select([conn,upstream],[],[],8)
                        if not active:return
                        for source in active:
                            data=source.recv(65536)
                            if not data:return
                            (upstream if source is conn else conn).sendall(data)
            except OSError:pass
            finally:conn.close()
        def relays():
            while True:
                try:c,_=relay.accept()
                except OSError:return
                threading.Thread(target=relay_one,args=(c,),daemon=True).start()
        threading.Thread(target=relays,daemon=True).start()
        try:
            for core in [CORE]+([OLD] if OLD else []):
                conf=server_config(p,stream);conf['outbounds']=[{'protocol':'socks','settings':{'servers':[{'address':'127.0.0.1','port':relay_port}]}}]
                server=start(core,'server',conf)
                try:
                    if not ready(p,server):raise RuntimeError('Vision data server did not start')
                    for client_core in [CORE]+([OLD] if OLD else []):
                        socks=port();client=start(client_core,'client',{'log':{'loglevel':'debug'},'inbounds':[{'listen':'127.0.0.1','port':socks,'protocol':'socks'}],'outbounds':[out]})
                        try:
                            if not ready(socks,client):raise RuntimeError('Vision data client did not start')
                            r=run(['curl','-s','--noproxy','','--http1.1','--tlsv1.3','--max-time','8','--cacert',root/'cert.pem','--socks5-hostname',f'127.0.0.1:{socks}','-o',root/'payload',f'https://{SNI}:{target_port}/'])
                            ok=r.returncode==0 and (root/'payload').is_file() and hashlib.sha256((root/'payload').read_bytes()).digest()==hashlib.sha256(payload).digest()
                            check(Path(core).name+'-vision-tls13-payload-client-'+Path(client_core).name,ok)
                        finally:stop(client)
                finally:stop(server)
        finally:target.close();relay.close()
    finally:mask.close()
print(json.dumps({'passed':sum(r['passed'] for r in results),'total':len(results),'results':results}))
raise SystemExit(not all(r['passed'] for r in results))
