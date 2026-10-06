import json,os,pathlib,subprocess,time,sys,shutil,uuid
os.umask(0o077)
S=pathlib.Path(__file__).resolve().parent
O=pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else S/'result';O.mkdir(parents=True,exist_ok=True)
for name in ('client.py','server.py'):
    shutil.copyfile(S/name,O/name)
B=pathlib.Path('/opt/vpnbot-hosted-ci/stand/bot')
for name in ('start_wp.sh','warp_fixup.sh','warp_probe.sh'):
    shutil.copyfile(B/'scripts'/name,O/name)
bundle=json.loads(pathlib.Path(os.environ['VPNBOT_BUNDLE_FILE']).read_text())['images']
image=bundle['wg']
names=['vpnbot-warp-udp-'+s for s in ('proxy','peer','client','untrusted')]
proxy,peer,client,untrusted=names;network='vpnbot-warp-udp-test';children=[];made=[];rows=[]
def run(*a,input=None,timeout=60,check=True):
    p=subprocess.run(a,input=input,text=True,capture_output=True,timeout=timeout)
    if check and p.returncode:raise RuntimeError(str(a[:4])+': '+p.stderr[-1500:])
    return p
def dx(c,*a,**kw):return run('docker','exec',c,*a,**kw)
def pid(c):return run('docker','inspect','--format','{{.State.Pid}}',c).stdout.strip()
def check(n,v,detail=None):
    rows.append({'name':n,'passed':bool(v),'detail':detail});(O/'results.json').write_text(json.dumps(rows,indent=2))
    print(('PASS ' if v else 'FAIL ')+n,flush=True)
def probe(c,kind,target='203.0.113.20',**kw):
    data={'kind':kind,'proxy':'10.80.0.13',**kw}
    if kind!='control':data['target']=target
    p=run('nsenter','-t',pid(c),'-n','python3',str(O/'client.py'),input=json.dumps(data),timeout=15)
    return json.loads(p.stdout)
try:
    test_id=str(uuid.uuid4())
    generated=run('docker','exec','-i','php-audit','php','/dev/stdin',test_id,input=(S/'generate.php').read_text()).stdout
    (O/'sing-box.json').write_text(json.dumps({'log':{'level':'warn'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':19080}], 'outbounds':[{'type':'vless','tag':'proxy','server':'10.80.0.9','server_port':24444,'uuid':test_id}]}))
    (O/'xray.json').write_text(generated.replace('10.10.','10.80.'))
    for n in names:assert run('docker','inspect',n,check=False).returncode,'fixture already exists'
    assert run('docker','network','inspect',network,check=False).returncode,'network exists'
    run('docker','network','create','--subnet','10.80.0.0/24',network);made.append(('network',network))
    for n,ip in [(peer,'245'),(client,'9'),(untrusted,'19')]:
        run('docker','run','-d','--name',n,'--network',network,'--ip','10.80.0.'+ip,'--cap-add','NET_ADMIN','--entrypoint','sh',bundle['xr'] if n==client else bundle['php'] if n==untrusted else image,'-c','sleep infinity');made.append(('container',n))
    server=dx(peer,'wg','genkey').stdout.strip();secret=dx(peer,'wg','genkey').stdout.strip()
    spub=run('docker','exec','-i',peer,'wg','pubkey',input=server).stdout.strip();cpub=run('docker','exec','-i',peer,'wg','pubkey',input=secret).stdout.strip()
    run('docker','exec','-i',peer,'sh','-c','umask 077; cat > /tmp/wg.key',input=server)
    dx(peer,'sh','-ec','ip link add auditwarp type wireguard; ip addr add 172.30.0.1/24 dev auditwarp; ip link set auditwarp up; ip addr add 203.0.113.20/32 dev lo; ip addr add 1.1.1.1/32 dev lo; ip addr add 1.0.0.1/32 dev lo')
    dx(peer,'wg','set','auditwarp','private-key','/tmp/wg.key','listen-port','51820','peer',cpub,'allowed-ips','172.30.0.2/32')
    for d in ('config','warp','logs','ssh'):(O/d).mkdir(exist_ok=True)
    (O/'config/pac.json').write_text('{}');(O/'warp/wgcf-account.toml').write_text('# synthetic account\n')
    (O/'warp/wgcf-profile.conf').write_text('[Interface]\nPrivateKey = '+secret+'\nAddress = 172.30.0.2/32\nMTU = 1280\n[Peer]\nPublicKey = '+spub+'\nAllowedIPs = 0.0.0.0/0\nEndpoint = 10.80.0.245:51820\nPersistentKeepalive = 25\n')
    (O/'ssh/key.pub').write_text('# no SSH login needed in isolated fixture\n')
    args=['docker','run','-d','--name',proxy,'--network',network,'--ip','10.80.0.13','--cap-add','NET_ADMIN','--sysctl','net.ipv4.conf.all.src_valid_mark=1','--sysctl','net.ipv4.ip_local_port_range=20000 29999','-e','WARP_SOCKS_ALLOW=10.80.0.9']
    for src,dst in [('config','/config'),('warp','/etc/warp'),('logs','/logs'),('ssh','/ssh'),('start_wp.sh','/start_wp.sh'),('warp_fixup.sh','/warp_fixup.sh'),('warp_probe.sh','/warp_probe.sh')]:args+=['-v',str(O/src)+':'+dst]
    run(*args,'--entrypoint','sh',image,'/start_wp.sh');made.append(('container',proxy))
    children.append(subprocess.Popen(['nsenter','-t',pid(peer),'-n','python3',str(O/'server.py')],stdout=subprocess.DEVNULL,stderr=open(O/'server.log','w')))
    children.append(subprocess.Popen(['nsenter','-t',pid(proxy),'-n','tcpdump','-U','-n','-i','any','-s','256','-w',str(O/'udp.pcap'),'udp'], stdout=subprocess.DEVNULL,stderr=open(O/'tcpdump.log','w')))
    end=time.monotonic()+35
    while time.monotonic()<end:
        if dx(proxy,'pgrep','-x','warp-socks',check=False).returncode==0:break
        time.sleep(1)
    check('Xray-SOCKS-started',dx(proxy,'pgrep','-x','warp-socks',check=False).returncode==0)
    run('docker','cp',str(O/'xray.json'),client+':/tmp/warp-xray.json')
    run('docker','cp',str(O/'sing-box.json'),untrusted+':/tmp/warp-client.json')
    dx(client,'sh','-ec','/usr/bin/xray run -config /tmp/warp-xray.json >/tmp/xray-warp.log 2>&1 &')
    dx(untrusted,'sh','-ec','sing-box run -c /tmp/warp-client.json >/tmp/sing-warp.log 2>&1 &')
    time.sleep(1)
    for kind in ('tcp','udp'):
        for target in ('203.0.113.20','public.test'):
            r=probe(client,kind,target);check(kind+'-public-'+target,r['ok'],r)
        for target in ('10.80.0.245','127.0.0.1','private.test','169.254.169.254','::1','::ffff:10.80.0.245'):
            r=probe(client,kind,target);check(kind+'-private-denied-'+target,not r['ok'],r)
    for source,port,label in ((client,18081,'Xray-WARP-outbound'),(untrusted,19080,'sing-box-VLESS-SOCKS-detour')):
        for kind in ('tcp','udp'):
            for target in ('203.0.113.20','public.test'):
                r=probe(source,kind,target,proxy='127.0.0.1',proxy_port=port);check(label+'-'+kind+'-'+target,r['ok'],r)
            for target in ('10.80.0.245','private.test'):
                r=probe(source,kind,target,proxy='127.0.0.1',proxy_port=port);check(label+'-'+kind+'-private-'+target,not r['ok'],r)
    for host in ("::","public.test"):
        r=probe(client,"udp",associate_host=host);check("UDP-association-address-"+host,r["ok"],r)
    for size in (256,1200,1400):
        r=probe(client,"udp",size=size,count=20);check("UDP-20-packets-size-"+str(size),r["ok"],r)
    for c in (untrusted,peer):
        r=probe(c,'control');check(c+'-SOCKS-denied',not r['ok'],r)
    for kw in ({'fragment':1},{'close':True}):
        r=probe(client,'udp',**kw);check('invalid-UDP-'+str(kw),not r['ok'],r)
    info=json.loads(run('docker','inspect',proxy).stdout)[0]
    check('no-published-ports',not info['HostConfig'].get('PortBindings'))
    check('all-proxy-processes-unprivileged',all(s.split()[0]!='root' for s in dx(proxy,'sh','-c','ps -o user,comm | grep warp-socks').stdout.splitlines()))
    dx(proxy,'wg-quick','down','/etc/warp/wgcf-profile.conf')
    dx(proxy,'ip','route','add','203.0.113.20/32','via','10.80.0.245')
    check('direct-root-path-real',dx(proxy,'curl','-sS','--max-time','3','http://203.0.113.20:18080/',check=False).returncode==0)
    for address in ('1.1.1.1','1.0.0.1'):
        dx(proxy,'ip','route','add',address+'/32','via','10.80.0.245')
    dns=dx(proxy,'curl','-4','-sS','--max-time','4','http://public.test:18080/',check=False)
    check('root-DNS-replies-with-WARP-down',dns.returncode==0 and 'WARP-UDP-FIXTURE' in dns.stdout,{'exit':dns.returncode,'stderr':dns.stderr})
    # A real listener proves that reply allowance cannot admit unsolicited UDP.
    listener_code="import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',0)); s.settimeout(2); print(s.getsockname()[1],flush=True)\ntry: print(s.recvfrom(1024)[0].decode(),flush=True)\nexcept TimeoutError: print('BLOCKED',flush=True)"
    for source,expected in ((untrusted,'BLOCKED'),(client,'ACL-PROBE')):
        listener=subprocess.Popen(['nsenter','-t',pid(proxy),'-n','python3','-u','-c',listener_code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        children.append(listener)
        port=int(listener.stdout.readline());assert 20000<=port<=29999
        sender="import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'ACL-PROBE',('10.80.0.13',"+str(port)+"))"
        run('nsenter','-t',pid(source),'-n','python3','-c',sender)
        output,error=listener.communicate(timeout=5)
        check(('untrusted-unsolicited-UDP-denied' if source==untrusted else 'authorized-UDP-fixture-positive-control'),listener.returncode==0 and output.strip()==expected,{'output':output.strip(),'stderr':error})
    for kind in ('tcp','udp'):
        r=probe(client,kind);check(kind+'-no-leak-after-WARP-loss',not r['ok'],r)
finally:
    for container,name in ((client,'xray-warp.log'),(untrusted,'sing-warp.log')):
        if ('container',container) in made:(O/name).write_text(dx(container,'cat','/tmp/'+name,check=False).stdout)
    for p in children:
        p.terminate()
        try:p.wait(timeout=5)
        except subprocess.TimeoutExpired:p.kill();p.wait()
    if ('container',proxy) in made:
        (O/'iptables.txt').write_text(dx(proxy,'iptables-save',check=False).stdout)
    for typ,n in reversed(made):run('docker','rm','-f',n,check=False) if typ=='container' else run('docker','network','rm',n,check=False)
    print(json.dumps({'passed':sum(x['passed'] for x in rows),'total':len(rows),'cleanup':True}),flush=True)
if not rows or not all(x['passed'] for x in rows):sys.exit(1)
