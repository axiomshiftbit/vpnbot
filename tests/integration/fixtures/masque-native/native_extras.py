exec(open('/lab/native_matrix.py').read().split('\ntry:\n for host')[0].replace('results/native.json','results/extras.json'))
try:
 echo('198.51.100.23',18080);echo('198.51.100.23',18081,True)
 write(DESIRED,copy.deepcopy(BASE));supervisor=server_start();check('extra_start',wait_for(lambda:status().get('phase')=='running'))
 # A private DNS server on a public test address proves remote DNS for domain destinations.
 dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);dns.bind(('198.51.100.23',53));dns.settimeout(.2);stops.append(dns)
 def dns_loop():
  while True:
   try:
    q,peer=dns.recvfrom(4096);end=12
    while q[end]:end+=q[end]+1
    end+=5
    a=q[:2]+b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'+q[12:end]+b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'+socket.inet_aton('198.51.100.23');dns.sendto(a,peer)
   except socket.timeout:continue
   except OSError:return
 threading.Thread(target=dns_loop,daemon=True).start()
 # Generate an ordinary TCP-only WARP-compatible SOCKS backend; no real WARP container is contacted.
 warp=socket.socket();warp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);warp.bind(('10.10.0.13',1080));warp.listen(8);warp.settimeout(.2);stops.append(warp);connected=[]
 def proxy(c):
  with c:
   try:
    hello=recv(c,2);recv(c,hello[1]);c.sendall(b'\x05\x00');hdr=recv(c,4)
    if hdr[3]==1:host=socket.inet_ntop(socket.AF_INET,recv(c,4))
    elif hdr[3]==4:host=socket.inet_ntop(socket.AF_INET6,recv(c,16))
    else:host=recv(c,recv(c,1)[0]).decode()
    port=struct.unpack('!H',recv(c,2))[0]
    if hdr[1]!=1:c.sendall(b'\x05\x07\x00\x01'+bytes(6));return
    target=socket.create_connection((host,port),timeout=3);connected.append(1);c.sendall(b'\x05\x00\x00\x01'+bytes(6))
    with target:
     for _ in range(10):
      ready,_,_=select.select([target,c],[],[],4)
      if not ready:return
      for src in ready:
       data=src.recv(65535)
       if not data:return
       (c if src==target else target).sendall(data)
   except (OSError,EOFError):pass
 def warp_loop():
  while True:
   try:c,_=warp.accept();threading.Thread(target=proxy,args=(c,),daemon=True).start()
   except socket.timeout:continue
   except OSError:return
 threading.Thread(target=warp_loop,daemon=True).start()
 s=copy.deepcopy(BASE);s['settings']['egress']='warp';s['config']['routing']['rules'][-1]['outboundTag']='warp'
 check('warp_state_applied',apply(s));c=client();check('warp_tcp_uses_socks',tcp() and len(connected)>0);check('warp_udp_rejected',not udp());stop(c)
 warp.close();c=client();check('warp_failure_has_no_direct_fallback',not tcp());stop(c);check('direct_restored',apply(copy.deepcopy(BASE)))
 # Same native client with a domain destination uses the configured tunnel DNS.
 c=client();stop(c);cfg=json.loads((ROOT/'client-1080-current.json').read_text());cfg['outbounds'][0]['settings']['remoteDNS']=['198.51.100.23'];write(ROOT/'client-dns.json',cfg)
 f=open(ROOT/'dns-client.log','ab');c=subprocess.Popen(['/client-xray','run','-config','/lab/client-dns.json'],stdout=f,stderr=f);f.close();children.append(c);time.sleep(.4)
 sock=socket.create_connection(('127.0.0.1',1080),timeout=3);sock.settimeout(4);sock.sendall(b'\x05\x01\x00');recv(sock,2);host=b'echo.example.test';sock.sendall(b'\x05\x01\x00\x03'+bytes([len(host)])+host+struct.pack('!H',18080));rep=recv(sock,4);recv(sock,4 if rep[3]==1 else 16);recv(sock,2);sock.sendall(b'dns-proof');check('remote_dns_and_domain_tcp',recv(sock,9)==b'dns-proof');sock.close();stop(c)
 # Corrupted TLS input never tears down the working generation; renewal restarts it.
 before=status()['pid'];cert=(ROOT/'certs/cert_public').read_bytes();(ROOT/'certs/cert_public').write_bytes(b'invalid')
 check('corrupt_tls_preserves_current',wait_for(lambda:status().get('phase')=='error' and status().get('pid')==before));(ROOT/'certs/cert_public').write_bytes(cert);check('tls_restored',wait_for(lambda:status().get('phase')=='running'))
 # A valid certificate with the wrong key must never replace the working generation.
 key=(ROOT/'certs/cert_private').read_bytes();subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out','/lab/certs/cert_private'],check=True,capture_output=True)
 check('mismatched_key_preserves_current',wait_for(lambda:status().get('phase')=='error' and status().get('pid')==before and status().get('error')=='tls_key_mismatch'));c=client();check('mismatched_key_old_traffic_survives',wait_for(lambda:tcp(),10));stop(c);(ROOT/'certs/cert_private').write_bytes(key);check('matching_key_restored',wait_for(lambda:status().get('phase')=='running'))
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=masque.example.test','-addext','subjectAltName=DNS:masque.example.test','-keyout','/lab/certs/cert_private','-out','/lab/certs/cert_public'],check=True,capture_output=True)
 check('certificate_renewal_restarts_core',wait_for(lambda:status().get('phase')=='running' and status().get('pid')!=before));c=client();check('new_certificate_traffic',wait_for(lambda:tcp()));stop(c)
 # XMUX из профиля бота: оригинальное ядро с 26.10.17, форк с 26.10.13; старые поле не знают.
 version=subprocess.run(['/client-xray','version'],capture_output=True,text=True).stdout.split()[1]
 xmux_core=tuple(map(int,version.split('-')[0].split('.')))>=((26,10,13) if '-' in version else (26,10,17))
 cfg=json.loads((ROOT/'client-xmux.json').read_text());cfg['log']['loglevel']='debug';write(ROOT/'client-xmux.json',cfg)
 check('xmux_profile_accepted_by_client',subprocess.run(['/client-xray','run','-test','-config','/lab/client-xmux.json'],capture_output=True).returncode==0)
 open(ROOT/'client-1080.log','w').close();c=client('xmux');ok=[]
 def xmux_load():
  for _ in range(8):ok.append(tcp());ok.append(udp(size=512))
 jobs=[threading.Thread(target=xmux_load) for _ in range(4)]
 for t in jobs:t.start()
 for t in jobs:t.join()
 check('xmux_parallel_64_tcp_udp',len(ok)==64 and all(ok))
 created=lambda:(ROOT/'client-1080.log').read_text(errors='replace').count('XMUX: creating xmuxClient')
 check('xmux_tunnels_'+('3' if xmux_core else 'ignored_by_old_core'),created()==3 if xmux_core else created()==0)
 if xmux_core:
  first=created();time.sleep(62)
  for _ in range(4):ok.append(tcp())
  check('xmux_reuse_expiry_opens_new_tunnel',created()>first and all(ok[-4:]))
 check('xmux_server_alive',supervisor.poll() is None and status().get('running'));stop(c)
 check('generation_count_bounded',len(list(STATE.glob('generation-*')))<=2)
 check('core_log_bounded',(STATE/'core.log').stat().st_size<1100000)
 print('EXTRAS COMPLETED',len(RESULTS),flush=True)
finally:
 for p in reversed(children):stop(p)
 for s in stops:s.close()
