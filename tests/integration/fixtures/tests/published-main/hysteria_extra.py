#!/usr/bin/env python3
import copy,json,pathlib,time
import proxy_helpers as h
h.OUT=h.ROOT/'results/hy-extra';h.OUT.mkdir(mode=0o700,exist_ok=True)
def bot(a):
 previous=h.run('docker','exec','hysteria-audit','pgrep','-x','hysteria').stdout if a in ['hy-init','hy-obfs'] else None
 r=h.run('docker','exec','php-audit','php','/tmp/audit-driver.php',a,timeout=90);r.check_returncode();v=json.loads(r.stdout);h.check('bot-'+a,not v['warnings'])
 if previous is not None:
  deadline=time.monotonic()+20
  while time.monotonic()<deadline:
   current=h.run('docker','exec','hysteria-audit','pgrep','-x','hysteria').stdout
   if current.strip() and current!=previous:break
   time.sleep(.2)
  else:raise RuntimeError('Hysteria did not apply settings')
  time.sleep(.25)
def auth():bot('hy-export');return json.loads((h.ROOT/'bot/logs/audit-hy.json').read_text())
def node(kind,a):
 if kind=='mihomo':
  n={'type':'hysteria2','server':'10.10.0.17','port':443,'password':a['password'],'sni':'vpnbot.test','udp':True}
  if a['obfs']:n.update(obfs='salamander',**{'obfs-password':a['obfs']})
 else:
  n={'type':'hysteria2','server':'10.10.0.17','server_port':443,'password':a['password'],'tls':{'enabled':True,'server_name':'vpnbot.test','certificate_path':'/tmp/audit-proxy-ca.crt'}}
  if a['obfs']:n['obfs']={'type':'salamander','password':a['obfs']}
 return n
h.run('docker','cp',str(h.ROOT/'bot/certs/cert_public'),h.C+':/tmp/audit-proxy-ca.crt').check_returncode()
controlled_connected=False
network_before=None
def default_route(pid):
 r=h.run('nsenter','-t',str(pid),'-n','ip','-j','route','show','default');r.check_returncode()
 return json.loads(r.stdout)
try:
 meta=json.loads(h.run('docker','inspect','hysteria-audit').stdout)[0]
 pid=meta['State']['Pid'];network_before=default_route(pid)
 if 'vpnbot-protocol-test' not in meta['NetworkSettings']['Networks']:
  h.run('docker','network','connect','--gw-priority','-1','vpnbot-protocol-test','hysteria-audit').check_returncode();controlled_connected=True
 network_after=default_route(pid)
 h.check('controlled-network-preserves-default',network_before==network_after and network_before[0]['gateway']=='10.10.0.1')
 (h.OUT/'controlled-network.json').write_text(json.dumps({'before':network_before,'after':network_after,'connected_by_test':controlled_connected},indent=2))
 old_packet=r"b'\x00\x00\x00\x01\x01\x01\x01\x01\x00\x35'"
 new_packet=r"b'\x00\x00\x00\x01\x0b\x4d\x00\x02\x27\x45'"
 assert h.UDP_ONE_SHOT.count(old_packet)==1
 controlled_udp=h.UDP_ONE_SHOT.replace(old_packet,new_packet)
 for obfs in [False,True]:
  a=auth()
  if bool(a['obfs'])!=obfs:bot('hy-obfs');a=auth()
  for kind in ['sing-box','mihomo']:
   label=kind+('-salamander' if obfs else '-quic');n=node(kind,a)
   if not h.start(kind,label,h.profile(kind,copy.deepcopy(n))):continue
   r=h.http('https://example.com/');h.save(label,r);h.check(label+'-https',r.returncode==0 and 'Example Domain' in r.stdout)
   r=h.exe('python3','-c',h.UDP,timeout=15);h.save(label+'-udp',r)
   if r.returncode:h.save(label+'-udp-client',h.exe('cat','/tmp/audit-proxy.log'))
   h.check(label+'-udp',r.returncode==0)
   r=h.exe('python3','-c',controlled_udp,timeout=15);h.save(label+'-controlled-udp',r);h.check(label+'-controlled-udp',r.returncode==0)
   if obfs:
    bad=copy.deepcopy(a);bad['obfs']='wrong-salamander-key';h.start(kind,label+'-bad-obfs',h.profile(kind,node(kind,bad)));r=h.http('https://example.com/',4);h.check(label+'-wrong-obfs-rejected',r.returncode!=0)
   h.start(kind,label+'-old',h.profile(kind,copy.deepcopy(n)));bot('hy-init');r=h.http('https://example.com/',4);h.check(label+'-old-password-rejected',r.returncode!=0)
   a=auth();h.start(kind,label+'-new',h.profile(kind,node(kind,a)));r=h.http('https://example.com/');h.check(label+'-new-password-works',r.returncode==0 and 'Example Domain' in r.stdout)
finally:
 h.stop()
 if controlled_connected:
  h.run('docker','network','disconnect','vpnbot-protocol-test','hysteria-audit').check_returncode()
  h.check('controlled-network-cleanup',default_route(pid)==network_before)
print(json.dumps({'passed':sum(x['passed'] for x in h.results),'total':len(h.results)}))
raise SystemExit(0 if all(x['passed'] for x in h.results) else 1)
