#!/usr/bin/env python3
import json,os,pathlib,socket,struct,subprocess,time
os.umask(0o077);R=pathlib.Path('/opt/vpnbot-hosted-ci/stand');O=R/'results/warp-network';O.mkdir(mode=0o700,exist_ok=True);results=[]
def run(*a,timeout=120,input=None):return subprocess.run(a,capture_output=True,text=True,timeout=timeout,input=input)
def check(n,v,detail=None):
 results.append({'name':n,'passed':bool(v),'detail':detail});(O/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if v else 'FAIL ')+n,flush=True)
def docker(c,*a,**kw):return run('docker','exec',c,*a,**kw)
def bot(a):
 p=docker('php-audit','php','/tmp/audit-driver.php',a);p.check_returncode();j=json.loads(p.stdout);check('bot-'+a,not j['warnings']);return j['result']
def curl(c='xray-audit',url='https://example.com/',timeout=8):
 start=time.monotonic()
 q=docker(c,'curl','-4','-sS','--noproxy','','-x','socks5h://10.10.0.13:1080','--max-time',str(timeout),url,timeout=timeout+10)
 with (O/'curl-details.jsonl').open('a') as f:f.write(json.dumps({'probe':len(results),'container':c,'url':url,'exit':q.returncode,'stderr':q.stderr,'seconds':time.monotonic()-start})+'\n')
 return q

def listener():return docker('warp-audit','sh','-c','pgrep -x warp-socks >/dev/null').returncode==0
def socks_ready():
 # A running process may still be loading its config. Require the actual
 # SOCKS5 greeting from an authorized client; do not retry application traffic.
 pid=run('docker','inspect','--format','{{.State.Pid}}','xray-audit').stdout.strip()
 if not pid.isdigit() or int(pid)<=0:return False
 code="import socket; s=socket.create_connection(('10.10.0.13',1080),1); s.sendall(bytes([5,1,0])); assert s.recv(2)==bytes([5,0]); s.close()"
 return run('nsenter','-t',pid,'-n','python3','-c',code,timeout=4).returncode==0

def wait_proxy():
 end=time.monotonic()+85
 while time.monotonic()<end:
  if listener() and socks_ready():return True
  time.sleep(1)
 return False
peer='vpnbot-audit-warppeer';exists=run('docker','inspect',peer).returncode==0
if not exists:
 image=docker('warp-audit','true');image=run('docker','inspect','--format','{{.Config.Image}}','warp-audit').stdout.strip()
 network=next(iter(json.loads(run('docker','inspect','--format','{{json .NetworkSettings.Networks}}','warp-audit').stdout)))
 run('docker','run','-d','--name',peer,'--network',network,'--ip','10.10.0.245','--cap-add','NET_ADMIN','--entrypoint','sh',image,'-c','sleep infinity').check_returncode()
server=docker(peer,'wg','genkey').stdout.strip();client=docker(peer,'wg','genkey').stdout.strip()
spub=run('docker','exec','-i',peer,'wg','pubkey',input=server).stdout.strip();cpub=run('docker','exec','-i',peer,'wg','pubkey',input=client).stdout.strip()
f=O/'server.key';f.write_text(server+'\n');run('docker','cp',str(f),peer+':/tmp/warp-test.key').check_returncode()
docker(peer,'sh','-c','ip link del auditwarp 2>/dev/null || true; ip link add auditwarp type wireguard; ip addr add 172.30.0.1/24 dev auditwarp; ip link set auditwarp up; iptables -t nat -C POSTROUTING -s 172.30.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 172.30.0.0/24 -o eth0 -j MASQUERADE').check_returncode()
docker(peer,'wg','set','auditwarp','private-key','/tmp/warp-test.key','listen-port','51820','peer',cpub,'allowed-ips','172.30.0.2/32').check_returncode()
conf=O/'wgcf-profile.conf';conf.write_text('[Interface]\nPrivateKey = '+client+'\nAddress = 172.30.0.2/32\nMTU = 1280\n[Peer]\nPublicKey = '+spub+'\nAllowedIPs = 0.0.0.0/0\nEndpoint = 10.10.0.245:51820\nPersistentKeepalive = 25\n')
run('docker','cp',str(conf),'warp-audit:/etc/warp/wgcf-profile.conf').check_returncode()
p=R/'bot/config/pac.json';j=json.loads(p.read_text());j.pop('warpoff',None);p.write_text(json.dumps(j))
run('docker','restart','warp-audit').check_returncode();check('controlled-peer-proxy-starts',wait_proxy())
# Исключение для UDP к локальному fixture endpoint (настоящий WARP использует публичный endpoint).
docker('warp-audit','iptables','-I','WARP_SOCKS_OUT','1','-p','udp','-d','10.10.0.245','--dport','51820','-j','RETURN').check_returncode()
hs=docker('warp-audit','wg','show','wgcf-profile','latest-handshakes').stdout;check('controlled-peer-real-handshake',any(int(s.split()[-1])>0 for s in hs.splitlines() if s.strip()))
check('controlled-peer-https',curl().returncode==0)
check('controlled-peer-http',curl(url='http://example.com/').returncode==0)
user=docker('warp-audit','sh','-c','ps -o user,comm | grep warp-socks').stdout;check('proxy-unprivileged',bool(user.strip()) and all(line.split()[0]!='root' for line in user.splitlines()))
for url,label in [('http://10.10.0.5/','adguard'),('http://10.10.0.7:8090/','panel'),('http://10.10.0.8:2375/version','docker'),('telnet://127.0.0.1:22','loopback-ssh')]:
 q=curl(url=url,timeout=3);check(label+'-denied',('SSH-' not in q.stdout if label=='loopback-ssh' else q.returncode!=0))
check('unapproved-source-denied',curl(c='vpnbot-audit-wgclient',timeout=3).returncode!=0)
docker('warp-audit','wg-quick','down','/etc/warp/wgcf-profile.conf').check_returncode();check('proxy-still-running-after-link-loss',listener());q=curl(timeout=3);check('no-direct-leak-after-link-loss',q.returncode!=0)
check('root-management-still-works',docker('warp-audit','curl','-4','-sS','--max-time','8','https://example.com/').returncode==0)
bot('warp-toggle');check('proxy-stopped-immediately-by-off',not listener())
bot('warp-toggle');check('proxy-recovers-on',wait_proxy());q=curl();check('traffic-recovers-on',q.returncode==0,{'exit':q.returncode,'stderr':q.stderr})
run('docker','restart','warp-audit').check_returncode();check('proxy-survives-restart',wait_proxy());docker('warp-audit','iptables','-I','WARP_SOCKS_OUT','1','-p','udp','-d','10.10.0.245','--dport','51820','-j','RETURN').check_returncode();check('traffic-survives-restart',curl().returncode==0)
bot('warp-toggle')
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results),'external_provider':'controlled WireGuard peer; no Cloudflare account used'}));raise SystemExit(0 if all(x['passed'] for x in results) else 1)
