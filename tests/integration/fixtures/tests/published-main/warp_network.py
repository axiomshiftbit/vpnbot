#!/usr/bin/env python3
import json,os,pathlib,socket,struct,subprocess,time
os.umask(0o077);R=pathlib.Path('/opt/vpnbot-hosted-ci/stand');O=R/'results/warp-network';O.mkdir(mode=0o700,exist_ok=True);results=[]
def run(*a,timeout=120,input=None):return subprocess.run(a,capture_output=True,text=True,timeout=timeout,input=input)
def check(n,v,detail=None):
 results.append({'name':n,'passed':bool(v),'detail':detail});(O/'results.json').write_text(json.dumps(results,indent=2));print(('PASS ' if v else 'FAIL ')+n,flush=True)
def docker(c,*a,**kw):return run('docker','exec',c,*a,**kw)
def bot(a,*more):
 p=docker('php-audit','php','/tmp/audit-driver.php',a,*more);p.check_returncode();j=json.loads(p.stdout);check('bot-'+a,not j['warnings']);return j['result']
def files():return docker('warp-audit','sh','-c','cd /etc/warp && sha256sum wgcf-profile.conf; ls -a | grep -c "^\\.bak$"').stdout.split()
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
# Сторож сам возвращает пропавший туннель; пауза между его проходами прерывается, как это делает бот.
docker('warp-audit','touch','/run/warp-kick').check_returncode();started=time.monotonic()
for _ in range(40):
 if docker('warp-audit','wg','show','wgcf-profile').returncode==0 and curl(timeout=4).returncode==0:break
 time.sleep(1)
check('watchdog-restores-lost-tunnel',curl().returncode==0,{'seconds':time.monotonic()-started})
menu=bot('warp-menu');check('menu-shows-tunnel-and-proxy',menu=={'tunnel':True,'socks':True},menu)
bot('warp-toggle');check('proxy-stopped-immediately-by-off',not listener())
check('disabled-warp-is-healthy-for-docker',docker('warp-audit','sh','/warp_probe.sh').returncode==0)
started=time.monotonic();bot('warp-toggle');check('proxy-recovers-on',wait_proxy());took=time.monotonic()-started
check('proxy-recovers-within-seconds-not-a-minute',took<30,{'seconds':took})
q=curl();check('traffic-recovers-on',q.returncode==0,{'exit':q.returncode,'stderr':q.stderr})
# Оборванная смена ключа: копия прежнего аккаунта цела, новая смена не начинается, возврат из копии работает.
before=files();docker('warp-audit','sh','-c','cd /etc/warp && mkdir -m 700 .bak && cp -p wgcf-profile.conf .bak/ && printf "# damaged\\n" >> wgcf-profile.conf').check_returncode()
blocked=bot('warp-key-blocked');check('interrupted-key-change-is-explained',blocked=={'explained':True,'buttons':1},blocked)
check('interrupted-key-change-keeps-the-copy',files()[-1]=='1' and files()[0]!=before[0])
bot('warp-backup','restore');after=files();check('backup-restores-previous-profile',after[0]==before[0] and after[-1]=='0',after)
check('proxy-works-after-backup-restore',wait_proxy() and curl().returncode==0)
run('docker','restart','warp-audit').check_returncode();check('proxy-survives-restart',wait_proxy());docker('warp-audit','iptables','-I','WARP_SOCKS_OUT','1','-p','udp','-d','10.10.0.245','--dport','51820','-j','RETURN').check_returncode();check('traffic-survives-restart',curl().returncode==0)
# ---- WARP через MASQUE. Cloudflare стенд не трогает: устройство синтетическое, его узел
# (203.0.113.77) не отвечает. Проверяется то, что от Cloudflare не зависит.
def wp(command,timeout=20):return docker('warp-audit','sh','-c',command,timeout=timeout)
def mode_file():return wp('cat /run/warp-mode 2>/dev/null').stdout.strip()
def wait_mode(want,seconds=60):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  if mode_file()==want:return True
  time.sleep(1)
 return False
def chain():return wp('iptables -S WARP_PROXY_OUT').stdout
state=bot('warp-masque-state');check('masque-supported-by-the-image',state['supported']=='' and state['mode']=='wireguard' and state['device']=='stand-sy',state)
check('wireguard-menu-offers-the-mode-switch',state['menu_mode'] and state['mode_button'] and not state['transport_button'],state)
# Узел недостижим: пробное подключение не проходит, бот отказывает, работающий WireGuard не затронут.
started=time.monotonic();switch=bot('warp-mode');check('masque-refused-when-the-endpoint-is-unreachable',switch=={'mode':'wireguard','refused':True,'switched':False,'reverted':False},switch)
check('refusal-did-not-interrupt-wireguard',listener() and mode_file()=='wireguard' and curl().returncode==0,{'seconds':time.monotonic()-started})
check('trial-connection-left-nothing-behind',wp('ls /run | grep -c masque-check').stdout.strip()=='0' and '203.0.113.77' not in chain())
# Режим задан настройками напрямую, как после восстановления из копии: контейнер обязан работать закрыто.
p=R/'bot/config/pac.json';j=json.loads(p.read_text());j['warp_mode']='masque';p.write_text(json.dumps(j))
wp('touch /run/warp-kick').check_returncode();check('container-switches-to-masque-on-the-flag',wait_mode('masque h3'))
rules=chain();check('masque-kill-switch-allows-only-the-endpoint','-A WARP_PROXY_OUT -d 203.0.113.77/32 -p udp -m udp --dport 443 -j RETURN' in rules and 'wgcf-profile' not in rules and rules.strip().endswith('-j REJECT --reject-with icmp-port-unreachable'),rules)
check('masque-has-no-wireguard-interface',wp('wg show wgcf-profile').returncode!=0)
user=wp('ps -o user,args | grep "[w]arp-socks run"').stdout;check('masque-proxy-unprivileged',bool(user.strip()) and all(line.split()[0]!='root' for line in user.splitlines()) and 'warp-socks-masque.json' in user,user)
check('masque-config-readable-by-the-proxy-only',wp('stat -c "%a %U:%G" /run/warp-socks-masque.json').stdout.strip()=='640 root:warp-proxy')
q=curl(timeout=5);check('masque-fails-closed-without-the-endpoint',q.returncode!=0,{'exit':q.returncode})
check('masque-unapproved-source-denied',curl(c='vpnbot-audit-wgclient',timeout=3).returncode!=0)
state=bot('warp-masque-state');check('masque-menu-shows-mode-device-and-transport',state['mode']=='masque' and state['menu_mode'] and state['mode_button'] and state['transport_button'],state)
# Обратно в WireGuard кнопкой бота: бот ждёт отметку сторожа, которая ставится только после рукопожатия.
switch=bot('warp-mode');check('bot-returns-to-wireguard',switch=={'mode':'wireguard','refused':False,'switched':True,'reverted':False},switch)
check('proxy-works-after-return-to-wireguard',mode_file()=='wireguard' and wait_proxy() and curl().returncode==0)
rules=chain();check('wireguard-kill-switch-restored','-A WARP_PROXY_OUT -o wgcf-profile -j RETURN' in rules and '203.0.113.77' not in rules,rules)
check('masque-config-with-the-key-removed',wp('ls /run/warp-socks-masque.json 2>/dev/null | wc -l').stdout.strip()=='0')
bot('warp-toggle')
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results),'external_provider':'controlled WireGuard peer; no Cloudflare account used'}));raise SystemExit(0 if all(x['passed'] for x in results) else 1)
