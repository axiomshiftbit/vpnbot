#!/usr/bin/env python3
"""Actual kernel traversal of both complete profiles; all frames remain in this namespace tree."""
import importlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import time

def checksum(data):
    if len(data) % 2: data += b'\0'
    value = sum(struct.unpack('!%dH' % (len(data)//2), data))
    value = (value & 65535) + (value >> 16)
    value = (value & 65535) + (value >> 16)
    return (~value) & 65535

def packet(v):
    if v['proto'] == 'arp':
        mac = bytes.fromhex(v['smac'].replace(':', ''))
        ether = bytes.fromhex(v['dmac'].replace(':', '')) + mac + b'\x08\x06'
        sender = bytes.fromhex(v.get('arp_smac', v['smac']).replace(':', ''))
        return ether + struct.pack('!HHBBH', 1, 0x800, 6, 4, v.get('op', 1)) + sender + socket.inet_aton(v['src']) + bytes(6) + socket.inet_aton(v['dst'])
    family = 6 if ':' in v['src'] else 4
    protocol = {'tcp': 6, 'udp': 17, 'icmp': 1, 'icmp6': 58}[v['proto']]
    af = socket.AF_INET6 if family == 6 else socket.AF_INET
    src, dst = (socket.inet_pton(af, v[k]) for k in ('src', 'dst'))
    if protocol == 6:
        body = struct.pack('!HHLLBBHHH', v['sport'], v['port'], 1234567, 0, 80, v.get('flags', 2), 65535, 0, 0)
        pos = 16
    elif protocol == 17:
        body = struct.pack('!HHHH', v['sport'], v['port'], 16, 0) + b'nft-test'
        pos = 6
    else:
        body = struct.pack('!BBHI', v.get('type', 128 if family == 6 else 8), v.get('code', 0), 0, 0) + b'nft-test'
        if 'nd_target' in v:
            body = struct.pack('!BBHI', v['type'], v.get('code', 0), 0, 0x60000000 if v['type'] == 136 else 0) + socket.inet_pton(socket.AF_INET6, v['nd_target'])
            if v['type'] == 136: body += b'\x02\x01' + bytes.fromhex(v['smac'].replace(':', ''))
        pos = 2
    pseudo = src + dst + (struct.pack('!L3xB', len(body), protocol) if family == 6 else struct.pack('!BBH', 0, protocol, len(body)))
    value = checksum((pseudo if protocol != 1 else b'') + body)
    body = body[:pos] + struct.pack('!H', value or 65535) + body[pos+2:]
    if family == 6:
        if v.get('extension'):
            body = bytes([protocol, 0, 0 if v['extension'] == 'rh0' else 1, 0 if v['extension'] == 'rh0' else 4, 0, 0, 0, 0]) + body
            protocol = 43 if v['extension'] == 'rh0' else 60
        ip = struct.pack('!LHBB', 6 << 28, len(body), protocol, v.get('hop', 64)) + src + dst
    else:
        options = b'\x01\x01\x01\x00' if v.get('options') else b''
        ip = struct.pack('!BBHHHBBH', 69 + len(options)//4, 0, 20+len(options)+len(body), v['sport'], v.get('frag', 0), 64, protocol, 0) + src + dst + options
        ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return bytes.fromhex(v['dmac'].replace(':', '')) + bytes.fromhex(v['smac'].replace(':', '')) + struct.pack('!H', 0x86dd if family == 6 else 0x800) + ip + body

if len(sys.argv) > 1 and sys.argv[1] == 'send':
    v = json.loads(sys.argv[2])
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((v['dev'], 0))
    raw=packet(v)
    frames=[raw]
    if v.get('fragments'):
        assert ':' not in v['src'] and v['proto']=='udp'
        frames=[]
        for offset, chunk in [(0,raw[34:42]),(1,raw[42:])]:
            header=raw[14:34]
            header=header[:2]+struct.pack('!H',20+len(chunk))+header[4:6]+struct.pack('!H',0x2000 if offset==0 else offset)+header[8:10]+b'\0\0'+header[12:]
            header=header[:10]+struct.pack('!H',checksum(header))+header[12:]
            frames.append(raw[:14]+header+chunk)
    for _ in range(v.get('count', 1)):
        for frame in frames:s.send(frame)
    sys.exit(0)

if len(sys.argv)>1 and sys.argv[1]=='echo':
    s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',int(sys.argv[2]) if len(sys.argv)>2 else 443));s.listen(8)
    c,_=s.accept()
    while True:
        data=c.recv(32)
        if not data:break
        c.sendall(data)
    sys.exit(0)

if len(sys.argv)>1 and sys.argv[1]=='flow':
    s=socket.socket();s.settimeout(1);s.bind((sys.argv[4] if len(sys.argv)>4 else '11.77.0.2',int(sys.argv[2])))
    try:
        s.connect((sys.argv[3] if len(sys.argv)>3 else '11.77.0.10',int(sys.argv[5]) if len(sys.argv)>5 else 443));print('connected',flush=True)
        for line in sys.stdin:
            s.sendall(b'nft-ping');print('ok' if s.recv(32)==b'nft-ping' else 'bad',flush=True)
    except OSError:print('blocked',flush=True)
    sys.exit(0)

assert os.environ.get('VPNBOT_NFT_LAB') == '1' and os.geteuid() == 0 and os.getpid() == 1
assert os.readlink('/proc/self/ns/net') != os.environ['VPNBOT_PARENT_NETNS']
sys.path.insert(0, '/src/scripts')
rows, processes = [], []
completed = False
serial = 30000

def run(args, **kw):
    p = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=20, **kw)
    if p.returncode: raise RuntimeError('command failed: '+str(args[0])+': '+p.stderr[:2000])
    return p.stdout

def nft(text): return run(['nft', '-f', '-'], input=text)

def peer(name, bridge=None):
    p = subprocess.Popen(['unshare', '-n', 'sleep', '600'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    processes.append(p)
    time.sleep(.08)
    run(['ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', 'p-'+name])
    run(['ip', 'link', 'set', 'p-'+name, 'netns', p.pid])
    run(['ip', 'link', 'set', name, 'up'])
    if bridge: run(['ip', 'link', 'set', name, 'master', bridge])
    run(['nsenter', '-t', p.pid, '-n', 'ip', 'link', 'set', 'p-'+name, 'up'])
    info = json.loads(run(['nsenter', '-t', p.pid, '-n', 'ip', '-j', 'link', 'show', 'p-'+name]))[0]
    hostinfo = json.loads(run(['ip', '-j', 'link', 'show', name]))[0]
    return {'pid': p.pid, 'dev': 'p-'+name, 'mac': info['address'], 'hostmac': hostinfo['address'], 'index': hostinfo['ifindex'], 'host': name}

def source(profile):
    text = Path('/src/nftables/'+profile+'.conf').read_text()
    text = re.sub(r'(define PUBLIC_IP\s*=\s*)[^\s#]+', r'\g<1>11.77.0.10', text)
    for directory, name, define, number, elements in [
        ('tg','tg','TG',101,'11.77.0.5 : $TG'),
        ('asn_nft','asn','ASN',102,'11.77.0.2 : $ASN, 11.77.0.4 : $ASN'),
        ('rkn','rkn','BLACKLIST',103,'11.77.0.4 : $BLACKLIST, 11.77.0.6 : $BLACKLIST'),
        ('my_server','my_server','MY_SERVER',104,'11.77.0.3 : $MY_SERVER, 11.77.0.6 : $MY_SERVER')]:
        text = re.sub(r'include "/opt/maxmind/list/'+directory+r'/geoip-def-[^"]+"', 'define '+define+' = '+str(number), text)
        text = text.replace('include "/opt/maxmind/list/'+directory+'/geoip-ipv4.nft"', 'map '+name+' { type ipv4_addr : mark; flags interval; elements = { '+elements+' }; }')
    # Optional runtime guards tested explicitly below with their real renderers.
    text = re.sub(r'^include "/etc/[^\n]+$', '', text, flags=re.M)
    assert not re.search(r'^\s*include ', text, re.M)
    return text

def witness():
    nft('''table inet audit_witness {
 counter arrived { }
 chain input { type filter hook input priority 3000; policy accept; counter name arrived drop; }
 chain forward { type filter hook forward priority 3000; policy accept; counter name arrived drop; }
}
table bridge audit_witness {
 counter arrived { }
 chain forward { type filter hook forward priority 3000; policy accept; counter name arrived drop; }
}
table arp audit_witness {
 counter arrived { }
 chain input { type filter hook input priority 3000; policy accept; counter name arrived drop; }
}''')

def origin_denied():
    data=json.loads(run(['nft','-j','list','chain','bridge','vpnbot_origin','denied']))
    return sum(e['counter']['packets'] for x in data['nftables'] for e in x.get('rule',{}).get('expr',[]) if 'counter' in e)

def check(label, endpoint, src, dst, port=22, proto='tcp', expected=False, dmac=None, smac=None, origin_drop=None, maximum=None, **extra):
    global serial
    serial += 1
    before=origin_denied() if origin_drop is not None else 0
    for family in ('inet', 'bridge', 'arp'): run(['nft','reset','counter',family,'audit_witness','arrived'])
    # Count only this probe. Kernel-generated NDP/ARP from peer namespaces must
    # never turn a denied TCP/UDP probe into an apparent successful bypass.
    rules=[]
    for family,chain in [('inet','input'),('inet','forward'),('bridge','forward'),('arp','input')]:
        rules.append('flush chain '+family+' audit_witness '+chain)
        if proto=='arp':
            match='arp saddr ip '+src+' arp daddr ip '+dst
            if family=='inet':continue
        else:
            if family=='arp':continue
            match=('ip6' if ':' in src else 'ip')+' saddr '+src
            if proto in ('tcp','udp'):match+=' '+proto+' sport '+str(serial)
            else:match+=' '+('icmpv6' if proto=='icmp6' else 'icmp')+' type '+str(extra.get('type',128 if proto=='icmp6' else 8))
        rules.append('add rule '+family+' audit_witness '+chain+' '+match+' counter name arrived drop')
    nft('\n'.join(rules))
    v = dict(src=src, dst=dst, port=port, proto=proto, sport=serial, dev=endpoint['dev'], smac=smac or endpoint['mac'], dmac=dmac or endpoint['hostmac'], **extra)
    run(['nsenter','-t',endpoint['pid'],'-n','python3','-B','/probes/packets.py','send',json.dumps(v)])
    time.sleep(.025)
    counts = {}
    for family in ('inet','bridge','arp'):
        data=json.loads(run(['nft','-j','list','counter',family,'audit_witness','arrived']))
        counts[family]=sum(x.get('counter',{}).get('packets',0) for x in data['nftables'])
    observed=any(counts.values())
    result=dict(case=label,expected=expected,accepted=observed,passed=observed==expected,counters=counts)
    if maximum is not None:
        result['maximum']=maximum
        result['passed']=result['passed'] and sum(counts.values())<=maximum
    if origin_drop is not None:
        result['origin_dropped']=origin_denied()-before
        result['passed']=result['passed'] and bool(result['origin_dropped'])==origin_drop
    rows.append(result)

try:
    run(['ip','link','set','lo','up'])
    wan=peer('eth0')
    run(['ip','address','add','11.77.0.10/24','dev','eth0'])
    run(['ip','address','add','2606:4700:77::10/64','dev','eth0','nodad'])
    run(['ip','route','add','default','via','11.77.0.1'])
    for key in ('ip_forward','conf/all/rp_filter','conf/default/rp_filter','conf/eth0/rp_filter'):
        Path('/proc/sys/net/ipv4/'+key).write_text('1' if key=='ip_forward' else '0')
    run(['ip','link','add','br-vpnbot0','type','bridge'])
    run(['ip','link','set','br-vpnbot0','up'])
    run(['ip','address','add','10.10.0.1/24','dev','br-vpnbot0'])
    good=peer('v-good','br-vpnbot0'); bad=peer('v-bad','br-vpnbot0')
    bridge_mac=json.loads(run(['ip','-j','link','show','br-vpnbot0']))[0]['address']
    for x in range(2,28):
        run(['ip','neigh','replace','10.10.0.'+str(x),'lladdr',bad['mac'] if x==6 else good['mac'],'nud','permanent','dev','br-vpnbot0'])
    text=source('nftables')
    run(['nft','-c','-f','-'],input=text); nft(text); witness()
    rows.append(dict(case='main-full-profile-load',passed=True))
    ports=[(80,'tcp'),(443,'tcp'),(443,'udp'),(9443,'tcp'),(5443,'udp'),(51820,'udp'),(51821,'udp'),(2443,'tcp'),(2443,'udp'),(1194,'tcp'),(1194,'udp'),(500,'udp'),(4500,'udp'),(8388,'tcp'),(8388,'udp'),(7443,'tcp'),(3443,'tcp'),(24445,'tcp'),(24445,'udp'),(9443,'udp'),(24447,'tcp'),(24448,'tcp'),(24449,'tcp'),(24449,'udp')]
    for tag,src,allow in [('asn','11.77.0.2',True),('own','11.77.0.3',True),('alien','11.77.0.200',False),('blacklisted-asn','11.77.0.4',False),('own-blacklist-override','11.77.0.6',True)]:
        check('main-'+tag+'-ssh',wan,src,'11.77.0.10',expected=allow)
        for port,proto in ports: check('main-'+tag+'-'+proto+'-'+str(port),wan,src,'11.77.0.10',port,proto,allow)
    for port in (53,853,8090,2375,2376,9091,10085,8443,10443,10890):
        for proto in ('tcp','udp'): check('main-unpublished-'+proto+'-'+str(port),wan,'11.77.0.2','11.77.0.10',port,proto)
    for src in ('127.0.0.2','10.10.0.7','10.0.1.2','172.17.0.2','192.168.1.2','0.0.0.0','100.64.0.2','169.254.1.2','224.0.0.1','240.0.0.1','11.77.0.10'):
        check('main-spoof-'+src,wan,src,'11.77.0.10')
    for flags in (0,1,3,4,6,16,41): check('main-tcp-flags-'+str(flags),wan,'11.77.0.2','11.77.0.10',flags=flags)
    check('main-ip-options',wan,'11.77.0.2','11.77.0.10',options=True)
    check('main-fragments-trusted',wan,'11.77.0.2','11.77.0.10',51820,'udp',True,fragments=True)
    check('main-fragments-alien',wan,'11.77.0.200','11.77.0.10',51820,'udp',fragments=True)
    check('main-fragments-spoof',wan,'10.10.0.7','11.77.0.10',51820,'udp',fragments=True)
    for target,allow in [('11.77.0.10',True),('10.10.0.1',False),('127.0.0.1',False),('10.0.1.2',False)]:
        check('main-arp-target-'+target,wan,'11.77.0.2',target,proto='arp',expected=allow,dmac='ff:ff:ff:ff:ff:ff')
    check('main-arp-source-spoof',wan,'10.10.0.7','11.77.0.10',proto='arp',dmac='ff:ff:ff:ff:ff:ff')
    for dst in ('127.0.0.1','10.10.0.7','10.10.0.8','10.0.1.2','11.77.0.11'):
        check('main-direct-target-'+dst,wan,'11.77.0.2',dst,2375)
    for dmac in ('ff:ff:ff:ff:ff:ff','01:00:5e:00:00:01','02:01:02:03:04:05'):
        check('main-l2-'+dmac,wan,'11.77.0.2','11.77.0.10',dmac=dmac)
    for src in ('2606:4700:77::2','::1','fc00::2','2606:4700:77::10'):
        for port in (22,443,8090): check('main-ipv6-'+src+'-'+str(port),wan,src,'2606:4700:77::10',port)
    # ICMP errors reach the host only as related to a tracked flow; NDP is
    # on-link (hop limit 255) and rate-limited.
    check('main-ipv4-unsolicited-icmp-error',wan,'11.77.0.2','11.77.0.10',proto='icmp',type=3,code=4)
    check('main-ipv6-unsolicited-packet-too-big',wan,'2606:4700:77::2','2606:4700:77::10',proto='icmp6',type=2)
    check('main-ipv6-neighbor-solicit-accepted',wan,'2606:4700:77::2','2606:4700:77::10',proto='icmp6',type=135,hop=255,nd_target='2606:4700:77::10',expected=True)
    check('main-ipv6-neighbor-solicit-offlink',wan,'2606:4700:77::2','2606:4700:77::10',proto='icmp6',type=135,hop=64,nd_target='2606:4700:77::10')
    check('main-ipv6-neighbor-solicit-flood-limited',wan,'2606:4700:77::2','2606:4700:77::10',proto='icmp6',type=135,hop=255,nd_target='2606:4700:77::10',expected=True,count=1000,maximum=400)
    nft('add element ip filter asn { 11.77.0.7 : 102 }')
    check('main-trusted-syn-burst-limited',wan,'11.77.0.7','11.77.0.10',443,expected=True,count=1000,maximum=400)
    # Actual established flow: distinguish a new-source ACL from live revocation.
    for family,chain in [('inet','input'),('inet','forward'),('bridge','forward'),('arp','input')]:
        nft('flush chain '+family+' audit_witness '+chain)
    for endpoint,address,gateway in [(wan,'11.77.0.2/24','11.77.0.10'),(good,'10.10.0.10/24','10.10.0.1')]:
        prefix=['nsenter','-t',endpoint['pid'],'-n']
        run(prefix+['ip','address','add',address,'dev',endpoint['dev']])
        run(prefix+['ip','route','add','default','via',gateway])
    echo=subprocess.Popen(['nsenter','-t',str(good['pid']),'-n','python3','-B','/probes/packets.py','echo'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);processes.append(echo)
    time.sleep(.1)
    flow=subprocess.Popen(['nsenter','-t',str(wan['pid']),'-n','python3','-B','/probes/packets.py','flow','41000'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True);processes.append(flow)
    started=flow.stdout.readline().strip()=='connected'
    rows.append(dict(case='main-real-tcp-dnat-connection',passed=started))
    echo_wan=subprocess.Popen(['nsenter','-t',str(wan['pid']),'-n','python3','-B','/probes/packets.py','echo'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);processes.append(echo_wan)
    time.sleep(.1)
    outgoing=subprocess.Popen(['python3','-B','/probes/packets.py','flow','41002','11.77.0.2','11.77.0.10'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True);processes.append(outgoing)
    outgoing_ready=outgoing.stdout.readline().strip()=='connected'
    rows.append(dict(case='main-outgoing-connection-control',passed=outgoing_ready))
    echo_host=subprocess.Popen(['python3','-B','/probes/packets.py','echo','22'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);processes.append(echo_host)
    time.sleep(.1)
    hostflow=subprocess.Popen(['nsenter','-t',str(wan['pid']),'-n','python3','-B','/probes/packets.py','flow','41003','11.77.0.10','11.77.0.2','22'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True);processes.append(hostflow)
    host_ready=hostflow.stdout.readline().strip()=='connected'
    rows.append(dict(case='main-input-tcp-connection-control',passed=host_ready))
    if started:
        flow.stdin.write('probe\n');flow.stdin.flush();initial=flow.stdout.readline().strip()=='ok'
        rows.append(dict(case='main-real-tcp-return-path',passed=initial))
        nft('add element ip filter rkn { 11.77.0.2 : 103 }')
        flow.stdin.write('probe\n');flow.stdin.flush();alive=flow.stdout.readline().strip()=='ok'
        rows.append(dict(case='main-blacklist-existing-flow-revoked',passed=not alive,accepted=alive))
        if host_ready:
            hostflow.stdin.write('probe\n');hostflow.stdin.flush();host_alive=hostflow.stdout.readline().strip()=='ok'
            rows.append(dict(case='main-blacklist-existing-input-revoked',passed=not host_alive,accepted=host_alive))
        if outgoing_ready:
            outgoing.stdin.write('probe\n');outgoing.stdin.flush();outgoing_alive=outgoing.stdout.readline().strip()=='ok'
            rows.append(dict(case='main-blacklist-outgoing-reply-retained',passed=outgoing_alive))
        new=run(['nsenter','-t',str(wan['pid']),'-n','python3','-B','/probes/packets.py','flow','41001'],input='probe\n')
        rows.append(dict(case='main-blacklist-new-flow-denied',passed=new.strip()=='blocked'))
        nft('delete element ip filter rkn { 11.77.0.2 : 103 }')
    flow.terminate();flow.wait(timeout=3);echo.terminate();echo.wait(timeout=3)
    outgoing.terminate();outgoing.wait(timeout=3);echo_wan.terminate();echo_wan.wait(timeout=3)
    hostflow.terminate();hostflow.wait(timeout=3);echo_host.terminate();echo_host.wait(timeout=3)
    # These are separate trust-boundary controls, before and after the real guard.
    check('main-untrusted-container-api-block',bad,'10.10.0.6','10.10.0.8',2375,dmac=good['mac'])
    check('main-php-container-api-allow',good,'10.10.0.7','10.10.0.8',2375,expected=True,dmac=bad['mac'])
    check('main-without-origin-spoof-control',bad,'10.10.0.7','10.10.0.8',2375,expected=True,dmac=good['mac'])
    origin=importlib.import_module('container_origin_guard')
    endpoints=[dict(bridge='br-vpnbot0',host=e['host'],index=e['index'],mac=e['mac'],ipv4=ips,ipv6=[],routed=[]) for e,ips in [(good,['10.10.0.7']),(bad,['10.10.0.6'])]]
    nft(origin.render(['br-vpnbot0'],endpoints))
    check('main-origin-source-spoof-block',bad,'10.10.0.7','10.10.0.8',2375,dmac=good['mac'])
    check('main-origin-mac-spoof-block',bad,'10.10.0.7','10.10.0.8',2375,dmac=good['mac'],smac=good['mac'])
    check('main-origin-valid-php-allow',good,'10.10.0.7','10.10.0.8',2375,expected=True,dmac=bad['mac'])
    for label,src,extra,allow in [('valid','10.10.0.6',{},True),('ip-spoof','10.10.0.7',{},False),('mac-spoof','10.10.0.6',{'arp_smac':good['mac']},False)]:
        check('main-origin-arp-'+label,bad,src,'10.10.0.8',proto='arp',expected=allow,dmac=good['mac'],origin_drop=not allow,**extra)
    local6=origin.mac_linklocal(bad['mac'])
    for label,target,hop,denied in [('valid',local6,255,False),('forged-target','fe80::1234',255,True),('invalid-hop',local6,64,True)]:
        check('main-origin-ndp-'+label,bad,local6,'ff02::1',proto='icmp6',type=136,hop=hop,nd_target=target,dmac=good['mac'],origin_drop=denied)
    check('main-origin-router-advert-block',bad,local6,'ff02::1',proto='icmp6',type=134,hop=255,dmac=good['mac'],origin_drop=True)
    text=source('noda'); run(['nft','-c','-f','-'],input=text); nft(text); witness()
    rows.append(dict(case='node-full-profile-load',passed=True))
    for tag,src,allow in [('asn','11.77.0.2',True),('own','11.77.0.3',True),('alien','11.77.0.200',False)]:
        check('node-before-install-'+tag+'-ssh',wan,src,'11.77.0.10',expected=allow)
        for port,proto in [(443,'tcp'),(80,'tcp'),(8443,'tcp'),(51820,'udp')]:
            check('node-before-install-'+tag+'-'+str(port),wan,src,'11.77.0.10',port,proto)
    node=importlib.import_module('node_config')
    host=dict(public4='11.77.0.10',public6='2606:4700:77::10',sources=['11.77.0.3','2606:4700:77::3'],admins=['11.77.0.3'],routers=[],ssh_ports=[22],ssh_networks=['11.77.0.2/32'],interface='eth0',uid=995,gid=995,cover_uid=997,awg_uid=994)
    nft(node.firewall(dict(transport='reality',family=4,core='origin',domain='',mask='mask.example.test'),host))
    for version,public,own,alien in [(4,'11.77.0.10','11.77.0.3','11.77.0.200'),(6,'2606:4700:77::10','2606:4700:77::3','2606:4700:77::200')]:
        for tag,src,allow in [('own',own,True),('alien',alien,False)]:
            check('node-guard-v'+str(version)+'-'+tag+'-vpn',wan,src,public,443,expected=allow)
            for port in (80,8080,8443,8090,2375): check('node-guard-v'+str(version)+'-'+tag+'-closed-'+str(port),wan,src,public,port)
    nft('add element inet vpnbot_node acme_http { 80 timeout 2s }')
    check('node-acme-window-open',wan,'11.77.0.200','11.77.0.10',80,expected=True)
    time.sleep(2.1)
    check('node-acme-window-expired',wan,'11.77.0.200','11.77.0.10',80)
    check('node-v6-destination-options-trusted',wan,'2606:4700:77::3','2606:4700:77::10',443,expected=True,extension='dest')
    check('node-v6-destination-options-alien',wan,'2606:4700:77::200','2606:4700:77::10',443,extension='dest')
    check('node-v6-routing-header-zero',wan,'2606:4700:77::3','2606:4700:77::10',443,extension='rh0')
    completed = True
finally:
    for p in reversed(processes):
        p.terminate()
        try: p.wait(timeout=3)
        except subprocess.TimeoutExpired: p.kill();p.wait()
    print(json.dumps(dict(cases=rows,passed=completed and bool(rows) and all(r['passed'] for r in rows),processes_cleaned=len(processes),namespace='unshare-net-mount-pid-chroot',boundary='kernel filter traversal; application authentication is not exercised')))
if not completed or not rows or not all(r['passed'] for r in rows):sys.exit(1)
