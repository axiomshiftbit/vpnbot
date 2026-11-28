#!/usr/bin/env python3
"""Packet tests for the minimal node, entirely inside disposable namespaces."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import re


def run(args, **kwargs):
    return subprocess.run(list(map(str, args)), capture_output=True, text=True, **kwargs)


def listener(address, port):
    server = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if ':' in address:
        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    server.bind((address, port))
    server.listen(16)
    while True:
        conn, _ = server.accept()
        with conn:
            conn.sendall(b'node-ok')


def datagram_listener(address, port):
    sock = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_DGRAM)
    if ':' in address:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((address, port))
    while True:
        body, remote = sock.recvfrom(2048)
        sock.sendto(body, remote)


if len(sys.argv) > 1:
    action, value = sys.argv[1], json.loads(sys.argv[2])
    if action == 'listen':
        if value.get('uid'):
            os.setgroups([])
            os.setgid(value['uid'])
            os.setuid(value['uid'])
        for address, port in value['sockets']:
            threading.Thread(target=datagram_listener if value.get('udp') else listener, args=(address, port), daemon=True).start()
        time.sleep(300)
    elif action == 'burst':
        # Unanswered half-open SYNs: nft counts each first SYN before any listen queue.
        sockets = []
        for _ in range(value['count']):
            conn = socket.socket(socket.AF_INET6 if ':' in value['target'] else socket.AF_INET)
            conn.setblocking(False)
            conn.bind((value['source'], 0))
            conn.connect_ex((value['target'], value['port']))
            sockets.append(conn)
        time.sleep(.5)  # Before the first SYN retransmission (1 s).
        sys.exit(0)
    elif action in ('connect', 'datagram'):
        if value.get('uid'):
            os.setgroups([])
            os.setgid(value['uid'])
            os.setuid(value['uid'])
        try:
            conn = socket.socket(socket.AF_INET6 if ':' in value['target'] else socket.AF_INET, socket.SOCK_DGRAM if action == 'datagram' else socket.SOCK_STREAM)
            conn.settimeout(.6)
            if value.get('ip_options'):
                conn.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, b'\x01\x01\x01\x00')
            if value.get('source'):
                conn.bind((value['source'], 0))
            conn.connect((value['target'], value['port']))
            if action == 'datagram': conn.send(b'node-ok')
            sys.exit(0 if conn.recv(32) == b'node-ok' else 1)
        except OSError:
            sys.exit(1)
    sys.exit(0)

if os.geteuid() != 0 or os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
    raise SystemExit('Run as root in a separate network namespace')
sys.path.insert(0, str(Path(os.environ['NODE_SOURCE_DIR'])/'scripts'))
spec = importlib.util.spec_from_file_location('node_config', Path(os.environ['NODE_SOURCE_DIR'])/'scripts/node_config.py')
node = importlib.util.module_from_spec(spec)
spec.loader.exec_module(node)
results, processes = [], []
script = str(Path(__file__).resolve())


def check(label, ok):
    results.append({'case': label, 'ok': bool(ok)})
    print(('PASS ' if ok else 'FAIL ') + label, flush=True)
    if not ok:
        raise AssertionError(label)


def connect(address, port, source='', uid=0, remote=False, ip_options=False, udp=False):
    args = (['nsenter', '-t', str(peer.pid), '-n'] if remote else [])
    result = run(args + [sys.executable, script, 'datagram' if udp else 'connect', json.dumps(dict(target=address, port=port, source=source, uid=uid, ip_options=ip_options))])
    return result.returncode == 0


def syn_counters(version):
    counts = {'accept': 0, 'drop': 0}
    for item in json.loads(run(['nft', '-j', 'list', 'chain', 'inet', 'vpnbot_node', f'syn{version}'], check=True).stdout)['nftables']:
        expressions = item.get('rule', {}).get('expr', [])
        packets = next((e['counter']['packets'] for e in expressions if 'counter' in e), 0)
        counts['accept' if any('accept' in e for e in expressions) else 'drop'] += packets
    return counts


def syn_burst(version, address, source, count):
    # Anonymous rule counters are not reset by 'nft reset counters': use deltas.
    before = syn_counters(version)
    run(['nsenter', '-t', str(peer.pid), '-n', sys.executable, script, 'burst',
         json.dumps(dict(target=address, port=443, source=source, count=count))], check=True, timeout=30)
    after = syn_counters(version)
    return after['accept']-before['accept'], after['drop']-before['drop']


def start_sockets(sockets, remote=False, uid=0, udp=False):
    args = (['nsenter', '-t', str(peer.pid), '-n'] if remote else [])
    process = subprocess.Popen(args + [sys.executable, script, 'listen', json.dumps(dict(sockets=sockets, uid=uid, udp=udp))],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    processes.append(process)


try:
    peer = subprocess.Popen(['unshare', '-n', 'sleep', '300'])
    processes.append(peer)
    time.sleep(.2)
    run(['ip', 'link', 'add', 'eth0', 'type', 'veth', 'peer', 'name', 'peer0'], check=True)
    run(['ip', 'link', 'set', 'peer0', 'netns', peer.pid], check=True)
    for prefix, interface, addresses in [
        ([], 'eth0', ['11.77.0.4/24', '2606:4700:4700::1111/64', '10.77.0.4/24', 'fd42::4/64']),
        (['nsenter', '-t', str(peer.pid), '-n'], 'peer0',
         ['11.77.0.2/24', '11.77.0.3/24', '11.77.0.200/24', '11.77.0.201/24', '11.77.0.128/24',
          '2606:4700:4700::2/64', '2606:4700:4700::3/64', '2606:4700:4700::200/64', '2606:4700:4700::201/64',
          '2620:fe::fe/128', '10.77.0.2/24', 'fd42::2/64'])]:
        run(prefix + ['ip', 'link', 'set', 'lo', 'up'], check=True)
        run(prefix + ['ip', 'link', 'set', interface, 'up'], check=True)
        for address in addresses:
            run(prefix + ['ip', 'address', 'add', address, 'dev', interface] + (['nodad'] if ':' in address else []), check=True)
    run(['ip', '-6', 'route', 'add', '2620:fe::fe/128', 'via', '2606:4700:4700::2'], check=True)
    start_sockets([(ip, port) for ip in ('0.0.0.0', '::') for port in (8443, 8080)], uid=995)
    start_sockets([(ip, 2222) for ip in ('0.0.0.0', '::')])
    start_sockets([(ip, 18080) for ip in ('11.77.0.128', '2620:fe::fe', '10.77.0.2', 'fd42::2')], remote=True)
    start_sockets([('127.0.0.1', 18080)])
    start_sockets([('0.0.0.0', 9443)], uid=997)
    start_sockets([('0.0.0.0', 9444)], uid=995)
    start_sockets([('11.77.0.4', 51830), ('2606:4700:4700::1111', 51830)], uid=995, udp=True)
    start_sockets([('11.77.0.4', 51831), ('2606:4700:4700::1111', 51831)], uid=994, udp=True)
    time.sleep(.3)
    options = dict(transport='reality', family=4, core='origin', domain='', mask='mask.example.test')
    host = dict(public4='11.77.0.4', public6='2606:4700:4700::1111',
                sources=['11.77.0.2', '2606:4700:4700::2'], admins=['11.77.0.3', '2606:4700:4700::3'],
                routers=[], ssh_ports=[2222], interface='eth0', uid=995, gid=995,
                ssh_networks=['11.77.0.201/32', '2606:4700:4700::201/128'], cover_uid=997, awg_uid=994)
    if os.environ.get('NODE_BASE_FIREWALL'):
        # Optional actual installation profile; only documentation addresses
        # and its external map includes are substituted inside this namespace.
        base = Path(os.environ['NODE_BASE_FIREWALL']).read_text().replace('ens3', 'eth0')
        base = re.sub(r'define PUBLIC_IP = \S+', 'define PUBLIC_IP = 11.77.0.4', base)
        base = base.replace('tcp dport 22 ', 'tcp dport 2222 ')
        if not os.environ.get('NODE_BASE_AUTO'):
            # The hand-configured fixture listens on one port for both roles.
            base = re.sub(r'(?m)^(define (?:NODE|SERVER)_SSH_PORTS\s*=).*$', r'\1 { 2222 }', base)
        for name, define, number, elements in (
                ('asn_nft', 'ASN', 25098, '11.77.0.201 : $ASN'),
                ('my_server', 'MY_SERVER', 25099, '11.77.0.2 : $MY_SERVER, 11.77.0.3 : $MY_SERVER')):
            base = re.sub(r'include "/opt/maxmind/list/'+name+r'/geoip-def-[^"]+"', f'define {define} = {number}', base)
            mapname = 'asn' if name == 'asn_nft' else name
            base = base.replace(f'include "/opt/maxmind/list/{name}/geoip-ipv4.nft"',
                                f'map {mapname} {{ type ipv4_addr : mark; flags interval; elements = {{ {elements} }}; }}')
        for name, elements in ([] if os.environ.get('NODE_BASE_AUTO') else [('node6_sources', '2606:4700:4700::2, 2606:4700:4700::3'),
                               ('node6_public', '2606:4700:4700::1111'), ('ipv6_routers', 'fe80::1'),
                               ('ssh_asn6', '2606:4700:4700::201/128')]):
            kind = ' flags interval;' if name == 'ssh_asn6' else ''
            base = re.sub(r'(?ms)^    set '+name+r' \{\n.*?^    \}',
                          f'    set {name} {{ type ipv6_addr;{kind} elements = {{ {elements} }}; }}', base)
        base = re.sub(r'(?m)^include "/etc/[^\n]+\n', '', base)
        if os.environ.get('NODE_BASE_AUTO'):
            import nft_host_setup
            base = nft_host_setup.render(base, host, 'node')
        check('installation-profile-atomic-load', run(['nft', '-f', '-'], input=base).returncode == 0)
    for family in (4, 6):
        options['family'] = family
        rules = ('delete table inet vpnbot_node\n' if family == 6 else '') + node.firewall(options, host)
        loaded = run(['nft', '-f', '-'], input=rules)
        check(f'family{family}-atomic-load', loaded.returncode == 0)
        for version, address, trusted, admin, alien in [(4, '11.77.0.4', '11.77.0.2', '11.77.0.3', '11.77.0.200'),
                (6, '2606:4700:4700::1111', '2606:4700:4700::2', '2606:4700:4700::3', '2606:4700:4700::200')]:
            label = f'egress{family}-ingress{version}'
            check(label+'-trusted-vpn', connect(address, 443, trusted, remote=True))
            if family == 4:
                # A busy main bot: 250 new connections at once from its one address.
                accepted, dropped = syn_burst(version, address, trusted, 250)
                print(f'INFO {label} burst 250: accepted {accepted}, dropped {dropped}', flush=True)
                # A rare SYN retransmission may add a packet; nothing may be dropped.
                check(label+'-trusted-burst-250-accepted', accepted >= 250 and dropped == 0)
                # No per-source budget: a flood forged with the bot's address must
                # not be able to lock out the bot's real users.
                accepted, dropped = syn_burst(version, address, trusted, 400)
                print(f'INFO {label} flood 400: accepted {accepted}, dropped {dropped}', flush=True)
                check(label+'-trusted-flood-not-rate-limited', accepted >= 400 and dropped == 0)
                time.sleep(2)  # Half-open test sockets are reset before the next checks.
            if version == 4:
                check(label+'-ipv4-options-block', not connect(address, 443, trusted, remote=True, ip_options=True))
            check(label+'-alien-vpn-block', not connect(address, 443, alien, remote=True))
            check(label+'-backend-port-block', not connect(address, 8443, trusted, remote=True))
            check(label+'-admin-ssh', connect(address, 2222, admin, remote=True))
            check(label+'-source-ssh', connect(address, 2222, trusted, remote=True))
            check(label+'-alien-ssh-block', not connect(address, 2222, alien, remote=True))
            asn = '11.77.0.201' if version == 4 else '2606:4700:4700::201'
            check(label+'-asn-ssh', connect(address, 2222, asn, remote=True))
            check(label+'-asn-vpn-block', not connect(address, 443, asn, remote=True))
            check(label+'-acme-closed', not connect(address, 80, alien, remote=True))
            run(['nft', 'add', 'element', 'inet', 'vpnbot_node', 'acme_http', '{ 80 timeout 2s }'], check=True)
            check(label+'-acme-open', connect(address, 80, alien, remote=True))
            check(label+'-acme-backend-block', not connect(address, 8080, alien, remote=True))
            time.sleep(2)
            check(label+'-acme-expired', not connect(address, 80, alien, remote=True))
        for target in ('11.77.0.128', '2620:fe::fe'):
            expected = (':' in target) == (family == 6)
            check(f'family{family}-public-egress-{target}', connect(target, 18080, uid=995) == expected)
        for target in ('10.77.0.2', 'fd42::2', '127.0.0.1', '11.77.0.4'):
            check(f'family{family}-private-egress-block-{target}', not connect(target, 18080, uid=995))
        check(f'family{family}-host-unaffected', connect('10.77.0.2', 18080))
        # The node's own WAN segment: neighbours and router, whatever their addresses.
        run(['nft', '-f', '-'], input='delete table inet vpnbot_node\n'+node.firewall(options, host | {
            'onlink': ['11.77.0.0/24', '2606:4700:4700::/64', '2620:fe::fe/128']}), check=True)
        for target in ('11.77.0.128', '2620:fe::fe'):
            check(f'family{family}-onlink-egress-block-{target}', not connect(target, 18080, uid=995))
            check(f'family{family}-onlink-host-unaffected-{target}', connect(target, 18080))
        for version, address, trusted in [(4, '11.77.0.4', '11.77.0.2'), (6, '2606:4700:4700::1111', '2606:4700:4700::2')]:
            check(f'family{family}-onlink-ingress{version}-still-open', connect(address, 443, trusted, remote=True))
        run(['nft', '-f', '-'], input='delete table inet vpnbot_node\n'+node.firewall(options, host), check=True)
        cover_options = options | {'cover': True, 'domain': 'node.example.test'}
        run(['nft', '-f', '-'], input='delete table inet vpnbot_node\n'+node.firewall(cover_options, host), check=True)
        check(f'family{family}-core-to-cover-only-port', connect('127.0.0.1', 9443, uid=995))
        check(f'family{family}-cover-to-core-only-port', connect('127.0.0.1', 9444, uid=997))
        check(f'family{family}-core-loopback-still-protected', not connect('127.0.0.1', 9444, uid=995))
        check(f'family{family}-cover-host-ssh-denied', not connect('127.0.0.1', 2222, uid=997))
        for target in ('11.77.0.128', '2620:fe::fe', '10.77.0.2', 'fd42::2'):
            check(f'family{family}-cover-egress-denied-{target}', not connect(target, 18080, uid=997))
        for port in (9443, 9444):
            check(f'family{family}-cover-backend-{port}-not-public', not connect('11.77.0.4', port, '11.77.0.2', remote=True))
        run(['nft', '-f', '-'], input='delete table inet vpnbot_node\n'+node.firewall(options, host), check=True)
        check(f'family{family}-disabled-cover-exception-removed', not connect('127.0.0.1', 9443, uid=995))
        for version, address, trusted, alien, asn in [(4, '11.77.0.4', '11.77.0.2', '11.77.0.200', '11.77.0.201'),
                (6, '2606:4700:4700::1111', '2606:4700:4700::2', '2606:4700:4700::200', '2606:4700:4700::201')]:
            check(f'family{family}-wg{version}-disabled', not connect(address, 51820, trusted, remote=True, udp=True))
        run(['nft', '-f', '-'], input='delete table inet vpnbot_node\n'+node.firewall(options | {'wireguard': {'enabled': True}}, host), check=True)
        for version, address, trusted, alien, asn in [(4, '11.77.0.4', '11.77.0.2', '11.77.0.200', '11.77.0.201'),
                (6, '2606:4700:4700::1111', '2606:4700:4700::2', '2606:4700:4700::200', '2606:4700:4700::201')]:
            check(f'family{family}-wg{version}-trusted', connect(address, 51820, trusted, remote=True, udp=True))
            check(f'family{family}-wg{version}-alien-denied', not connect(address, 51820, alien, remote=True, udp=True))
            check(f'family{family}-wg{version}-asn-denied', not connect(address, 51820, asn, remote=True, udp=True))
            check(f'family{family}-wg{version}-backend-denied', not connect(address, 51830, trusted, remote=True, udp=True))
        for version, address, trusted in [(4,'11.77.0.4','11.77.0.2'), (6,'2606:4700:4700::1111','2606:4700:4700::2')]:
            check(f'family{family}-awg{version}-disabled', not connect(address, 51821, trusted, remote=True, udp=True))
        run(['nft','-f','-'],input='delete table inet vpnbot_node\n'+node.firewall(options | {'amnezia':{'enabled':True}}, host),check=True)
        for version, address, trusted, alien, asn in [(4,'11.77.0.4','11.77.0.2','11.77.0.200','11.77.0.201'),
                (6,'2606:4700:4700::1111','2606:4700:4700::2','2606:4700:4700::200','2606:4700:4700::201')]:
            check(f'family{family}-awg{version}-trusted',connect(address,51821,trusted,remote=True,udp=True))
            check(f'family{family}-awg{version}-alien-denied',not connect(address,51821,alien,remote=True,udp=True))
            check(f'family{family}-awg{version}-asn-denied',not connect(address,51821,asn,remote=True,udp=True))
            check(f'family{family}-awg{version}-backend-denied',not connect(address,51831,trusted,remote=True,udp=True))
        check(f'family{family}-awg-fixed-vless-target',connect('127.0.0.1',8443,uid=994))
        for target, port in [('127.0.0.1',2222),('127.0.0.1',9443),('11.77.0.128',18080),
                             ('2620:fe::fe',18080),('10.77.0.2',18080),('fd42::2',18080)]:
            check(f'family{family}-awg-egress-denied-{target}-{port}',not connect(target,port,uid=994))
        run(['nft','-f','-'],input='delete table inet vpnbot_node\n'+node.firewall(options,host),check=True)
        check(f'family{family}-disabled-awg-exception-removed',not connect('127.0.0.1',8443,uid=994))
    # VPN-only sources retain both optional reserve channels, but never SSH.
    for protocol, port, backend in [('wireguard',51820,51830),('amnezia',51821,51831)]:
        for enabled in (False, True):
            selected = options | {protocol:{'enabled':enabled}, 'vpn_sources':['11.77.0.200','2606:4700:4700::200']}
            run(['nft','-f','-'], input='delete table inet vpnbot_node\n'+node.firewall(selected,host), check=True)
            for version, address, source in [(4,'11.77.0.4','11.77.0.200'),(6,'2606:4700:4700::1111','2606:4700:4700::200')]:
                label=f'vpn-only-{protocol}-{version}-{enabled}'
                check(label+'-tcp443', connect(address,443,source,remote=True))
                check(label+'-ssh-denied', not connect(address,2222,source,remote=True))
                check(label+'-reserve', connect(address,port,source,remote=True,udp=True) == enabled)
                check(label+'-backend-denied', not connect(address,backend,source,remote=True,udp=True))
    # Cold bootstrap uses lo before the node receives its external interface.
    run(['nft', '-f', '-'], input='delete table inet vpnbot_node\n'
        + node.firewall(options, host | {'interface': 'lo'}), check=True)
    run(['nft', '-f', '-'], input='''table inet node_loopback_test {
        chain redirect_local {
            type nat hook output priority dstnat; policy accept;
            oifname "lo" tcp dport 28443 redirect to :8443
        }
    }''', check=True)
    for family, address in ((4, '127.0.0.1'), (6, '::1')):
        check(f'loopback-{family}-direct-readiness', connect(address, 8443))
        check(f'loopback-{family}-unlisted-dnat-denied', not connect(address, 28443))
finally:
    for process in reversed(processes):
        process.terminate()
        process.wait(timeout=5)
    Path(os.environ['NODE_RESULTS_FILE']).write_text(json.dumps(results, indent=2))
