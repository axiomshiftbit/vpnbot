#!/usr/bin/env python3
"""Actual nft meter capacity must fail closed, using disposable namespaces."""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
import time

def run(args, **kwargs):
    return subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=15, **kwargs)

if len(sys.argv) == 3 and sys.argv[1] == 'probe':
    value = json.loads(sys.argv[2])
    try:
        sock = socket.socket(socket.AF_INET6 if ':' in value['source'] else socket.AF_INET)
        sock.settimeout(.5)
        sock.bind((value['source'], 0))
        sock.connect((value['target'], 2222))
        raise SystemExit(0 if sock.recv(2) == b'ok' else 1)
    except OSError:
        raise SystemExit(1)

if os.geteuid() != 0 or os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
    raise SystemExit('Run in a disposable network namespace')
sys.path.insert(0, str(Path(os.environ['NODE_SOURCE_DIR'])/'scripts'))
import node_config as config
host = dict(public4='11.77.0.4', public6='2606:4700:4700::1111', sources=['11.77.0.2'],
            admins=['11.77.0.2'], routers=[], ssh_ports=[2222], interface='meter0', uid=995, gid=995)
options = dict(transport='reality', core='origin', family=4, domain='', mask='mask.example.test')
rules = config.firewall(options, host)
cases = []
for version in (4, 6):
    line = next(line for line in rules.splitlines() if line.startswith(f' chain syn{version} '))
    cases.append((f'core-ipv{version}', version, line.split('{', 1)[1].rsplit('}', 1)[0]))
for path in sys.argv[1:]:
    text = Path(path).read_text()
    for name, version in [('node6_ingress', 6), ('ssh', 4), ('ssh', 6)]:
        table = 'table ip6 filter {' if version == 6 else 'table ip filter {'
        if table not in text: continue
        body = re.search(r'(?ms)^    chain '+name+r' \{\n(.*?)^    \}', text.split(table, 1)[1])
        if body: cases.append((Path(path).name+'-'+name+str(version), version, body[1]))

def listen(family):
    sock = socket.socket(family)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6: sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', 2222));sock.listen()
    while True:
        conn, _ = sock.accept()
        with conn: conn.sendall(b'ok')

peer = subprocess.Popen(['unshare', '-n', 'sleep', '300'])
failed = False
try:
    time.sleep(.2)
    run(['ip', 'link', 'add', 'meter0', 'type', 'veth', 'peer', 'name', 'peer0'], check=True)
    run(['ip', 'link', 'set', 'peer0', 'netns', peer.pid], check=True)
    pfx = ['nsenter', '-t', str(peer.pid), '-n']
    for prefix, dev, addresses in [([], 'meter0', ['11.77.0.4/24', '2606:4700:4700::1111/64']),
            (pfx, 'peer0', ['11.77.0.2/24', '11.77.0.3/24', '11.77.0.200/24',
                           '2606:4700:4700::2/64', '2606:4700:4700::3/64', '2606:4700:4700::200/64'])]:
        run(prefix+['ip', 'link', 'set', 'lo', 'up'], check=True)
        run(prefix+['ip', 'link', 'set', dev, 'up'], check=True)
        for address in addresses:
            run(prefix+['ip', 'addr', 'add', address, 'dev', dev]+(['nodad'] if ':' in address else []), check=True)
    for family in (socket.AF_INET, socket.AF_INET6):
        threading.Thread(target=listen, args=(family,), daemon=True).start()
    time.sleep(.2)
    for name, version, body in cases:
        body = body.replace('size 65535', 'size 2')
        # SSH's final logging chain is terminal ACCEPT; logs are not the
        # subject of this packet test, and do not change the meter verdict.
        body = body.replace('jump ssh_log', 'counter accept')
        rule = 'flush ruleset\ntable inet meter_test {\n chain limited {\n'+body+'\n }\n'
        rule += ' chain input { type filter hook input priority 0; policy accept; ct state new tcp flags & (fin|syn|rst|ack) == syn tcp dport 2222 jump limited; }\n}\n'
        run(['nft', '-f', '-'], input=rule, check=True)
        sources = ['11.77.0.2', '11.77.0.3', '11.77.0.200'] if version == 4 else ['2606:4700:4700::2', '2606:4700:4700::3', '2606:4700:4700::200']
        target = host['public'+str(version)]
        actual = [run(pfx+[sys.executable, str(Path(__file__).resolve()), 'probe', json.dumps(dict(source=source, target=target))]).returncode == 0 for source in sources]
        ok = actual == [True, True, False]
        print(('PASS ' if ok else 'FAIL ')+name+' meter exhaustion closes new source', flush=True)
        failed |= not ok
finally:
    peer.terminate();peer.wait(timeout=5)
raise SystemExit(1 if failed else 0)
