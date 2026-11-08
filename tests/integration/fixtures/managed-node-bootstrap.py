#!/usr/bin/env python3
"""First firewall activation and new SSH sessions, only in disposable namespaces."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

if os.geteuid() != 0 or os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
    raise SystemExit('Run as root in a separate network namespace')
source = Path(os.environ['NODE_SOURCE_DIR'])
sys.path.insert(0, str(source/'scripts'))
import node_host
import node_setup
import nft_host_setup

checks, processes = [], []


def run(args, **kwargs):
    return subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=20, **kwargs)


def check(name, value):
    checks.append(dict(case=name, ok=bool(value)))
    print(('PASS ' if value else 'FAIL ')+name, flush=True)
    if not value: raise AssertionError(name)


try:
    peer = subprocess.Popen(['unshare', '-n', 'sleep', '300'])
    processes.append(peer)
    time.sleep(.2)
    remote = ['nsenter', '-t', str(peer.pid), '-n']
    run(['ip', 'link', 'add', 'eth0', 'type', 'veth', 'peer', 'name', 'peer0'], check=True)
    run(['ip', 'link', 'set', 'peer0', 'netns', peer.pid], check=True)
    for prefix, interface, addresses in [
        ([], 'eth0', ['11.77.0.4/24', '2606:4700:4700::4/64']),
        (remote, 'peer0', ['11.77.0.'+str(n)+'/24' for n in (2, 3, 5, 200, 201)]+
         ['2606:4700:4700::'+str(n)+'/64' for n in (2, 3, 5, 200, 201)])]:
        run(prefix+['ip', 'link', 'set', 'lo', 'up'], check=True)
        run(prefix+['ip', 'link', 'set', interface, 'up'], check=True)
        for address in addresses:
            run(prefix+['ip', 'address', 'add', address, 'dev', interface]+(['nodad'] if ':' in address else []), check=True)
    run(['ip', 'route', 'add', 'default', 'via', '11.77.0.2'], check=True)
    run(['ip', '-6', 'route', 'add', 'default', 'via', '2606:4700:4700::2'], check=True)
    os.environ['SSH_CONNECTION'] = '11.77.0.3 12000 11.77.0.4 7384'
    with tempfile.TemporaryDirectory(prefix='node-bootstrap-', dir='/root') as tmp:
        root = Path(tmp)
        # Disposable keys are consumed only by OpenSSH; private material is
        # never read by Python, printed, archived or copied out of this lab.
        for name in ('host', 'client'):
            run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', root/name], check=True)
        (root/'authorized_keys').write_text((root/'client.pub').read_text())
        (root/'known_hosts').write_text('[11.77.0.4]:7384,[2606:4700:4700::4]:7384 '+(root/'host.pub').read_text())
        ssh_config = root/'sshd.conf'
        ssh_config.write_text('Port 7384\nListenAddress 0.0.0.0\nListenAddress ::\nHostKey '+str(root/'host')+
            '\nPidFile '+str(root/'sshd.pid')+'\nAuthorizedKeysFile '+str(root/'authorized_keys')+
            '\nPermitRootLogin prohibit-password\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n'+
            'StrictModes yes\nForceCommand /bin/true\nLogLevel QUIET\n')
        def start_ssh():
            process = subprocess.Popen(['/usr/sbin/sshd', '-D', '-f', str(ssh_config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(process)
            time.sleep(.2)
            return process
        daemon = start_ssh()
        def ssh(address):
            target = '2606:4700:4700::4' if ':' in address else '11.77.0.4'
            return run(remote+['ssh', '-F', '/dev/null', '-i', root/'client', '-b', address, '-p', '7384',
                '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile='+str(root/'known_hosts'),
                '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=2', 'root@'+target, 'true']).returncode == 0
        def listen(address, port, udp):
            sock = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if ':' in address: sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((address, port))
            if not udp: sock.listen(16)
            while True:
                if udp:
                    data, sender = sock.recvfrom(32); sock.sendto(data, sender)
                else:
                    conn, _ = sock.accept()
                    with conn: conn.sendall(b'ok')
        ports = [(port, False) for port in (80, 443, 8080, 8443, 9443, 9444)]+[(port, True) for port in (51820, 51821, 51830, 51831)]
        for address in ('0.0.0.0', '::'):
            for port, udp in ports:
                threading.Thread(target=listen, args=(address, port, udp), daemon=True).start()
        time.sleep(.2)
        def reaches(source, port, udp):
            target = '2606:4700:4700::4' if ':' in source else '11.77.0.4'
            script = '''import socket,sys,json
source,target,port,udp=json.loads(sys.argv[1])
s=socket.socket(socket.AF_INET6 if ':' in source else socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
s.settimeout(.4)
try:
 s.bind((source,0));s.connect((target,port))
 if udp:s.send(b'ok')
 sys.exit(0 if s.recv(32)==b'ok' else 1)
except OSError:sys.exit(1)
'''
            return run(remote+[sys.executable, '-c', script, json.dumps([source, target, port, udp])]).returncode == 0
        for address in ('11.77.0.2', '2606:4700:4700::2'):
            for port, udp in ports:
                check('positive-control-service-'+address+'-'+str(port), reaches(address, port, udp))
        for address in ('11.77.0.3', '11.77.0.200', '2606:4700:4700::3', '2606:4700:4700::200'):
            check('positive-control-ssh-'+address, ssh(address))
        base = Path(os.environ['NODE_BASE_FIREWALL']).read_text()
        # Input is a sanitized template, never a production configuration.
        for name, define, number, elements in (
                ('asn_nft', 'ASN', 25098, '11.77.0.201 : $ASN'),
                ('my_server', 'MY_SERVER', 25099, '11.77.0.2 : $MY_SERVER')):
            base = re.sub(r'include "/opt/maxmind/list/'+name+r'/geoip-def-[^"]+"', f'define {define} = {number}', base)
            mapname = 'asn' if name == 'asn_nft' else name
            base = base.replace(f'include "/opt/maxmind/list/{name}/geoip-ipv4.nft"',
                f'map {mapname} {{ type ipv4_addr : mark; flags interval; elements = {{ {elements} }}; }}')
        base = re.sub(r'(?m)^include "/etc/[^\n]+\n', '', base)
        base = re.sub(r'define WAN = "[^"]+"', 'define WAN = "ens3"', base)
        base = node_host.elements(base, 'node4_admins', [])
        base = node_host.elements(base, 'node6_admins', [])
        run(['nft', '-f', '-'], input=base, check=True)
        check('old-bootstrap-blocks-new-ssh', not ssh('11.77.0.3'))
        original_command = node_host.command
        def host_command(args):
            return original_command(['/usr/sbin/sshd', '-T', '-f', str(ssh_config)] if args == ['sshd', '-T'] else args)
        with patch.object(node_host, 'command', side_effect=host_command):
            facts = node_host.discover()
            check('actual-network-and-ssh-port', facts['interface'] == 'eth0' and facts['ssh_ports'] == [7384] and facts['public4'] == '11.77.0.4')
            prepared = node_host.prepare(base, facts, ['11.77.0.3', '11.77.0.5', '2606:4700:4700::3', '2606:4700:4700::5'])
            path = root/'nftables.conf'
            path.write_text(prepared)
            def access_checks(stage):
                for address in ('11.77.0.3', '11.77.0.5', '2606:4700:4700::3', '2606:4700:4700::5'):
                    check(stage+'-admin-'+address, ssh(address))
                for address in ('11.77.0.200', '11.77.0.201', '2606:4700:4700::200', '2606:4700:4700::201'):
                    check(stage+'-outsider-or-asn-denied-'+address, not ssh(address))
            run(['nft', '-f', path], check=True)
            access_checks('first-load')
            for address in ('11.77.0.2', '2606:4700:4700::2'):
                for port, udp in ports:
                    check('before-node-vpn-acme-backend-closed-'+address+'-'+str(port), not reaches(address, port, udp))
            daemon.terminate(); daemon.wait(timeout=10)
            daemon = start_ssh()
            run(['nft', '-f', path], check=True)
            access_checks('persistent-reload')
            key = 'ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+b'k'*32).decode()
            defaults = node_host.defaults(path)
            with patch.object(node_host, 'defaults', return_value=defaults), patch('builtins.input', side_effect=[key]+['']*14), contextlib.redirect_stdout(io.StringIO()):
                value = node_setup.prompt()
            host = value['deployment'] | dict(uid=995, gid=995, cover_uid=997, awg_uid=994)
            check('enter-preserves-explicit-admins-and-port', host['admins'] == defaults['admins'] and host['ssh_ports'] == [7384])
            guard = root/'guard.nft'
            guard.write_text(node_setup.config.firewall(value['options'], host))
            path.write_text(nft_host_setup.render(prepared, host, 'node')+'\ninclude "'+str(guard)+'"\n')
            run(['nft', '-f', path], check=True)
            access_checks('node-installed')
            check('node-keeps-asn-on-old-port', 'define NODE_SSH_PORTS = { 22 }' in path.read_text())
            real_command = node_setup.command
            service = b'LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\nUnitFileState=enabled\n'
            def health_command(args, **kwargs):
                return SimpleNamespace(stdout=service, returncode=0) if args[0] == 'systemctl' else real_command(args, **kwargs)
            with patch.object(node_setup, 'command', side_effect=health_command):
                backend = SimpleNamespace(guard=guard)
                node_setup.verify_firewall(backend, path)
                check('persistent-and-live-firewall-match', True)
                run(['nft', 'insert', 'rule', 'inet', 'vpnbot_node', 'input', 'accept'], check=True)
                try: node_setup.verify_firewall(backend, path)
                except ValueError: refused = True
                else: refused = False
                check('unexpected-accept-rule-detected', refused)
                run(['nft', '-f', path], check=True)
                service = service.replace(b'ActiveState=active', b'ActiveState=failed')
                try: node_setup.verify_firewall(backend, path)
                except ValueError: refused = True
                else: refused = False
                check('failed-nftables-service-detected', refused)
            access_checks('node-persistent-reload')
finally:
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
    if os.environ.get('NODE_RESULTS_FILE'):
        Path(os.environ['NODE_RESULTS_FILE']).write_text(json.dumps(checks))
print('PASS '+str(len(checks))+' bootstrap checks', flush=True)
