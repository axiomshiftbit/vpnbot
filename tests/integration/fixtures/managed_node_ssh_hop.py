"""IPv4-only PHP -> pinned Xray SSH hop -> IPv6 node, on an isolated bridge."""
import json
import subprocess
import time

NAME = 'vpnbot-managed-hop-fixture'
FABRIC = 'vpnbot-managed-link-fixture'


def run(args, **kwargs):
    return subprocess.run(list(map(str, args)), capture_output=True, timeout=60, **kwargs)


def connect(main, node_pid):
    run(['docker', 'run', '-d', '--name', FABRIC, '--network', 'none', '--memory', '32m',
         '--pids-limit', '16', '--cap-drop', 'ALL', '--entrypoint', 'sleep',
         'vpnbot-audit1031-php:final', '1800'], check=True)
    fabric_pid = int(run(['docker', 'inspect', '-f', '{{.State.Pid}}', FABRIC], check=True).stdout)
    main_pid = int(run(['docker', 'inspect', '-f', '{{.State.Pid}}', main], check=True).stdout)
    run(['nsenter', '-t', fabric_pid, '-n', 'ip', 'link', 'add', 'switch', 'type', 'bridge'], check=True)
    run(['nsenter', '-t', fabric_pid, '-n', 'ip', 'link', 'set', 'switch', 'up'], check=True)
    for port, peer, pid in [('node-port', 'mn-node', node_pid), ('main-port', 'mn-main', main_pid)]:
        for args in (['link', 'add', port, 'type', 'veth', 'peer', 'name', peer],
                     ['link', 'set', port, 'master', 'switch'], ['link', 'set', port, 'up'],
                     ['link', 'set', peer, 'netns', str(pid)]):
            run(['nsenter', '-t', fabric_pid, '-n', 'ip', *args], check=True)


def start(work, main, node_pid):
    public = work/'hop-public'
    public.mkdir(mode=0o755)
    run(['docker', 'exec', main, 'ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', '/ssh/key'], check=True)
    (public/'controller.pub').write_bytes((work/'ssh/key.pub').read_bytes())
    (public/'controller.pub').chmod(0o644)
    run(['docker', 'run', '-d', '--init', '--name', NAME, '--network', 'none', '--memory', '128m',
         '--pids-limit', '64', '--security-opt', 'no-new-privileges',
         '-v', str(public)+':/public:ro', '--entrypoint', 'sleep', 'vpnbot-managed-node-lab:xr', '1800'], check=True)
    hop_pid = int(run(['docker', 'inspect', '-f', '{{.State.Pid}}', NAME], check=True).stdout)
    fabric_pid = int(run(['docker', 'inspect', '-f', '{{.State.Pid}}', FABRIC], check=True).stdout)
    for args in (['link', 'add', 'mn-hop-port', 'type', 'veth', 'peer', 'name', 'mn-hop'],
                 ['link', 'set', 'mn-hop-port', 'master', 'switch'], ['link', 'set', 'mn-hop-port', 'up'],
                 ['link', 'set', 'mn-hop', 'netns', str(hop_pid)]):
        run(['nsenter', '-t', fabric_pid, '-n', 'ip', *args], check=True)
    for args in (['link', 'set', 'mn-hop', 'up'], ['address', 'add', '10.10.0.9/32', 'dev', 'mn-hop'],
                 ['route', 'add', '11.77.0.3/32', 'dev', 'mn-hop'],
                 ['-6', 'address', 'add', '2620:fe::fe/128', 'dev', 'mn-hop', 'nodad'],
                 ['-6', 'route', 'add', '2606:4700:4700::1111/128', 'dev', 'mn-hop']):
        run(['nsenter', '-t', hop_pid, '-n', 'ip', *args], check=True)
    main_pid = int(run(['docker', 'inspect', '-f', '{{.State.Pid}}', main], check=True).stdout)
    run(['nsenter', '-t', main_pid, '-n', 'ip', 'route', 'add', '10.10.0.9/32', 'dev', 'mn-main'], check=True)
    run(['docker', 'exec', main, 'sh', '-c', 'printf "\n10.10.0.9 xr\n" >> /etc/hosts'], check=True)
    run(['docker', 'exec', NAME, 'ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', '/run/hop-host'], check=True)
    pin = run(['docker', 'exec', NAME, 'cat', '/run/hop-host.pub'], check=True).stdout
    destination = work/'ssh/hosts/xr'
    destination.mkdir(parents=True)
    (destination/'ssh_host_ed25519_key.pub').write_bytes(pin)
    config = b'''Port 22
ListenAddress 10.10.0.9
HostKey /run/hop-host
AuthorizedKeysFile /public/controller.pub
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTTY no
UsePAM no
LogLevel ERROR
'''
    run(['docker', 'exec', '-i', NAME, 'sh', '-c', 'cat > /run/hop-sshd.conf'], input=config, check=True)
    run(['docker', 'exec', '-d', NAME, '/usr/sbin/sshd', '-D', '-e', '-f', '/run/hop-sshd.conf'], check=True)
    for _ in range(30):
        ready = run(['docker', 'exec', main, 'python3', '-c', 'import socket;socket.create_connection(("10.10.0.9",22),timeout=.3).close()'])
        if ready.returncode == 0:
            break
        time.sleep(.1)
    else:
        raise RuntimeError('fixture SSH hop did not listen')
    addresses = json.loads(run(['nsenter', '-t', main_pid, '-n', 'ip', '-j', '-6', 'address'], check=True).stdout)
    assert not any(a.get('scope') == 'global' for link in addresses for a in link.get('addr_info', []))
    (work/'work/ipv6-egress.json').write_text(json.dumps({'enabled': True, 'public': '2620:fe::fe'}))
    print('PASS PHP has no global IPv6 while the separate SSH hop has IPv6', flush=True)


def stop():
    run(['docker', 'rm', '-f', NAME])
    run(['docker', 'rm', '-f', FABRIC])
