#!/usr/bin/env python3
"""Disposable root filesystem inside an already isolated mount/network/PID namespace."""
import os
from pathlib import Path
import subprocess
import sys

root, source, probes, parent = map(Path, sys.argv[1:5])
assert os.geteuid() == 0 and os.getpid() == 1
assert os.readlink('/proc/self/ns/net') != str(parent)
assert root.parent == probes and root.name.startswith('root-') and not any(root.iterdir())
for line in Path('/proc/self/mountinfo').read_text().splitlines():
    assert not any(x.startswith(('shared:', 'master:')) for x in line.split(' - ')[0].split()[6:])

def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

def bind(src, dst, readonly=True):
    target = root / dst.lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True)
    if Path(src).is_dir(): target.mkdir(exist_ok=True)
    else: target.touch()
    run('mount', '--bind', str(src), str(target))
    if readonly: run('mount', '-o', 'remount,bind,ro,nosuid', str(target))

run('mount', '-t', 'tmpfs', '-o', 'mode=0755,nosuid,size=256m', 'tmpfs', str(root))
bind('/usr', '/usr')
for name in ('bin', 'sbin', 'lib', 'lib64'):
    (root/name).symlink_to('usr/'+name)
for name in ('tmp', 'run', 'proc', 'dev', 'etc'):
    (root/name).mkdir(exist_ok=True)
(root/'tmp').chmod(0o1777)
for name in ('null', 'zero', 'random', 'urandom'):
    bind('/dev/'+name, '/dev/'+name, False)
run('mount', '-t', 'proc', '-o', 'nosuid,nodev,noexec', 'proc', str(root/'proc'))
bind('/proc/sys', '/proc/sys')
bind('/proc/sys/net', '/proc/sys/net', False)
bind('/etc/protocols', '/etc/protocols')
bind(source, '/src')
bind(probes/'packets.py', '/probes/packets.py')
os.chroot(root)
os.chdir('/')
os.execve('/usr/bin/python3', ['python3', '-B', '/probes/packets.py'], {
    'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'VPNBOT_NFT_LAB': '1',
    'VPNBOT_PARENT_NETNS': str(parent), 'PYTHONDONTWRITEBYTECODE': '1'})
