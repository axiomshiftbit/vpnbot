#!/usr/bin/env python3
"""Run NODE01 crash/recovery tests in a disposable root mount/net/PID namespace.

Needs root, Linux unshare/mount, Python and Docker CLI (no Docker socket).
Never reads host node configuration and never contacts its services.
"""
import ast
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def command(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)


def inner(root, snapshot, parent_netns):
    if os.getpid() != 1 or os.readlink('/proc/self/ns/net') == parent_netns:
        raise RuntimeError('a separate PID/network namespace is required')
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        if any(value.startswith(('shared:', 'master:')) for value in line.split(' - ')[0].split()[6:]):
            raise RuntimeError('mount propagation must be private')
    if root.parent != snapshot.parent or not root.parent.name.startswith('node-code-native-') or any(root.iterdir()):
        raise RuntimeError('fresh owned rootfs is required')
    command('mount', '-t', 'tmpfs', '-o', 'mode=0755,nosuid', 'tmpfs', str(root))
    def bind(source, destination, readonly=True):
        target = root/destination.lstrip('/'); target.parent.mkdir(parents=True, exist_ok=True)
        if Path(source).is_dir(): target.mkdir(exist_ok=True)
        else: target.touch()
        command('mount', '--bind', str(source), str(target))
        if readonly: command('mount', '-o', 'remount,bind,ro,nosuid', str(target))
    bind('/usr', '/usr'); bind(snapshot, '/src')
    for name, target in [('bin', 'usr/bin'), ('sbin', 'usr/sbin'), ('lib', 'usr/lib'), ('lib64', 'usr/lib64')]:
        (root/name).symlink_to(target)
    for name in ('tmp', 'etc', 'proc', 'root', 'run', 'dev/shm'):
        (root/name).mkdir(parents=True, exist_ok=True)
    (root/'tmp').chmod(0o1777)
    for name in ('null', 'zero', 'urandom', 'random'): bind('/dev/'+name, '/dev/'+name, readonly=False)
    command('mount', '-t', 'proc', '-o', 'nosuid,nodev,noexec', 'proc', str(root/'proc'))
    bind('/proc/sys', '/proc/sys')
    os.chroot(root); os.chdir('/')
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'VPNBOT_KERNEL_SANDBOX': '1', 'VPNBOT_PARENT_NETNS': parent_netns}
    os.execve('/usr/bin/python3', ['python3', '-B', '-m', 'unittest', 'discover', '-s', '/src/tests', '-p', 'node_code_test.py', '-v'], env)


def main():
    if os.geteuid() != 0: raise RuntimeError('requires root on the disposable test VM')
    os.umask(0o077)
    if sys.argv[1:2] == ['--inner']:
        inner(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
        return
    if sys.argv[1:]: raise RuntimeError('unsupported arguments')
    for program in ('unshare', 'mount', 'umount', 'docker', 'systemctl'):
        if not shutil.which(program): raise RuntimeError('missing test dependency: '+program)
    repo = Path(__file__).resolve().parents[2]
    tree = ast.parse((repo/'scripts/node_upgrade.py').read_text())
    modules = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'MODULES' for target in node.targets))
    with tempfile.TemporaryDirectory(prefix='node-code-native-') as temporary:
        base = Path(temporary); snapshot = base/'source'; root = base/'rootfs'; root.mkdir()
        for name in ['scripts/'+name for name in modules]+['tests/node_code_test.py']:
            destination = snapshot/name; destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(repo/name, destination)
        result = subprocess.run(['unshare', '--mount', '--propagation', 'private', '--net', '--pid', '--fork',
                                 '--mount-proc', '--kill-child=KILL', '/usr/bin/python3', '-B', str(Path(__file__).resolve()),
                                 '--inner', str(root), str(snapshot), os.readlink('/proc/self/ns/net')],
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'}, timeout=120)
        raise SystemExit(result.returncode)


if __name__ == '__main__': main()
