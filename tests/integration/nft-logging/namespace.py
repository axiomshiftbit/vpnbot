#!/usr/bin/env python3
import os,sys,subprocess
from pathlib import Path
root,base,parent,case=sys.argv[1:]
root=Path(root).resolve(); base=Path(base).resolve()
assert os.getuid()==0 and os.getpid()==1 and os.readlink('/proc/self/ns/net')!=parent
assert root.parent==base and root.name.startswith('root-') and not any(root.iterdir())
for line in Path('/proc/self/mountinfo').read_text().splitlines():
    assert not any(x.startswith(('shared:','master:')) for x in line.split(' - ')[0].split()[6:])
def cmd(*v): subprocess.run(v,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
def bind(src,dst,ro=True):
    p=root/dst.lstrip('/'); p.parent.mkdir(parents=True,exist_ok=True)

    if not p.exists():
        p.mkdir() if Path(src).is_dir() else p.touch()
    cmd('mount','--bind',str(src),str(p))
    if ro: cmd('mount','-o','remount,bind,ro,nosuid',str(p))
cmd('mount','-t','tmpfs','-o','size=192M,mode=0755,nosuid','tmpfs',str(root))
bind('/usr','/usr')
for name,target in [('bin','usr/bin'),('sbin','usr/sbin'),('lib','usr/lib'),('lib64','usr/lib64')]: (root/name).symlink_to(target)
for name in ['tmp','dev','proc','run','var/log','var/backups','var/lib/logrotate','etc/rsyslog.d','etc/logrotate.d','etc/cron.d','etc/alternatives','source','lab']:
    (root/name).mkdir(parents=True,exist_ok=True)
(root/'tmp').chmod(0o1777)
for name in ('null','zero','urandom','random'): bind('/dev/'+name,'/dev/'+name,False)
(root/'dev/fd').symlink_to('/proc/self/fd')
cmd('mount','-t','proc','-o','nosuid,nodev,noexec','proc',str(root/'proc')); bind('/proc/sys','/proc/sys')
bind(base/'source','/source'); bind(base/'case.py','/lab/case.py'); bind(base/'systemctl.py','/usr/bin/systemctl')
# Only executable paths, no host configuration or NSS databases.
(root/'etc/passwd').write_text('root:x:0:0:root:/root:/bin/sh\nsyslog:x:104:104:synthetic:/nonexistent:/bin/false\n')
(root/'etc/group').write_text('root:x:0:\nsyslog:x:104:\nadm:x:4:\n')
(root/'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files\n')
(root/'etc/hosts').write_text('127.0.0.1 localhost\n')
for name in ['awk']:
    p=Path('/usr/bin')/name
    if p.is_symlink() and '/etc/alternatives/' in os.readlink(p): (root/'etc/alternatives'/name).symlink_to(str(p.resolve()))
# The outer runner uses umask 077 for its artifacts; the synthetic OS must
# still allow its unprivileged syslog account to traverse standard directories.
for name in ('etc', 'etc/rsyslog.d', 'etc/logrotate.d', 'etc/cron.d', 'etc/alternatives',
             'var', 'var/log', 'var/backups', 'var/lib', 'var/lib/logrotate', 'run', 'dev'):
    (root/name).chmod(0o755)
for name in ('passwd', 'group', 'nsswitch.conf', 'hosts'):
    (root/'etc'/name).chmod(0o644)
os.chroot(root);os.chdir('/')
os.execve('/usr/bin/python3',['python3','-B','/lab/case.py',case],{'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','NFT_LOGGING_SANDBOX':'1','PARENT_NETNS':parent})
