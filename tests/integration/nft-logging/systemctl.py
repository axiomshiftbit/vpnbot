#!/usr/bin/python3
import os,sys,time,subprocess,signal
from pathlib import Path
assert os.environ.get('NFT_LOGGING_SANDBOX')=='1' and os.readlink('/proc/self/ns/net')!=os.environ['PARENT_NETNS']
a=sys.argv[1:]; p=Path('/run/rsyslog.pid')
def pid():
    try:return int(p.read_text())
    except (OSError,ValueError):return 0
def alive():
    try:
        n=pid()
        if n: os.kill(n,0);return Path('/proc/'+str(n)+'/stat').read_text().split()[2]!='Z'
    except (ProcessLookupError,FileNotFoundError):pass
    return False
if a[0]=='show': print(pid());sys.exit(0)
if a[0]=='is-active': sys.exit(0 if 'cron.service' in a or 'crond.service' in a or alive() else 3)
if a[0]=='kill':
    if alive():os.kill(pid(),signal.SIGHUP)
    sys.exit(0)
if a[0]=='restart':
    if Path('/run/fail-restart').exists(): Path('/run/fail-restart').unlink();sys.exit(1)
    if alive():
        os.kill(pid(),signal.SIGTERM)
        for _ in range(150):
            if not alive():break
            time.sleep(.02)
    p.unlink(missing_ok=True);Path('/dev/log').unlink(missing_ok=True)
    with open('/run/rsyslog.stderr','ab') as log:
        subprocess.Popen(['/usr/sbin/rsyslogd','-n','-i',str(p)],stdin=subprocess.DEVNULL,stdout=log,stderr=log,close_fds=True,start_new_session=True)
    for _ in range(150):
        if alive() and Path('/dev/log').exists():sys.exit(0)
        time.sleep(.02)
    sys.exit(1)
sys.exit(2)
