#!/usr/bin/env python3
"""Real nft transactions, failed persistence and watchdog in an isolated namespace."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

if os.geteuid() != 0 or os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
    raise SystemExit('Run as root in a separate network namespace')
source=Path(os.environ['NODE_SOURCE_DIR'])
sys.path[:0]=[str(source/'scripts'),str(source/'tests')]
from nft_host_setup_test import FULL, NODE, HOST
import nft_host_setup as nft

checks=0

def check(name,value):
    global checks
    if not value: raise AssertionError(name)
    checks+=1
    print('PASS '+name,flush=True)

def current(): return json.loads(nft.run(['nft','-j','list','ruleset']))
def rules(doc): return nft.clean(nft.objects(doc,'rule'))

with tempfile.TemporaryDirectory(prefix='vpnbot-nft-test-',dir='/run') as tmp:
    path=Path(tmp)/'nftables.conf'
    for mode,text in [('full',FULL),('node',NODE)]:
        nft.run(['nft','-f','-'], text)
        nft.run(['nft','-f','-'],'table inet foreign { chain guard { type filter hook forward priority -50; policy drop; }\n}\n')
        before=current()
        foreign=[x for x in before['nftables'] if next(iter(x))!='metainfo' and ('foreign' in x[next(iter(x))].values())]
        path.write_text(text)
        check(mode+'-check-only',nft.ensure(path,HOST,mode,check=True) and path.read_text()==text and current()==before)
        check(mode+'-automatic-config', nft.ensure(path,HOST,mode))
        check(mode+'-persistent-syntax', bool(nft.compile_rules(path.read_text())))
        live=current()
        check(mode+'-foreign-table-kept',foreign==[x for x in live['nftables'] if next(iter(x))!='metainfo' and ('foreign' in x[next(iter(x))].values())])
        check(mode+'-idempotent',not nft.ensure(path,HOST,mode))
        saved=path.read_text();live=current()
        atomic=nft.sets.atomic
        def fail_persist(p,text,permissions):
            if p==path and text!=saved: raise OSError('synthetic disk error')
            return atomic(p,text,permissions)
        with patch.object(nft.sets,'atomic',side_effect=fail_persist):
            try: nft.ensure(path,HOST|{'public4':'11.77.0.128'},mode)
            except OSError: pass
            else: raise AssertionError('expected failure')
        check(mode+'-disk-error-rollback',path.read_text()==saved and rules(current())==rules(live))
        new=nft.render(saved,HOST|{'public4':'11.77.0.128'},mode)
        change,reverse=nft.delta(nft.compile_rules(saved),nft.compile_rules(new),current())
        fd,child=nft.watchdog(path,saved,new,0o600,reverse)
        nft.run(['nft','-j','-f','-'],json.dumps(change));path.write_text(new)
        os.close(fd)  # EOF = abrupt installer loss, no confirmation.
        _,status=os.waitpid(child,0)
        check(mode+'-watchdog-rollback',status==0 and path.read_text()==saved and rules(current())==rules(live))
        check(mode+'-backup-exists',path.with_name(path.name+'.before-vpnbot-setup').is_file())
        link=Path(tmp)/'link';link.symlink_to(path)
        try: nft.ensure(link,HOST,mode)
        except ValueError: pass
        else: raise AssertionError('symlink accepted')
        link.unlink()
        check(mode+'-symlink-rejected',True)
    # Empty baseline on disk may already be supplied but not loaded.
    nft.run(['nft','delete','table','ip','filter']);nft.run(['nft','delete','table','ip6','filter'])
    path.write_text(FULL)
    check('initial-profile-load',nft.ensure(path,HOST,'full'))
    check('initial-foreign-table-kept',any(x.get('table',{}).get('name')=='foreign' for x in current()['nftables']))
    for family in (4,6):
        nft.run(['nft','-f','-'],NODE)
        path.write_text(NODE)
        host=HOST|{'public'+str(10-family):'', 'routers':[], 'ssh_networks':[],
                   'sources':[x for x in HOST['sources'] if (':' in x)==(family==6)],
                   'admins':[x for x in HOST['admins'] if (':' in x)==(family==6)]}
        check('single-family-'+str(family),nft.ensure(path,host,'node'))
        check('single-family-'+str(family)+'-idempotent',not nft.ensure(path,host,'node'))
print('PASS '+str(checks)+' nft installation checks',flush=True)
