#!/usr/bin/env python3
"""Actual scheduler/native PHP receipt/nginx; synthetic issuer and controlled clock."""
import importlib.util
import json
import pathlib
import subprocess
import sys
import time

phase = sys.argv[1]
if phase not in ('control', 'fault', 'recover'):
    raise SystemExit(2)
if pathlib.Path('/run/vpnbot-synthetic-audit').read_text().strip() != 'SYNTHETIC-ONLY':
    raise SystemExit(2)
spec = importlib.util.spec_from_file_location('acme', '/src/scripts/acme_window.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
clock = [int(time.time())]
m.now = lambda: clock[0]
state = pathlib.Path('/work/scheduler') / ('fault' if phase == 'recover' else phase)
state.mkdir(parents=True, exist_ok=True)
acme = state / 'acme'
(acme / 'state').mkdir(parents=True, exist_ok=True)
(acme / 'request').mkdir(exist_ok=True)
m.STATE_DIR = str(state)
window, window_calls = {}, []

def batch(lines):
    for line in lines:
        window_calls.append(line.split()[0])
        for key in m.ALL_SETS:
            if ' '.join(key) in line:
                window[key] = line.startswith('add element')

m.nft_batch = batch
m.set_exists = lambda key: True
m.set_elements = lambda key: ['synthetic-window'] if window.get(key) else []
m.log = lambda message: None
events = {'synthetic_issue_calls': 0, 'native_install_calls': 0}

def driver(*args):
    result = subprocess.run(['php', '/fixture/native_driver.php', *args], capture_output=True, text=True, timeout=40)
    if result.returncode:
        raise m.Fail('fail_preflight', 'synthetic PHP driver failed')
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise m.Fail('fail_preflight', 'synthetic PHP receipt unavailable') from None

class SyntheticIssuerTarget(m.Target):
    def preflight(self):
        if not m.served_serial('ng', 8443, 'tls.audit.test'):
            raise m.Fail('fail_preflight', 'synthetic TLS endpoint unavailable')
        self.names = driver('tls-info')['names']
        return self.names

    def issue(self, dry_run):
        if dry_run:
            raise m.Fail('fail_issue', 'dry-run outside fixture')
        events['synthetic_issue_calls'] += 1
        directory = pathlib.Path('/work/pki/newer')
        cmd = ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-keyout', str(directory/'key.pem'),
               '-out', str(directory/'cert.pem'), '-days', '90', '-set_serial', '303' if phase == 'control' else '404',
               '-subj', '/CN=tls.audit.test', '-addext', 'subjectAltName=' + ','.join('DNS:'+n for n in self.names)]
        result = subprocess.run(cmd, capture_output=True, timeout=30)
        if result.returncode:
            raise m.Fail('fail_issue', 'synthetic issuer failed')
        self.issued_certificate = driver('tls-stage', 'newer')['issued_certificate']
        return 'synthetic issuer'

    def install(self):
        events['native_install_calls'] += 1
        if self.reapply_installed:
            receipt = driver('tls-reapply', self.expected_certificate)
        else:
            receipt = driver('tls-receipt', self.expected_certificate, self.issued_certificate, json.dumps(self.names))
        self.installed_certificate = receipt.get('certificate')
        if receipt.get('stale'):
            raise m.Fail('fail_changed', 'native receipt rejected stale generation')
        if not receipt.get('installed'):
            raise m.Fail('fail_install', 'native application failed')

m.Target = SyntheticIssuerTarget
m.Runner.notify = lambda self, target, result, always=False: None
target = {'name':'synthetic', 'kind':'vpnbot', 'auto':True, 'label':{'ru':'synthetic'}, 'cert_file':'/certs/cert_public',
          'upstream_ip':'172.30.80.3', 'upstream_port':80, 'redirect':False, 'verify_port':8443}
cfg = {'public_ip':'172.30.80.3', 'bot_dir':'/work', 'acme_dir':str(acme), 'targets':[target]}
runner = m.Runner(cfg)
if phase == 'recover':
    ts = runner.ts(target)
    clock[0] = max(clock[0], m.next_attempt(ts, m.cert_info(target['cert_file'])) + 1)
outcome = runner.one(target, manual=phase != 'recover')
ts = runner.ts(target)
info = m.cert_info(target['cert_file'])
old = m.cert_info('/work/pki/old/cert.pem')
due, current = m.next_attempt(ts, info), clock[0]
served = m.served_serial('ng', 8443, 'tls.audit.test')
initial_failures, initial_success, initial_pending = ts['failures'], ts['last_success'] > 0, bool(ts['pending_install'])
issued_before = events['synthetic_issue_calls']
at_expiry = None
if phase == 'fault':
    clock[0] = old['not_after'] + 1
    at_expiry = runner.one(target)
print(json.dumps({'phase':phase, 'result':outcome, 'failures':initial_failures, 'last_success_set':initial_success,
    'pending_install':initial_pending, 'issued_count':len(ts['issued']), 'served_matches_file':served == info['serial'],
    'served_is_old':served == old['serial'], 'next_attempt_seconds':due-current,
    'next_attempt_after_old_expiry':due > old['not_after'], 'automatic_attempt_at_old_expiry':at_expiry is not None,
    'additional_issues_at_old_expiry':events['synthetic_issue_calls']-issued_before,
    'window_closed':not any(window.values()), 'window_add_calls':window_calls.count('add'), 'events':events,
    'boundaries':{'synthetic_issuer':True, 'real_CA':False, 'HTTP01_window_adapter':True, 'controlled_clock':True,
        'native_attempt':True, 'native_Runner_one':True, 'native_next_attempt':True, 'native_cert_info':True,
        'native_served_serial':True, 'native_PHP_receipt':True, 'native_backup_lock':True,
        'native_SSH':True, 'real_nginx':True, 'notifications_suppressed':True}}))
