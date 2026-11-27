#!/usr/bin/env python3
"""Node card data: installed code and images, host metrics and live connections."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import image_bundle
import node_manager as manager
import node_state as state
import node_upgrade as upgrade
from node_state_test import VALUE

XR = 'ghcr.io/axiomshiftbit/vpnbot-xr@sha256:' + 'a'*64


def git(directory, *args):
    return subprocess.run(['git', '-C', str(directory), *args], check=True, capture_output=True,
                          env={'PATH': os.environ['PATH'], 'HOME': str(directory), 'GIT_CONFIG_NOSYSTEM': '1',
                               'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@example.test',
                               'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@example.test'}).stdout.decode().strip()


def bundle(source, xr=XR):
    images = {name: image_bundle.REGISTRY + name + '@sha256:' + 'b'*64 for name in image_bundle.IMAGES}
    images['xr'] = xr
    return {'schema': 1, 'source': source, 'run': 1, 'attempt': 1, 'state_epoch': 1, 'images': images}


class InstalledCode(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='vpnbot-node-card-')
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.store = state.Store(self.base/'state')
        self.store.activate(self.store.create(VALUE))
        self.lib = self.base/'lib'
        self.lib.mkdir(mode=0o755)
        for name in upgrade.MODULES:
            (self.lib/name).write_text(name)
        patcher = patch.object(upgrade, 'LIB', self.lib)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.dict(os.environ, {'GIT_CONFIG_NOSYSTEM': '1'})
        patcher.start()
        self.addCleanup(patcher.stop)

    def checkout(self):
        work = self.base/'work'
        (work/'scripts').mkdir(parents=True)
        git(work, 'init', '-q', '-b', 'master')
        for name in upgrade.MODULES:
            (work/'scripts'/name).write_text(name)
        git(work, 'add', '-A')
        git(work, 'commit', '-q', '-m', 'x')
        return work, git(work, 'rev-parse', 'HEAD')

    def test_install_code_uses_the_same_module_list(self):
        import node_install
        source = Path(node_install.__file__).read_text()
        self.assertIn('node_upgrade.MODULES', source)
        for name in upgrade.MODULES:
            self.assertTrue((Path(upgrade.__file__).parent/name).is_file(), name)

    def test_sandboxed_units_keep_the_uid_switch_capability(self):
        # systemd 257 drops CAP_SETUID for User=root + NoNewPrivileges + ProtectKernelModules.
        import node_install
        for name, unit in node_install.units().items():
            if 'ProtectKernelModules=yes' in unit:
                with self.subTest(unit=name):
                    self.assertIn('NoNewPrivileges=yes', unit)
                    self.assertNotIn('User=', unit)
                    self.assertNotIn('Group=', unit)

    def test_manual_install_from_clean_checkout_reports_its_commit(self):
        work, head = self.checkout()
        upgrade.record(self.store.root, work/'scripts', True)
        self.assertEqual(upgrade.code_status(self.store, self.lib), {'source': head, 'upgrade': True, 'origin': 'manual', 'verified': True})

    def test_local_edit_or_archive_claims_no_commit(self):
        work, _ = self.checkout()
        (work/'scripts'/'node_runtime.py').write_text('edited')
        self.assertIsNone(upgrade.checkout_commit(work/'scripts'))
        (work/'scripts'/'node_runtime.py').write_text('node_runtime.py')
        (work/'scripts'/'node_awg.py').unlink()
        self.assertIsNone(upgrade.checkout_commit(work/'scripts'))
        archive = self.base/'archive'/'scripts'
        archive.mkdir(parents=True)
        self.assertIsNone(upgrade.checkout_commit(archive))
        self.assertIsNone(upgrade.checkout_commit(self.base/'work'))  # not a scripts directory
        upgrade.record(self.store.root, archive, True)
        self.assertEqual(upgrade.code_status(self.store, self.lib), {'source': None, 'upgrade': True, 'origin': 'manual', 'verified': True})

    def test_changed_installed_files_are_reported(self):
        work, head = self.checkout()
        upgrade.record(self.store.root, work/'scripts', True)
        (self.lib/'node_xray.py').write_text('patched on the node')
        self.assertFalse(upgrade.code_status(self.store, self.lib)['verified'])
        (self.lib/'node_xray.py').unlink()
        self.assertFalse(upgrade.code_status(self.store, self.lib)['verified'])

    def test_legacy_button_sha_does_not_verify_modules_from_another_commit(self):
        work, source = self.checkout()
        state.atomic(self.store.root/upgrade.CODE, state.encode({'source': source, 'time': 0}))
        (self.lib/'node_xray.py').write_text('legitimate different installation')
        upgrade.record(self.store.root, work/'scripts', False)
        with patch.object(upgrade, 'REPOSITORY', work):
            self.assertFalse(upgrade.code_status(self.store, self.lib)['verified'])

    def test_button_commit_wins_and_failed_record_removes_stale_claim(self):
        work, head = self.checkout()
        upgrade.record(self.store.root, work/'scripts', True)
        state.atomic(self.store.root/upgrade.CODE, state.encode({'source': head, 'digest': upgrade.digest(), 'time': 0}))
        upgrade.record(self.store.root, self.base/'unpacked'/'scripts', False)
        self.assertEqual(upgrade.code_status(self.store, self.lib), {'source': head, 'upgrade': True, 'origin': 'button', 'verified': True})
        (self.lib/'node_wg.py').unlink()
        upgrade.record(self.store.root, work/'scripts', True)
        self.assertFalse((self.store.root/upgrade.INSTALLED).exists())
        self.assertNotIn('verified', upgrade.code_status(self.store, self.lib))

    def test_images_source_only_for_the_running_digest(self):
        self.assertIsNone(upgrade.images_source(self.store))
        image_bundle.atomic(self.store.root/'release.json', (__import__('json').dumps(bundle('d'*40))).encode())
        self.assertEqual(upgrade.images_source(self.store), 'd'*40)
        image_bundle.atomic(self.store.root/'release.json', (__import__('json').dumps(bundle('d'*40, xr='ghcr.io/axiomshiftbit/vpnbot-xr@sha256:'+'f'*64))).encode())
        self.assertIsNone(upgrade.images_source(self.store))  # downloaded, but not running (rollback/failed update)
        image_bundle.atomic(self.store.root/upgrade.RELEASE, (__import__('json').dumps(bundle('e'*40))).encode())
        self.assertEqual(upgrade.images_source(self.store), 'e'*40)


TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1
   1: 0500710B:20FB 076433C6:B3A0 01 00000000:00000000 00:00000000 00000000     0        0 2 1
   2: 0500710B:20FB 076433C6:B3A2 01 00000000:00000000 00:00000000 00000000     0        0 3 1
   3: 0100007F:20FB 0100007F:9C40 01 00000000:00000000 00:00000000 00000000     0        0 4 1
   4: 0500710B:20FB 097100CB:9C41 06 00000000:00000000 00:00000000 00000000     0        0 5 1
   5: 0500710B:A1B2 087100CB:20FB 01 00000000:00000000 00:00000000 00000000     0        0 6 1
   6: 0500710B:20FB 0A7100CB:9C42 01 00000000:00000000 00:00000000 00000000     0        0 7 1
"""
TCP6 = """  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:20FB 0000000000000000FFFF0000086433C6:C000 01 0 0 0
   1: 00000000000000000000000000000000:20FB B80D0120000000000000000007000000:C001 01 0 0 0
   2: 00000000000000000000000000000000:20FB 00000000000000000000000001000000:C002 01 0 0 0
"""
CONNTRACK = """ipv4     2 udp      17 115 src=198.51.100.7 dst=203.0.113.5 sport=40000 dport=51820 src=203.0.113.5 dst=198.51.100.7 sport=51820 dport=40000 [ASSURED] mark=0 zone=0 use=2
ipv4     2 udp      17 25 src=198.51.100.9 dst=203.0.113.5 sport=40001 dport=51821 [UNREPLIED] src=203.0.113.5 dst=198.51.100.9 sport=51821 dport=40001 mark=0 zone=0 use=2
ipv4     2 udp      17 25 src=198.51.100.10 dst=203.0.113.5 sport=53 dport=40002 src=203.0.113.5 dst=198.51.100.10 sport=40002 dport=53 mark=0 zone=0 use=2
ipv4     2 tcp      6 431999 ESTABLISHED src=198.51.100.11 dst=203.0.113.5 sport=1 dport=51820 src=203.0.113.5 dst=198.51.100.11 sport=51820 dport=1 [ASSURED] mark=0 use=1
ipv6     10 udp      17 100 src=2001:0db8:0000:0000:0000:0000:0000:0007 dst=2001:0db8:0000:0000:0000:0000:0000:0001 sport=4 dport=51821 src=2001:0db8:0000:0000:0000:0000:0000:0001 dst=2001:0db8:0000:0000:0000:0000:0000:0007 sport=51821 dport=4 [ASSURED] mark=0 zone=0 use=2
"""


class Connections(unittest.TestCase):
    def proc(self, **files):
        temp = tempfile.TemporaryDirectory(prefix='vpnbot-node-proc-')
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root/'net').mkdir()
        for name, text in files.items():
            (root/'net'/name).write_text(text)
        return root

    def test_established_inbound_connections_per_address(self):
        proc = self.proc(tcp=TCP, tcp6=TCP6)
        # Listener, closing (06), outgoing (remote port 8443) do not count.
        self.assertEqual(manager.tcp_connections(proc), {'198.51.100.7': 2, '127.0.0.1': 1, '203.0.113.10': 1,
                                                         '198.51.100.8': 1, '2001:db8::7': 1, '::1': 1})
        self.assertIsNone(manager.tcp_connections(self.proc()))

    def test_answered_udp_tunnels_only(self):
        self.assertEqual(manager.udp_peers(self.proc(nf_conntrack=CONNTRACK)), {'198.51.100.7', '2001:db8::7'})
        self.assertIsNone(manager.udp_peers(self.proc()))
        with patch.object(manager, 'CONNTRACK_LIMIT', 100):
            self.assertIsNone(manager.udp_peers(self.proc(nf_conntrack=CONNTRACK)))  # too large: no claim

    def test_permitted_servers_and_unexpected_sources(self):
        proc = self.proc(tcp=TCP, tcp6=TCP6, nf_conntrack=CONNTRACK)
        result = manager.connections(['198.51.100.7'], ['198.51.100.8', '2001:0db8::7', '198.51.100.12', '198.51.100.7'], proc)
        self.assertEqual(result['servers'], [
            {'address': '198.51.100.7', 'role': 'main', 'tcp': 2, 'udp': True},
            {'address': '198.51.100.8', 'role': 'vpn', 'tcp': 1, 'udp': False},
            {'address': '2001:db8::7', 'role': 'vpn', 'tcp': 1, 'udp': True},
            {'address': '198.51.100.12', 'role': 'vpn', 'tcp': 0, 'udp': False}])
        self.assertEqual((result['local'], result['other']), (2, 1))
        unknown = manager.connections(['198.51.100.7'], [], self.proc())
        self.assertEqual(unknown, {'servers': [{'address': '198.51.100.7', 'role': 'main', 'tcp': None, 'udp': None}]})

    def test_host_metrics_from_proc(self):
        proc = self.proc(dev="Inter-|   Receive\n face |bytes packets\n    lo: 5 1 0 0 0 0 0 0 6 1 0 0 0 0 0 0\n  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n")
        (proc/'uptime').write_text('3725.31 100.0\n')
        (proc/'meminfo').write_text('MemTotal:        2048 kB\nMemFree:  1 kB\nMemAvailable:    1024 kB\n')
        with patch('os.getloadavg', return_value=(0.123, 0.5, 1.0)):
            result = manager.host_metrics('eth0', proc, str(proc))
        self.assertEqual({k: result[k] for k in ('uptime', 'load', 'memory', 'network')},
                         {'uptime': 3725, 'load': [0.12, 0.5, 1.0], 'memory': {'total': 2097152, 'available': 1048576},
                          'network': {'rx': 1000, 'tx': 2000}})
        self.assertGreater(result['disk']['total'], 0)
        missing = manager.host_metrics('eth1', self.proc(), '/nonexistent-vpnbot')
        self.assertFalse({'uptime', 'memory', 'disk', 'network'} & set(missing))


class Status(unittest.TestCase):
    def test_status_carries_card_data_and_survives_metric_errors(self):
        temp = tempfile.TemporaryDirectory(prefix='vpnbot-node-status-')
        self.addCleanup(temp.cleanup)
        store = state.Store(Path(temp.name)/'state')
        store.activate(store.create(VALUE))
        runtime = SimpleNamespace(status=lambda: {'running': True, 'sources': ['198.51.100.7'], 'options': {'vpn_sources': ['198.51.100.8']}},
                                  host={'interface': 'eth0'})
        status = manager.Manager(store, runtime).rpc({'action': 'status'})
        self.assertEqual([s['address'] for s in status['host']['servers']], ['198.51.100.7', '198.51.100.8'])
        self.assertIn('images', status['code'])
        with patch.object(manager, 'connections', side_effect=ValueError):
            self.assertEqual(manager.Manager(store, runtime).rpc({'action': 'status'})['host'], {})


if __name__ == '__main__':
    unittest.main()
