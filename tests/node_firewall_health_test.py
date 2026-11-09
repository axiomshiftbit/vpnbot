import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import node_setup as setup


class FirewallHealth(unittest.TestCase):
    def test_service_and_live_policy_failures_are_not_success(self):
        base = {'nftables': [
            {'table': {'family': 'ip', 'name': 'filter'}},
            {'chain': {'family': 'ip', 'table': 'filter', 'name': 'input', 'type': 'filter', 'hook': 'input', 'prio': 0, 'policy': 'drop'}},
            {'rule': {'family': 'ip', 'table': 'filter', 'chain': 'input', 'expr': [{'drop': None}]}}
        ]}
        guard = {'nftables': [
            {'table': {'family': 'inet', 'name': 'vpnbot_node'}},
            {'chain': {'family': 'inet', 'table': 'vpnbot_node', 'name': 'input', 'type': 'filter', 'hook': 'input', 'prio': -20, 'policy': 'drop'}}
        ]}
        healthy = dict(LoadState='loaded', ActiveState='active', SubState='exited', Result='success', UnitFileState='enabled')
        cases = [(None, None)] + [(field, value) for field, value in [
            ('LoadState', 'not-found'), ('ActiveState', 'inactive'), ('ActiveState', 'failed'),
            ('SubState', 'dead'), ('Result', 'exit-code'), ('UnitFileState', 'disabled')]]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base_path, guard_path = root/'base', root/'guard'
            base_path.write_text('table ip filter { }')
            guard_path.write_text('guard fixture')
            for field, value in cases:
                status = healthy | ({field: value} if field else {})
                live = dict(nftables=base['nftables']+guard['nftables'])
                def command(args, **kwargs):
                    body = '\n'.join(k+'='+v for k, v in status.items()) if args[0] == 'systemctl' else json.dumps(live)
                    return SimpleNamespace(stdout=body.encode(), returncode=0)
                with self.subTest(field=field, value=value), patch.object(setup, 'command', side_effect=command), \
                        patch.object(setup.os, 'open', return_value=100), patch.object(setup.os, 'close'), \
                        patch.object(setup.fcntl, 'flock'), patch.object(setup.state, 'trusted'), \
                        patch.object(setup.node_host, 'read_profile', return_value=base_path.read_text()), \
                        patch.object(setup.nft_host_setup, 'compile_rules', side_effect=lambda text: guard if text == 'guard fixture' else base):
                    backend = SimpleNamespace(guard=guard_path)
                    if field:
                        with self.assertRaisesRegex(ValueError, 'service is not active'):
                            setup.verify_firewall(backend, base_path)
                    else:
                        setup.verify_firewall(backend, base_path)
                        for mutation in ('missing_guard', 'accept_policy', 'extra_accept'):
                            live = copy.deepcopy(dict(nftables=base['nftables']+guard['nftables']))
                            if mutation == 'missing_guard': live['nftables'] = live['nftables'][:3]
                            elif mutation == 'accept_policy': live['nftables'][1]['chain']['policy'] = 'accept'
                            else: live['nftables'].append({'rule': {'family':'ip','table':'filter','chain':'input','expr':[{'accept':None}]}})
                            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'live rules differ'):
                                setup.verify_firewall(backend, base_path)

    def test_docker_firewall_objects_anywhere_are_rejected(self):
        # A node's packet filtering is manual: dockerd must not add its own
        # chains to the profile tables nor its own nat/docker-bridges tables.
        base = {'nftables': [
            {'table': {'family': 'ip', 'name': 'filter'}},
            {'chain': {'family': 'ip', 'table': 'filter', 'name': 'input', 'type': 'filter', 'hook': 'input', 'prio': 0, 'policy': 'drop'}},
            {'rule': {'family': 'ip', 'table': 'filter', 'chain': 'input', 'expr': [{'drop': None}]}}
        ]}
        guard = {'nftables': [{'table': {'family': 'inet', 'name': 'vpnbot_node'}}]}
        healthy = 'LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\nUnitFileState=enabled'
        cases = [('clean', [], None),
                 ('profile-table-chain', [{'chain': {'family': 'ip', 'table': 'filter', 'name': 'DOCKER-USER'}}], 'Docker firewall rules'),
                 ('nat-table', [{'table': {'family': 'ip', 'name': 'nat'}},
                                {'chain': {'family': 'ip', 'table': 'nat', 'name': 'DOCKER'}}], 'Docker firewall rules'),
                 ('nft-backend', [{'table': {'family': 'ip6', 'name': 'docker-bridges'}}], 'Docker firewall rules'),
                 # Hand-written names of the full bot profile are not Docker's own.
                 ('manual-names', [{'table': {'family': 'ip', 'name': 'dockernat'}},
                                   {'chain': {'family': 'ip', 'table': 'dockernat', 'name': 'dockernat'}}], None)]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base_path, guard_path = root/'base', root/'guard'
            base_path.write_text('table ip filter { }')
            guard_path.write_text('guard fixture')
            for label, extra, error in cases:
                live = dict(nftables=base['nftables']+guard['nftables']+extra)
                def command(args, **kwargs):
                    body = healthy if args[0] == 'systemctl' else json.dumps(live)
                    return SimpleNamespace(stdout=body.encode(), returncode=0)
                with self.subTest(label), patch.object(setup, 'command', side_effect=command), \
                        patch.object(setup.os, 'open', return_value=100), patch.object(setup.os, 'close'), \
                        patch.object(setup.fcntl, 'flock'), patch.object(setup.state, 'trusted'), \
                        patch.object(setup.node_host, 'read_profile', return_value=base_path.read_text()), \
                        patch.object(setup.nft_host_setup, 'compile_rules', side_effect=lambda text: guard if text == 'guard fixture' else base):
                    backend = SimpleNamespace(guard=guard_path)
                    if error:
                        with self.assertRaisesRegex(ValueError, error):
                            setup.verify_firewall(backend, base_path)
                    else:
                        setup.verify_firewall(backend, base_path)

    def test_docker_must_not_manage_the_firewall(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon, proc = root/'daemon.json', root/'proc'
            proc.mkdir()
            def dockerd(*arguments):
                for old in proc.iterdir():
                    for item in old.iterdir(): item.unlink()
                    old.rmdir()
                if arguments is not None:
                    (proc/'123').mkdir()
                    (proc/'123'/'comm').write_text('dockerd\n')
                    (proc/'123'/'cmdline').write_bytes(b'\0'.join([b'/usr/bin/dockerd', *arguments])+b'\0')
            cases = [('absent-default', None, (), False),
                     ('all-off', '{"iptables": false, "ip6tables": false, "ip-forward": false, "userland-proxy": false}', (), True),
                     ('forwarding-on-by-default', '{"iptables": false, "ip6tables": false}', (), False),
                     ('ipv6-on-by-default', '{"iptables": false}', (), False),
                     ('explicit-true', '{"iptables": true, "ip6tables": false}', (), False),
                     ('string-false', '{"iptables": "false", "ip6tables": false}', (), False),
                     ('invalid-json', '{"iptables": false,', (), False),
                     ('flags-off', None, (b'--iptables=false', b'--ip6tables=false', b'--ip-forward=false'), True),
                     ('flag-on', '{"ip6tables": false, "ip-forward": false}', (b'--iptables',), False)]
            for label, body, flags, allowed in cases:
                daemon.unlink(missing_ok=True)
                if body is not None: daemon.write_text(body)
                dockerd(*flags)
                with self.subTest(label):
                    if allowed:
                        setup.docker_firewall_disabled(daemon, proc)
                    else:
                        with self.assertRaisesRegex(ValueError, 'Docker firewall management'):
                            setup.docker_firewall_disabled(daemon, proc)
        message = setup.failure_message(ValueError('Docker firewall management is enabled'))
        self.assertIn('"iptables": false', message)
        self.assertIn('"ip6tables": false', message)
        self.assertIn('"ip-forward": false', message)

    def test_fresh_install_merges_docker_settings_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon, proc = root/'docker'/'daemon.json', root/'proc'
            proc.mkdir(); daemon.parent.mkdir()
            daemon.write_text('{"log-driver": "local", "iptables": false}')
            calls = []
            with patch.object(setup, 'command', side_effect=lambda args, **kw: calls.append(args)):
                self.assertTrue(setup.prepare_docker(daemon))
                value = json.loads(daemon.read_text())
                self.assertEqual(value, {'log-driver': 'local', 'iptables': False, 'ip6tables': False, 'ip-forward': False})
                self.assertEqual(json.loads((root/'docker'/'daemon.json.before-vpnbot-node').read_text()), {'log-driver': 'local', 'iptables': False})
                self.assertEqual(calls, [['systemctl', 'restart', 'docker.service']])
                # Already prepared: no second restart, no rewrite.
                self.assertFalse(setup.prepare_docker(daemon))
                self.assertEqual(len(calls), 1)
                daemon.write_text('not json')
                with self.assertRaisesRegex(ValueError, 'Docker firewall management'):
                    setup.prepare_docker(daemon)
                self.assertEqual(len(calls), 1)

if __name__ == '__main__':
    unittest.main()
