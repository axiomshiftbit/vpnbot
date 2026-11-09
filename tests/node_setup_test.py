#!/usr/bin/env python3
import base64
import copy
from pathlib import Path
import sys
import unittest
import contextlib
import io
import json
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import node_setup as setup
from node_config_test import HOST, OPTIONS


class NodeSetup(unittest.TestCase):
    def setUp(self):
        key = base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'+b'k'*32).decode()
        self.value = dict(schema=1, controller_key='ssh-ed25519 '+key,
                          deployment={k: v for k, v in HOST.items() if k not in ('uid', 'gid', 'cover_uid')}, options=OPTIONS)

    def test_public_enrollment(self):
        result = setup.enrollment(self.value)
        self.assertNotIn('uid', result['deployment'])
        self.assertNotIn('private', result)
        self.assertEqual(result['options']['transport'], 'reality')

    def test_prompt_answers_reach_both_firewall_layers(self):
        import nft_host_setup
        from nft_host_setup_test import NODE
        key = self.value['controller_key']
        answers = [key, '11.77.0.2 2606:4700:4700::2', '11.77.0.3 2606:4700:4700::3',
                   '11.77.0.4', '2606:4700:4700::1111', 'eth0.100', '2222 7384', 'fe80::1',
                   'reality', 'нет', 'www.example.test', 'origin', '6', '4']
        defaults = dict(interface='eth0', public4='', public6='', ssh_ports=[22], routers=[], sources=[], admins=[], ssh_networks=[])
        with patch.object(setup.node_host, 'defaults', return_value=defaults), \
                patch('builtins.input', side_effect=answers), contextlib.redirect_stdout(io.StringIO()):
            value = setup.prompt()
        host = value['deployment'] | {'uid':995, 'gid':995}
        self.assertEqual(host['interface'], 'eth0.100')
        self.assertEqual(host['ssh_ports'], [2222,7384])
        self.assertEqual(host['routers'], ['fe80::1'])
        self.assertEqual(value['options']['family'], 6)
        self.assertEqual(value['options']['connect_family'], 4)
        guard = setup.config.firewall(value['options'], host)
        self.assertIn('iifname "eth0.100"', guard)
        self.assertIn('tcp dport { 2222, 7384 }', guard)
        base = nft_host_setup.render(NODE, host, 'node')
        self.assertIn('iifname "eth0.100"', base)
        self.assertIn('define NODE_SSH_PORTS = { 2222, 7384 }', base)
        self.assertEqual(base, nft_host_setup.render(base, host, 'node'))
        for family in (4,6):
            for suffix, expected in [('sources', host['sources']), ('admins', host['sources']+host['admins'])]:
                a,b = nft_host_setup.block(base, r'\bset\s+node'+str(family)+'_'+suffix+r'\s*\{')
                for address in expected:
                    if (':' in address) == (family == 6): self.assertIn(address, base[a:b])

    def test_prompt_enter_preserves_discovered_and_explicit_settings(self):
        defaults = dict(interface='eth0.100', public4='11.77.0.4', public6='2606:4700::4', ssh_ports=[7384],
                        routers=['fe80::1'], sources=['11.77.0.2'], admins=['11.77.0.3'], ssh_networks=['11.77.0.128/25'])
        answers = [self.value['controller_key']]+['']*14
        with patch.object(setup.node_host, 'defaults', return_value=defaults), patch('builtins.input', side_effect=answers) as ask, contextlib.redirect_stdout(io.StringIO()):
            value = setup.prompt()
        for name in defaults:
            self.assertEqual(value['deployment'][name], defaults[name])
        prompts = '\n'.join(call.args[0] for call in ask.call_args_list)
        for shown in ('[11.77.0.4]', '[7384]', '[eth0.100]', '[11.77.0.128/25]'):
            self.assertIn(shown, prompts)

    def test_prompt_manual_changes_and_explicit_optional_clear(self):
        defaults = dict(interface='eth0', public4='11.77.0.4', public6='2606:4700::4', ssh_ports=[7384],
                        routers=['fe80::1'], sources=['11.77.0.2'], admins=['11.77.0.3'], ssh_networks=['11.77.0.128/25'])
        answers = [self.value['controller_key'], '11.77.0.5', '11.77.0.6', '11.77.0.7', '-', 'eth0.100', '2222 7384', '-', '-', '', '', '', '', '', '']
        with patch.object(setup.node_host, 'defaults', return_value=defaults), patch('builtins.input', side_effect=answers), contextlib.redirect_stdout(io.StringIO()):
            value = setup.prompt()['deployment']
        self.assertEqual(value['public4'], '11.77.0.7')
        self.assertEqual(value['public6'], '')
        self.assertEqual(value['routers'], [])
        self.assertEqual(value['ssh_networks'], [])
        self.assertEqual(value['ssh_ports'], [2222,7384])
        self.assertEqual(value['sources'], ['11.77.0.5'])
        self.assertEqual(value['admins'], ['11.77.0.6'])

    def test_failure_message_only_exposes_reviewed_validation(self):
        result = setup.failure_message(ValueError('a public node address is required'))
        self.assertIn('Не задан публичный адрес', result)
        self.assertIn('sshd', setup.failure_message(ValueError('Порты SSH должны совпадать с действующей конфигурацией sshd')))
        for error in (ValueError('synthetic-sensitive-input'), RuntimeError('synthetic-sensitive-output')):
            self.assertNotIn('synthetic-sensitive', setup.failure_message(error))

    def test_preflight_rejects_wrong_interface_address_ports_and_ssh_source(self):
        value = setup.enrollment(self.value)
        def command(args, **kwargs):
            if args[0] == 'ip':
                body = json.dumps([{'addr_info':[{'local':address} for address in (HOST['public4'],HOST['public6'])]}]).encode()
            elif args[0] == 'sshd': body = b'port 22\n'
            else: body = b''
            return SimpleNamespace(stdout=body, returncode=0)
        with tempfile.TemporaryDirectory() as tmp, patch.object(setup, 'ROOT', Path(tmp)), \
                patch.object(setup, 'command', side_effect=command), patch.dict(setup.os.environ, {'SSH_CONNECTION':'11.77.0.3 12345 11.77.0.4 22'}), \
                patch.object(setup, 'docker_firewall_disabled') as docker:
            setup.preflight(value)
            docker.assert_called_once_with()
            for field, changed in [('public4','11.77.0.200'), ('ssh_ports',[2222]), ('admins',['11.77.0.200'])]:
                bad = copy.deepcopy(value); bad['deployment'][field] = changed
                with self.subTest(field=field), self.assertRaises(ValueError): setup.preflight(bad)
            with patch.object(setup, 'command', side_effect=lambda args, **kw: SimpleNamespace(stdout=b'[]', returncode=0) if args[0]=='ip' else command(args, **kw)), self.assertRaises(ValueError):
                setup.preflight(value)

    def test_no_remote_uid_command_or_private_key(self):
        for field, value in [('uid', 0), ('command', 'id'), ('private_key', 'fixture')]:
            change = copy.deepcopy(self.value)
            change['deployment'][field] = value
            with self.assertRaises(ValueError):
                setup.enrollment(change)
        change = self.value | {'controller_key': '-----BEGIN OPENSSH PRIVATE KEY-----'}
        with self.assertRaises(ValueError):
            setup.enrollment(change)

    def test_missing_selected_family_rejected(self):
        change = copy.deepcopy(self.value)
        change['deployment']['public6'] = ''
        change['options'] = change['options'] | {'connect_family': 6}
        with self.assertRaises(ValueError):
            setup.enrollment(change)

    def large_asn(self):
        self.value['deployment']['ssh_networks'] = [f'11.{n//256}.{n%256}.0/24' for n in range(6000)]
        return self.value

    def test_public_enrollment_file_accepts_large_asn(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'public.json'
            path.write_text(json.dumps(self.large_asn()))
            public = dict(ssh_user='fixture', host_fingerprint='fixture', host_key=self.value['controller_key'])
            with patch.object(sys, 'argv', ['node_setup.py', '--config', str(path)]), \
                    patch.object(setup.os, 'geteuid', return_value=0), \
                    patch.object(setup, 'setup', return_value=public) as install, contextlib.redirect_stdout(io.StringIO()):
                setup.main()
            self.assertEqual(len(install.call_args.args[0]['deployment']['ssh_networks']), 6000)

    def test_large_asn_is_persisted_before_release_fetch(self):
        class ManifestReached(Exception): pass
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            account = SimpleNamespace(pw_uid=59999, pw_gid=59999)
            with patch.object(setup, 'ROOT', root/'state'), patch.object(setup.install, 'ETC', root), \
                    patch.object(setup, 'preflight'), patch.object(setup.install, 'accounts', return_value=account), \
                    patch.object(setup.pwd, 'getpwnam', side_effect=lambda name: SimpleNamespace(pw_uid=59998 if name == setup.install.COVER else 59997)), \
                    patch.object(setup.install, 'install_code'), \
                    patch.object(setup.image_bundle, 'read', side_effect=ManifestReached):
                with self.assertRaises(ManifestReached):
                    setup.setup(self.large_asn(), root, bundle=root/'bundle.json')
            self.assertEqual(len(json.loads((root/'deployment.json').read_bytes())['ssh_networks']), 6000)

    def test_final_firewall_failure_rolls_back_installation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            account = SimpleNamespace(pw_uid=59999, pw_gid=59999)
            calls = []
            def command(args, **kwargs):
                calls.append(args)
                return SimpleNamespace(stdout=b'', returncode=1 if args[:3] == ['nft', 'list', 'table'] else 0)
            with patch.object(setup, 'ROOT', root), patch.object(setup.install, 'ETC', root), \
                    patch.object(setup, 'preflight'), patch.object(setup.install, 'accounts', return_value=account), \
                    patch.object(setup.pwd, 'getpwnam', side_effect=lambda name: SimpleNamespace(pw_uid=59998 if name == setup.install.COVER else 59997)), \
                    patch.object(setup.install, 'install_code'), patch.object(setup.install, 'install_ssh', return_value={'fixture': 'authorization'}), \
                    patch.object(setup.install, 'restore_ssh') as restore, \
                    patch.object(setup.image_bundle, 'read', return_value={'images': {'xr': 'fixture'}}), \
                    patch.object(setup, 'command', side_effect=command), patch.object(setup.nft_host_setup, 'configure'), \
                    patch.object(setup, 'Runtime') as runtime, patch.object(setup.state, 'Store') as store, \
                    patch.object(setup, 'verify_firewall', side_effect=ValueError('nftables service is not active and enabled')):
                store.return_value.current.return_value = None
                store.return_value.root = root
                store.return_value.activate.side_effect = lambda generation: (root/'current.json').write_text('fixture')
                backend = runtime.return_value
                backend.identity.return_value = {}
                backend.routed_host.return_value = setup.config.deployment(HOST)
                backend.guard = root/'guard.nft'
                with self.assertRaisesRegex(ValueError, 'nftables service'):
                    setup.setup(self.value, root, bundle=root/'bundle.json')
                backend.stop.assert_called_once_with()
                restore.assert_called_once_with({'fixture': 'authorization'})
                self.assertFalse((root/'current.json').exists())
                self.assertFalse(backend.guard.exists())
                self.assertTrue(any(args[:3] == ['systemctl', 'disable', '--now'] for args in calls))

    def test_upgrade_code_only_on_settled_installed_node(self):
        class Store:
            current_value, pending_value, job = 'a'*32, None, {}
            def __init__(self, root): pass
            def current(self): return self.current_value
            def pending(self): return self.pending_value
            def read(self, name): return self.job if name == 'job.json' else None
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'deployment.json').write_bytes(setup.state.encode(HOST, setup.state.MAX_DEPLOYMENT_BYTES))
            with patch.object(setup, 'ROOT', root), patch.object(setup.state, 'Store', Store), \
                    patch.object(setup.install, 'ETC', root), patch.object(setup, 'Runtime') as runtime, \
                    patch.object(setup.nft_host_setup, 'configure') as firewall, \
                    patch.object(setup, 'verify_firewall') as health, \
                    patch.object(setup, 'docker_firewall_disabled') as docker, \
                    patch.object(setup.install, 'install_code') as install_code:
                setup.upgrade_code(root/'src')
                install_code.assert_called_once_with(root/'src')
                # The new code's guard is loaded at once, not at the next restart.
                runtime.return_value.load_firewall.assert_called_once_with()
                firewall.assert_called_once_with(host=setup.config.deployment(HOST), mode='node')
                health.assert_called_once_with(runtime.return_value)
                docker.assert_called_once_with()
                # Docker managing the firewall stops the upgrade before any change.
                docker.side_effect = ValueError('Docker firewall management is enabled')
                install_code.reset_mock()
                with self.assertRaisesRegex(ValueError, 'Docker firewall'):
                    setup.upgrade_code(root/'src')
                install_code.assert_not_called()
                docker.side_effect = None
                self.assertEqual(runtime.call_args.args[1]['sources'], HOST['sources'])
                for field, value in (('current_value', None), ('pending_value', {'before': 'b'*32}), ('job', {'state': 'running'})):
                    with self.subTest(blocked=field), patch.object(Store, field, value):
                        install_code.reset_mock(); runtime.reset_mock(); firewall.reset_mock()
                        with self.assertRaises(ValueError):
                            setup.upgrade_code(root/'src')
                        install_code.assert_not_called()
                        runtime.return_value.load_firewall.assert_not_called()
                        firewall.assert_not_called()


if __name__ == '__main__':
    unittest.main()
