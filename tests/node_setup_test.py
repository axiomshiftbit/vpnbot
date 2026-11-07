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

    def test_upgrade_code_only_on_settled_installed_node(self):
        class Store:
            current_value, pending_value, job = 'a'*32, None, {}
            def __init__(self, root): pass
            def current(self): return self.current_value
            def pending(self): return self.pending_value
            def read(self, name): return self.job if name == 'job.json' else None
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(setup, 'ROOT', root), patch.object(setup.state, 'Store', Store), \
                    patch.object(setup.install, 'install_code') as install_code:
                setup.upgrade_code(root/'src')
                install_code.assert_called_once_with(root/'src')
                for field, value in (('current_value', None), ('pending_value', {'before': 'b'*32}), ('job', {'state': 'running'})):
                    with self.subTest(blocked=field), patch.object(Store, field, value):
                        install_code.reset_mock()
                        with self.assertRaises(ValueError):
                            setup.upgrade_code(root/'src')
                        install_code.assert_not_called()


if __name__ == '__main__':
    unittest.main()
