#!/usr/bin/env python3
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import subprocess
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from node_awg_test import Amnezia
import node_awg_client as client
import node_config
from node_config_test import HOST, OPTIONS, KEYS


class Carrier(unittest.TestCase):
    def setUp(self):
        fixture = Amnezia()
        fixture.setUp()
        self.keys, self.profile = fixture.keys, fixture.value
        self.row = {'session': 'a'*16, 'client': self.profile}

    def test_metadata_has_only_bounded_fixed_slots(self):
        self.assertTrue(client.metadata([self.row])[0] == self.row)
        for value in [{'8': self.row}, {'-1': self.row}, {'0': self.row | {'command': 'id'}},
                      {'0': self.row | {'session': 'bad'}}, {'0': self.row | {'client': self.profile | {'endpoint': '127.0.0.1'}}}]:
            with self.assertRaises(ValueError):
                client.metadata(value)

    def test_config_reader_refuses_symlinks_and_oversize(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'xray.json'
            path.write_text(json.dumps({'_vpnbot_amnezia':[self.row]}))
            with patch.object(client, 'CONFIG', path):
                self.assertTrue(client.read_config()[0] == self.row)
                path.unlink()
                path.symlink_to('/dev/null')
                with self.assertRaises(OSError):
                    client.read_config()
                path.unlink()
                with path.open('wb') as stream:
                    stream.truncate(8*1024*1024+1)
                with self.assertRaises(ValueError):
                    client.read_config()

    def test_profile_preserves_vless_and_never_exports_server_awg_key(self):
        options = OPTIONS | {'amnezia': {'enabled': True, 'active': True}}
        host = HOST | {'awg_uid': 994}
        identity = KEYS | {'amnezia': self.keys}
        value = node_config.export_profile(options, host, identity)
        self.assertEqual(value['channel'], 'amnezia')
        self.assertEqual(value['outbound']['protocol'], 'vless')
        self.assertTrue(self.keys['server_private'] not in json.dumps(value), 'server key stays on node')
        peer = {'id':'22222222-2222-4222-8222-222222222222','name':'panel','enabled':True}
        external = node_config.export_profile(options, host, identity, peer)
        self.assertNotIn('amnezia', external)
        self.assertNotIn('channel', external)
        with self.assertRaises(ValueError):
            node_config.settings(options | {'wireguard': {'enabled':True,'active':True}})

    def test_slow_child_exit_does_not_kill_supervisor_or_reuse_its_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            carrier = client.Carriers.__new__(client.Carriers)
            process = Mock()
            process.poll.return_value = None
            process.wait.side_effect = subprocess.TimeoutExpired('fixture', 2)
            carrier.active, carrier.retry = {0: (self.row, process)}, {}
            with patch.object(client, 'ROOT', Path(directory)):
                carrier.sync({})
                self.assertIn(0, carrier.active, 'unreaped child still owns its slot')
                process.kill.assert_called_once()
                process.poll.return_value = -9
                carrier.sync({})
                self.assertEqual(carrier.active, {})

    @unittest.skipUnless(os.geteuid() == 0, 'native root fixture')
    def test_restricted_child_can_read_only_its_generated_file(self):
        # The supervisor starts under UMask=0077, as in the container.
        # The child must traverse the directory but cannot replace any file.
        with tempfile.TemporaryDirectory(prefix='awg-test-', dir='/run') as directory:
            parent = Path(directory)
            parent.chmod(0o711)
            old = os.umask(0o077)
            try:
                with patch.object(client, 'ROOT', parent/'carriers'):
                    client.Carriers()
                    permissions = client.ROOT.stat().st_mode & 0o777
                    self.assertEqual(permissions, 0o711, 'carrier directory must allow unprivileged traversal')
            finally:
                os.umask(old)


if __name__ == '__main__':
    unittest.main()
