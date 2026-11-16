"""NOD-01: a failed re-enrollment must not destroy the only controller key.

Re-adding a removed node adopts its archived (retired) key. If writing
endpoint.json then fails, the card stays unconnected; removing that card must
still leave the archived key for the next attempt. Inert synthetic key pairs.
"""
import base64
import errno
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import node_ssh as transport


def public(letter):
    return 'ssh-ed25519 ' + base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + letter * 32).decode()


HOST = public(b'h')
TARGET = dict(address='1.1.1.1', port=22, host_key=HOST)  # never contacted: request() is patched


class RetiredKeyEndpointTest(unittest.TestCase):
    def setUp(self):
        self.mask = os.umask(0o077)
        self.addCleanup(os.umask, self.mask)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'nodes'
        self.client = transport.Client('11223344', self.root)
        self.archive = transport.retired_directory(self.root, HOST)
        self.archive.mkdir(parents=True, mode=0o700)
        self.retired = {'key': b'SYNTHETIC-RETIRED-PRIVATE', 'key.pub': public(b'r').encode()}
        for name, body in self.retired.items():
            (self.client.directory / name).write_bytes(b'SYNTHETIC-FRESH-PRIVATE' if name == 'key' else public(b'f').encode())
            (self.archive / name).write_bytes(body)
        self.ping = 0

    def request(self, value, target=None):
        # The node rejects the fresh key and still trusts the retired one.
        self.ping += 1
        if (self.client.directory / 'key').read_bytes() == b'SYNTHETIC-FRESH-PRIVATE':
            raise ValueError('ssh_failed')
        return {'schema': 1}

    def connect(self, fail_endpoint):
        real_atomic = transport.atomic

        def atomic(path, body):
            if fail_endpoint and path.name == 'endpoint.json':
                raise OSError(errno.ENOSPC, 'synthetic endpoint failure')
            return real_atomic(path, body)
        with patch.object(transport, 'atomic', side_effect=atomic), patch.object(transport, 'validate_pair'), \
                patch.object(self.client, 'request', side_effect=self.request):
            return self.client.connect(TARGET)

    def archived(self):
        return {n: (self.archive / n).read_bytes() for n in self.retired if (self.archive / n).is_file()}

    def test_failed_endpoint_write_keeps_archived_key_after_card_removal(self):
        with self.assertRaises(OSError):
            self.connect(fail_endpoint=True)
        self.assertFalse((self.client.directory / 'endpoint.json').exists())
        # The administrator removes the unconnected card.
        self.client.forget()
        self.assertEqual(self.archived(), self.retired, 'the only key trusted by the node was destroyed')
        # A later attempt can still adopt it.
        self.client = transport.Client('11223344', self.root)
        (self.client.directory / 'key').write_bytes(b'SYNTHETIC-FRESH-PRIVATE')
        (self.client.directory / 'key.pub').write_bytes(public(b'f').encode())
        self.assertEqual(self.connect(fail_endpoint=False)['connected'], True)
        self.assertEqual((self.client.directory / 'key').read_bytes(), self.retired['key'])

    def test_successful_enrollment_consumes_the_archive(self):
        self.assertTrue(self.connect(fail_endpoint=False)['connected'])
        self.assertEqual(self.archived(), {})
        self.assertTrue((self.client.directory / 'endpoint.json').is_file())


if __name__ == '__main__':
    unittest.main()
