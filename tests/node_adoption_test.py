"""Crash/fault/concurrency tests of transport pair adoption; inert pair fixtures."""
import base64
import errno
import multiprocessing
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import node_ssh as transport


def public(letter):
    return 'ssh-ed25519 ' + base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + letter * 32).decode()


HOST = public(b'h')
TARGET = dict(address='1.1.1.1', port=22, host_key=HOST)


class NodeAdoptionTest(unittest.TestCase):
    def setUp(self):
        self.mask = os.umask(0o077)
        self.addCleanup(os.umask, self.mask)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'nodes'
        self.client = transport.Client('11223344', self.root)
        self.archive = transport.retired_directory(self.root, HOST)
        self.archive.mkdir(parents=True, mode=0o700)
        self.fresh = {'key': b'SYNTHETIC-FRESH-PRIVATE', 'key.pub': public(b'f').encode()}
        self.retired = {'key': b'SYNTHETIC-RETIRED-PRIVATE', 'key.pub': public(b'r').encode()}
        for name in self.fresh:
            (self.client.directory / name).write_bytes(self.fresh[name])
            (self.archive / name).write_bytes(self.retired[name])
        (self.client.directory / 'snapshot.json').write_bytes(b'{"synthetic":"metadata"}')

    def assert_pair(self, expected):
        for name, body in expected.items():
            self.assertEqual((self.client.directory / name).read_bytes(), body)
        self.assertEqual((self.client.directory / 'snapshot.json').read_bytes(), b'{"synthetic":"metadata"}')

    def test_staging_failures_never_publish_half_a_pair(self):
        real_atomic = transport.atomic
        for name in ('key', 'key.pub'):
            def atomic(path, body):
                if path.parent.name.startswith('.adopt-') and path.name == name:
                    raise OSError(errno.ENOSPC, 'synthetic staging failure')
                return real_atomic(path, body)
            with self.subTest(name=name), patch.object(transport, 'atomic', side_effect=atomic), \
                 patch.object(transport, 'validate_pair'), patch.object(self.client, 'request') as request:
                with self.assertRaises(OSError): self.client.adopt_retired(TARGET)
                request.assert_not_called()
                self.assert_pair(self.fresh)
                self.assertTrue(all((self.archive / n).read_bytes() == b for n, b in self.retired.items()))

    def test_failed_validation_ping_or_exchange_preserves_active_pair(self):
        for stage in ('validation', 'ping', 'exchange'):
            with self.subTest(stage=stage), \
                 patch.object(transport, 'validate_pair', side_effect=ValueError('mismatch') if stage == 'validation' else None), \
                 patch.object(self.client, 'request', side_effect=ValueError('ssh_failed') if stage == 'ping' else None,
                              return_value={'schema': 1}), \
                 patch.object(transport, 'exchange_directories', side_effect=OSError(errno.ENOTSUP, 'unsupported')):
                with self.assertRaises((ValueError, OSError)): self.client.adopt_retired(TARGET)
                self.assert_pair(self.fresh)
                self.assertTrue(self.archive.exists())

    def test_public_waits_for_candidate_ping_and_atomic_exchange(self):
        ctx = multiprocessing.get_context('fork')
        waiting, release = ctx.Event(), ctx.Event()
        reader, writer = ctx.Pipe(duplex=False)
        def adoption():
            client = transport.Client('11223344', self.root)
            def ping(*args):
                waiting.set()
                if not release.wait(5): raise RuntimeError('test timeout')
                return {'schema': 1}
            with patch.object(transport, 'validate_pair'), patch.object(client, 'request', side_effect=ping):
                client.adopt_retired(TARGET)
        def reading():
            writer.send(transport.Client('11223344', self.root).public())
            writer.close()
        adopter = ctx.Process(target=adoption); adopter.start()
        observer = None
        try:
            self.assertTrue(waiting.wait(5))
            self.assert_pair(self.fresh)
            observer = ctx.Process(target=reading); observer.start()
            self.assertFalse(reader.poll(.2), 'public must wait for the complete SSH action')
            release.set()
            self.assertTrue(reader.poll(5))
            self.assertEqual(reader.recv(), public(b'r'))
            adopter.join(5); observer.join(5)
            self.assertEqual(adopter.exitcode, 0); self.assertEqual(observer.exitcode, 0)
            self.assert_pair(self.retired)
        finally:
            release.set()
            for process in (adopter, observer):
                if process is not None:
                    if process.is_alive(): process.terminate()
                    process.join(5)
            reader.close(); writer.close()

    def test_process_exit_before_or_after_exchange_keeps_a_complete_pair(self):
        ctx = multiprocessing.get_context('fork')
        for after in (False, True):
            real_exchange = transport.exchange_directories
            def child():
                client = transport.Client('11223344', self.root)
                def exchange(first, second):
                    if after: real_exchange(first, second)
                    os._exit(42)
                with patch.object(transport, 'validate_pair'), patch.object(client, 'request', return_value={'schema': 1}), \
                     patch.object(transport, 'exchange_directories', side_effect=exchange):
                    client.adopt_retired(TARGET)
            process = ctx.Process(target=child); process.start(); process.join(5)
            try:
                self.assertEqual(process.exitcode, 42)
                self.assert_pair(self.retired if after else self.fresh)
                self.assertTrue(self.archive.exists())
                self.assertEqual(transport.Client('11223344', self.root).public(), public(b'r' if after else b'f'))
            finally:
                if process.is_alive(): process.terminate(); process.join(5)

    @unittest.skipUnless(shutil.which('ssh-keygen'), 'нужен ssh-keygen')
    def test_derived_public_validation_rejects_mismatched_pair(self):
        # Generate new synthetic keys; never read their private material in the test.
        directory = Path(self.tmp.name) / 'generated'; directory.mkdir(mode=0o700)
        for name in ('key', 'other'):
            result = subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(directory / name)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertEqual(result.returncode, 0)
        transport.validate_pair(directory)
        (directory / 'key.pub').write_bytes((directory / 'other.pub').read_bytes())
        with self.assertRaisesRegex(ValueError, 'controller_key_mismatch'): transport.validate_pair(directory)


if __name__ == '__main__':
    unittest.main()
