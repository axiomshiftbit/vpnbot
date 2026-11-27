#!/usr/bin/env python3
import base64
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'app'))
import node_ssh as transport

KEY = 'ssh-ed25519 '+base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'+b'k'*32).decode()


class NodeSSH(unittest.TestCase):
    def test_tls_probe_crosses_controller_transport_without_target_arguments(self):
        reply={'tls':'TLSv1.3','alpn':'h2','record':36,'name':'node.example.test','own':True,'transport':'reality'}
        with tempfile.TemporaryDirectory() as tmp:
            client=transport.Client('aabbccdd',Path(tmp)/'nodes')
            with patch.object(client,'ssh',return_value=['fixture-ssh']),patch.object(transport,'run',return_value=transport.encode({'ok':True,'result':reply})) as run:
                self.assertEqual(client.request({'action':'tls_probe'},target={}),reply)
                self.assertEqual(transport.decode(run.call_args.args[1]),{'action':'tls_probe'})

    def busy_peer(self, directory, busy_count, status=1):
        counter = Path(directory)/'calls'
        code = '''from pathlib import Path
import json,sys
counter=Path(sys.argv[1]);n=int(counter.read_text()) if counter.exists() else 0
counter.write_text(str(n+1))
if n<int(sys.argv[2]):
 print('{"ok":false,"error":"busy"}');sys.exit(int(sys.argv[3]))
print('{"ok":true,"result":{"schema":1}}')
'''
        return [sys.executable, '-c', code, str(counter), str(busy_count), str(status)], counter

    def test_only_explicit_lock_busy_is_retried(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = transport.Client('aabbccdd', Path(tmp)/'nodes')
            command, counter = self.busy_peer(tmp, 3)
            with patch.object(client, 'ssh', return_value=command):
                reply = client.request({'action': 'ping'}, target={})
            self.assertEqual(reply, {'schema': 1})
            self.assertEqual(counter.read_text(), '4')

    def test_lists_missing_is_reported_once_and_distinctly(self):
        # Nothing was queued: the controller resends the lists in full, the transport does not retry.
        with tempfile.TemporaryDirectory() as tmp:
            client = transport.Client('aabbccdd', Path(tmp)/'nodes')
            counter = Path(tmp)/'calls'
            code = ('from pathlib import Path\nimport sys\np=Path(sys.argv[1]);p.write_text(str(int(p.read_text())+1) if p.exists() else "1")\n'
                    'print(\'{"ok":false,"error":"lists_missing"}\');sys.exit(1)\n')
            with patch.object(client, 'ssh', return_value=[sys.executable, '-c', code, str(counter)]), \
                    self.assertRaises(transport.ListsMissing):
                client.request({'action': 'submit', 'request': {'operation': 'restart', 'value': None}}, target={})
            self.assertEqual(counter.read_text(), '1')

    def test_busy_retries_are_bounded_and_ssh_failure_is_never_replayed(self):
        for action, status, expected in [('status', 1, 4), ('submit', 1, 4), ('confirm', 1, 1), ('submit', 255, 1)]:
            with tempfile.TemporaryDirectory() as tmp:
                client = transport.Client('aabbccdd', Path(tmp)/'nodes')
                command, counter = self.busy_peer(tmp, 100, status)
                with patch.object(client, 'ssh', return_value=command), self.assertRaises(ValueError):
                    client.request({'action': action, 'request': {}}, target={})
                self.assertEqual(counter.read_text(), str(expected))

    def test_only_literal_public_endpoints(self):
        for address in ('127.0.0.1', '192.168.0.1', '169.254.169.254', '::1', 'fd42::1',
                        '::ffff:127.0.0.1', '64:ff9b::7f00:1', '2002:7f00:1::', 'example.com',
                        '1.1.1.1;id', 'fe80::1%eth0', 'ff02::1'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                transport.endpoint(dict(address=address, port=22, host_key=KEY))
        for address in ('1.1.1.1', '2606:4700:4700::1111'):
            self.assertEqual(transport.endpoint(dict(address=address, port=2222, host_key=KEY))['address'], address)

    def test_host_key_type_blob_and_ports_strict(self):
        for key in ('ssh-rsa AAAA', KEY+'\ncommand=touch', KEY.replace('ssh-ed25519', 'other')):
            with self.assertRaises(ValueError):
                transport.key(key)
        for port in (True, '22', 0, 65536):
            with self.assertRaises(ValueError):
                transport.endpoint(dict(address='1.1.1.1', port=port, host_key=KEY))

    def test_json_limits_and_duplicates(self):
        for body in (b'{"id":1,"id":2}', b'{"id":NaN}', b' '*65537):
            with self.assertRaises(ValueError):
                transport.decode(body)

    def test_path_traversal_rejected(self):
        for identifier in ('../other', 'a'*9, 'a'*7, '/ssh/key'):
            with self.assertRaises(ValueError):
                transport.Client(identifier)

    def test_pin_required_and_agent_disabled(self):
        args = transport.arguments('/key', '/known', '1.1.1.1', 22, 'vpnbot-ctl')
        for value in ('StrictHostKeyChecking=yes', 'IdentityAgent=none', 'ForwardAgent=no', 'ClearAllForwardings=yes'):
            self.assertIn(value, args)
        self.assertNotIn('accept-new', args)

    def test_failed_connect_keeps_saved_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = transport.Client('aabbccdd', Path(tmp)/'nodes')
            path = client.directory/'endpoint.json'
            path.write_text('previous')
            with patch.object(client, 'public', return_value=KEY), patch.object(client, 'request', side_effect=ValueError()):
                with self.assertRaises(ValueError):
                    client.connect(dict(address='1.1.1.1', port=22, host_key=KEY))
            self.assertEqual(path.read_text(), 'previous')

    def test_peer_cannot_fill_disk_or_memory(self):
        with self.assertRaises(ValueError):
            transport.run([sys.executable, '-c', 'import sys;sys.stdout.write("x"*1000000)'])

    def test_timeout_stops_process_tree(self):
        import subprocess
        with self.assertRaises(subprocess.TimeoutExpired):
            transport.run([sys.executable, '-c', 'import time;time.sleep(30)'], timeout=.05)

    def test_saved_snapshot_is_bounded_and_content_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = transport.Client('aabbccdd', Path(tmp)/'nodes')
            path = client.directory/'snapshot.json'
            path.write_text('{"fixture":1}')
            first = client.saved()
            self.assertEqual(first['snapshot'], {'fixture': 1})
            path.write_text('{"fixture":2}')
            self.assertNotEqual(client.saved()['hash'], first['hash'])
            for body in ('[]', '{"x":1,"x":2}', ' '*65537):
                path.write_text(body)
                with self.assertRaises(ValueError):
                    client.saved()
            path.unlink()
            path.symlink_to('/dev/zero')
            with self.assertRaises(ValueError):
                client.saved()

    def test_uploaded_snapshot_replaces_saved_one_only_with_fixed_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = transport.Client('aabbccdd', Path(tmp)/'nodes')
            confirmed = client.directory/'snapshot.json'
            confirmed.write_text('{"fixture":1}')
            # Audit 26.11.2026 (C19): the upload waits beside the last confirmed copy.
            path = client.directory/transport.IMPORTED
            value = {'schema': 1, 'options': {'amnezia': {'parameters': {}}}, 'identity': {}, 'peers': [], 'images': {'xr': 'x'}, 'tls': {}}
            result = client.store(value)
            self.assertEqual(client.saved(True), result)
            self.assertEqual(confirmed.read_text(), '{"fixture":1}')
            self.assertEqual(transport.decode(path.read_bytes()), value)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            for bad in ([], value | {'extra': 1}, {k: v for k, v in value.items() if k != 'tls'}, value | {'schema': True}, value | {'schema': 2}):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    client.store(bad)
            self.assertEqual(transport.decode(path.read_bytes()), value)
            path.unlink()
            path.symlink_to(Path(tmp)/'elsewhere')
            with self.assertRaises(ValueError):
                client.store(value)
            self.assertFalse((Path(tmp)/'elsewhere').exists())

    def test_forget_only_own_fixed_files_and_no_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'nodes'
            client = transport.Client('aabbccdd', root)
            other = transport.Client('eeff0011', root)
            (other.directory/'key.pub').write_text('other')
            (client.directory/'endpoint.json').write_text('{}')
            (client.directory/'key').symlink_to(other.directory/'key.pub')
            with self.assertRaises(ValueError):
                client.forget()
            self.assertTrue((client.directory/'endpoint.json').exists())
            (client.directory/'key').unlink()
            with self.assertRaises(ValueError):
                client.forget()  # An enrolled node with missing keys is not disposable.
            (client.directory/'endpoint.json').unlink()
            self.assertEqual(client.forget(), {'forgotten': True})
            self.assertFalse(client.directory.exists())
            self.assertEqual((other.directory/'key.pub').read_text(), 'other')

    def test_archive_failure_preserves_original_pair_and_retry(self):
        import errno
        for failed_name in ('key', 'key.pub'):
            for code in (errno.ENOSPC, errno.EACCES):
                with self.subTest(file=failed_name, code=code), tempfile.TemporaryDirectory() as tmp:
                    client = transport.Client('aabbccdd', Path(tmp)/'nodes')
                    original = {'key': b'fixture-private', 'key.pub': b'fixture-public',
                                'endpoint.json': transport.encode(dict(address='1.1.1.1', port=22, host_key=KEY))}
                    for name, body in original.items():
                        (client.directory/name).write_bytes(body)
                    atomic = transport.atomic
                    def fail(path, body):
                        if transport.RETIRED in path.parts and path.name == failed_name:
                            raise OSError(code, 'injected archive failure')
                        return atomic(path, body)
                    with patch.object(transport, 'atomic', side_effect=fail), self.assertRaises(OSError):
                        client.forget()
                    for name, body in original.items():
                        self.assertEqual((client.directory/name).read_bytes(), body)
                    self.assertEqual(client.forget(), {'forgotten': True})
                    retired = transport.retired_directory(client.root, KEY)
                    for name in ('key', 'key.pub'):
                        self.assertEqual((retired/name).read_bytes(), original[name])
                        self.assertEqual((retired/name).stat().st_mode & 0o777, 0o600)

    def retired_setup(self, root, host_key=KEY):
        # These existing transport fixtures contain inert labels, not SSH keys.
        validation = patch.object(transport, 'validate_pair')
        validation.start()
        self.addCleanup(validation.stop)
        old = transport.Client('aabbccdd', root)
        (old.directory/'key').write_text('old-private'); (old.directory/'key.pub').write_text('old-public')
        (old.directory/'endpoint.json').write_bytes(transport.encode(dict(address='1.1.1.1', port=22, host_key=host_key)))
        self.assertEqual(old.forget(), {'forgotten': True})
        new = transport.Client('11223344', root)
        (new.directory/'key').write_text('fresh-private'); (new.directory/'key.pub').write_text('fresh-public')
        return new, transport.retired_directory(root, host_key)

    def test_removed_node_key_is_reused_when_the_server_rejects_a_new_one(self):
        target = dict(address='1.1.1.1', port=22, host_key=KEY)
        with tempfile.TemporaryDirectory() as tmp:
            new, retired = self.retired_setup(Path(tmp)/'nodes')
            self.assertEqual((retired/'key').read_text(), 'old-private')
            self.assertEqual((retired/'key').stat().st_mode & 0o777, 0o600)
            used = []
            def request(body, target=None):
                used.append((new.directory/'key').read_text())
                if used[-1] != 'old-private': raise ValueError('ssh_failed')
                return {'schema': 1}
            with patch.object(new, 'public', return_value=KEY), patch.object(new, 'request', side_effect=request):
                self.assertTrue(new.connect(target)['connected'])
            self.assertEqual(used, ['fresh-private', 'old-private'])
            self.assertEqual((new.directory/'key').read_text(), 'old-private')
            self.assertEqual((new.directory/'key.pub').read_text(), 'old-public')
            self.assertFalse(retired.exists())
            self.assertTrue((new.directory/'endpoint.json').exists())

    def test_new_key_wins_and_failed_reuse_restores_fresh_key(self):
        target = dict(address='1.1.1.1', port=22, host_key=KEY)
        with tempfile.TemporaryDirectory() as tmp:
            new, retired = self.retired_setup(Path(tmp)/'nodes')
            with patch.object(new, 'public', return_value=KEY), patch.object(new, 'request', return_value={'schema': 1}):
                new.connect(target)
            self.assertEqual((new.directory/'key').read_text(), 'fresh-private')
            self.assertTrue(retired.exists(), 'a reinstalled node with the new key keeps the archive untouched')
        with tempfile.TemporaryDirectory() as tmp:
            new, retired = self.retired_setup(Path(tmp)/'nodes')
            with patch.object(new, 'public', return_value=KEY), patch.object(new, 'request', side_effect=ValueError('ssh_failed')), \
                    self.assertRaises(ValueError):
                new.connect(target)
            self.assertEqual((new.directory/'key').read_text(), 'fresh-private')
            self.assertEqual((new.directory/'key.pub').read_text(), 'fresh-public')
            self.assertEqual((retired/'key').read_text(), 'old-private')
            self.assertFalse((new.directory/'endpoint.json').exists())

    def test_busy_node_or_other_server_never_gets_a_retired_key(self):
        other = 'ssh-ed25519 '+base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'+b'z'*32).decode()
        for host_key, error in ((KEY, transport.NodeBusy('node_busy')), (other, ValueError('ssh_failed'))):
            with self.subTest(host_key=host_key[-6:], error=type(error).__name__), tempfile.TemporaryDirectory() as tmp:
                new, retired = self.retired_setup(Path(tmp)/'nodes', host_key=KEY)
                with patch.object(new, 'public', return_value=KEY), patch.object(new, 'request', side_effect=error) as request, \
                        self.assertRaises(ValueError):
                    new.connect(dict(address='1.1.1.1', port=22, host_key=host_key))
                self.assertEqual(request.call_count, 1)
                self.assertEqual((new.directory/'key').read_text(), 'fresh-private')
                self.assertEqual((retired/'key').read_text(), 'old-private')

    def test_reconnect_keeps_pin_and_commits_only_healthy_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = transport.Client('aabbccdd', Path(tmp)/'nodes')
            path = client.directory/'endpoint.json'
            before = dict(address='1.1.1.1', port=22, host_key=KEY)
            target = dict(address='2606:4700:4700::1111', port=2222)
            status = dict(running=True, pending=None)
            for outcome in (ValueError('unreachable'), [{'schema': 1}, dict(running=True, pending={'id': 'busy'})],
                            [{'schema': 1}, dict(running=False, pending=None)]):
                transport.atomic(path, transport.encode(before))
                with patch.object(client, 'request', side_effect=outcome), self.assertRaises(ValueError):
                    client.reconnect(target)
                self.assertEqual(transport.decode(path.read_bytes()), before)
            with patch.object(client, 'request', side_effect=[{'schema': 1}, status]) as request:
                self.assertEqual(client.reconnect(target), {'status': status})
                self.assertEqual(request.call_args.args[1], before | target)
            self.assertEqual(transport.decode(path.read_bytes()), before | target)
            with self.assertRaises(ValueError):
                client.reconnect(target | {'host_key': KEY})

    def test_explicit_rebind_checks_new_pin_without_touching_snapshot(self):
        new_key = 'ssh-ed25519 '+base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'+b'n'*32).decode()
        with tempfile.TemporaryDirectory() as tmp:
            client = transport.Client('aabbccdd', Path(tmp)/'nodes')
            path = client.directory/'endpoint.json'
            before = dict(address='1.1.1.1', port=22, host_key=KEY)
            target = before | {'host_key': new_key}
            snapshot = client.directory/'snapshot.json'
            snapshot.write_text('{"fixture":"saved"}')
            for outcome in (ValueError('host_pin'), [{'schema': 1}, {'running': False}],
                            [{'schema': 1}, {'running': True, 'pending': {'id': 'busy'}}]):
                transport.atomic(path, transport.encode(before))
                with patch.object(client, 'request', side_effect=outcome), self.assertRaises(ValueError):
                    client.rebind(target)
                self.assertEqual(transport.decode(path.read_bytes()), before)
            status = dict(running=True, pending=None)
            with patch.object(client, 'request', side_effect=[{'schema': 1}, status]) as request:
                self.assertEqual(client.rebind(target), {'status': status})
                self.assertEqual(request.call_args.args[1], target)
            self.assertEqual(transport.decode(path.read_bytes()), target)
            self.assertEqual(snapshot.read_text(), '{"fixture":"saved"}')

    def test_reconnect_has_one_deadline_within_php_transport_timeout(self):
        import subprocess
        elapsed = [0.0]
        budgets = []
        def peer(args, body, timeout, rpc, limit=transport.LIMIT):
            budgets.append(timeout)
            if timeout < 14:
                elapsed[0] += timeout
                raise subprocess.TimeoutExpired(args, timeout)
            elapsed[0] += 14
            action = transport.decode(body)['action']
            return transport.encode({'ok': True, 'result': {'schema': 1} if action == 'ping' else {'running': True, 'pending': None}})
        with tempfile.TemporaryDirectory() as tmp, patch.object(transport.time, 'monotonic', side_effect=lambda: elapsed[0]):
            client = transport.Client('aabbccdd', Path(tmp)/'nodes')
            before = dict(address='1.1.1.1', port=22, host_key=KEY)
            path = client.directory/'endpoint.json'
            transport.atomic(path, transport.encode(before))
            with patch.object(client, 'ssh', return_value=['synthetic-peer']), patch.object(transport, 'run', side_effect=peer):
                with self.assertRaises(subprocess.TimeoutExpired):
                    client.reconnect(dict(address='8.8.8.8', port=22))
            self.assertLessEqual(elapsed[0], 20)
            self.assertEqual(budgets, [15, 6])
            self.assertEqual(transport.decode(path.read_bytes()), before)


if __name__ == '__main__':
    unittest.main()
