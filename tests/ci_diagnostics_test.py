#!/usr/bin/env python3
"""Encrypted failure diagnostics: nothing readable leaves the runner."""
import base64
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import ci_diagnostics as diag

SECRETS = {
    'github-token': b'token ghp_' + b'A' * 36,
    'github-pat': b'github_pat_' + b'B' * 40,
    # Built from parts: no literal key header in the repository for secret scanners.
    'private-key': b'-----BEGIN OPENSSH ' + b'PRIVATE KEY-----\nAAAAsecret\n-----END OPENSSH ' + b'PRIVATE KEY-----',
    'authorization': b'Authorization: Bearer abcdef123456',
    'basic-auth-url': b'https://user:pa55word@example.test/path',
    'jwt': b'eyJ' + b'hbGciOiJIUzI1NiJ9' + b'.eyJ' + b'zdWIiOiIxMjM0NTYifQ' + b'.c2lnbmF0dXJlLXZhbHVl',
    'telegram-bot-token': b'123456789:AAH' + b'x' * 32,
    'signed-url-query': b'https://ghcr.test/blob?sig=SECRETSIG&se=2026',
    'aws-key': b'AK' + b'IA' + b'ABCDEFGHIJKLMNOP',
}


class DiagnosticsTest(unittest.TestCase):
    def test_every_credential_format_is_redacted(self):
        for name, secret in SECRETS.items():
            with self.subTest(name):
                counts = {}
                out = diag.redact(b'before ' + secret + b'\nafter', counts, [])
                self.assertTrue(counts, name)
                for fragment in (b'AAAAsecret', b'pa55word', b'SECRETSIG', b'abcdef123456', b'A' * 36, b'B' * 40,
                                 b'x' * 32, b'ABCDEFGHIJKLMNOP', b'c2lnbmF0dXJlLXZhbHVl'):
                    self.assertNotIn(fragment, out)
                self.assertIn(b'before', out); self.assertIn(b'after', out)

    def test_forbidden_values_and_encodings_are_redacted(self):
        value = 'synthetic-runner-token-0123456789'
        with patch.dict(os.environ, {'CI_DIAG_FORBIDDEN_1': value}):
            values = diag.forbidden_values()
        data = b'a ' + value.encode() + b' b ' + base64.b64encode(value.encode()) + b' c ' + base64.b64encode(b'x-access-token:' + value.encode())
        counts = {}
        out = diag.redact(data, counts, values)
        self.assertNotIn(value.encode(), out)
        self.assertNotIn(base64.b64encode(value.encode()), out)
        self.assertEqual(counts['forbidden-value'], 3)

    def test_only_allow_listed_logs_are_collected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'root'
            files = {
                'private.log': b'START fresh-users\n', 'results/suite.log': b'ok\n',
                'stand/results/openconnect/results.json': b'[]', 'tests/module-cycle-results.json': b'[]',
                'masque-native/native_matrix.log': b'ok',
                # Never collected:
                'stand/bot/config/config.php': b'secret', 'stand/results/x/server.key': b'k',
                'stand/results/x/client.pem': b'p', 'stand/results/x/swanctl.conf': b'psk',
                'results/ssh/id_ed25519': b'k', 'masque-native/certs/cert_private': b'k',
                'masque-native/state/usage.json': b'{}', 'stand/results/backups/full.json': b'{}',
                'tests/driver.php': b'code', 'other/random.log': b'x',
            }
            for name, data in files.items():
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
            (root / 'results/link.log').symlink_to(root / 'stand/bot/config/config.php')
            outside = root.parent / (root.name + '-outside'); outside.mkdir(); (outside / 'leak.log').write_bytes(b'secret')
            (root / 'results/linked-dir').symlink_to(outside, target_is_directory=True)
            got = {p.relative_to(root).as_posix() for p in diag.candidates(root)}
            self.assertEqual(got, {'private.log', 'results/suite.log', 'stand/results/openconnect/results.json',
                                   'tests/module-cycle-results.json', 'masque-native/native_matrix.log'})

    def test_round_trip_encrypts_and_redacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'root'; (root / 'results').mkdir(parents=True)
            marker = b'PLAINTEXT-MARKER-0123456789'
            (root / 'results/suite.log').write_bytes(marker + b' ' + SECRETS['github-token'])
            key, cert, out = (Path(directory) / n for n in ('k.pem', 'c.pem', 'd.cms'))
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=test',
                            '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
            entries, counts = diag.collect(root, include_docker=False)
            diag.encrypt(diag.pack(entries), cert, out)
            cipher = out.read_bytes()
            self.assertNotIn(marker, cipher); self.assertNotIn(b'ghp_', cipher)
            plain = subprocess.run(['openssl', 'cms', '-decrypt', '-binary', '-inform', 'DER', '-in', str(out),
                                    '-inkey', str(key), '-recip', str(cert)], check=True, capture_output=True).stdout
            with tarfile.open(fileobj=io.BytesIO(plain)) as archive:
                data = archive.extractfile('stand/results/suite.log').read()
            self.assertIn(marker, data); self.assertNotIn(b'A' * 36, data); self.assertEqual(counts['github-token'], 1)
            self.assertEqual([p.name for p in Path(directory).iterdir() if p.name.endswith('.tar.gz')], [])

    def test_failure_prints_only_the_error_type(self):
        source = (Path(diag.__file__)).read_text()
        self.assertIn("print('Diagnostics not produced: ' + type(error).__name__", source)
        self.assertNotIn('print(path', source); self.assertNotIn('print(entries', source)


if __name__ == '__main__':
    unittest.main()
