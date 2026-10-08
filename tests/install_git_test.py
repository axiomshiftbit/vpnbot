#!/usr/bin/env python3
"""Установка из git: deploy-ключ, привязка кода к опубликованному комплекту."""
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STUB = '''import json, os, sys
open(sys.argv[3], 'w').write(json.dumps({'source': os.environ['RELEASED']}))
'''


@unittest.skipUnless(all(shutil.which(tool) for tool in ('bash', 'git', 'ssh-keygen')), 'нужны bash, git и ssh-keygen')
class InstallFromGitTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        source = (ROOT / 'scripts/init.sh').read_text()
        functions = re.search(r'^DEPLOY_DIR=.*?(?=^SCRIPT_DIR=)', source, re.M | re.S).group()
        functions += re.search(r'^install_from_git\(\) \{.*?^\}\n', source, re.M | re.S).group()
        self.script = self.tmp / 'run.sh'
        self.script.write_text('set -euo pipefail\nINSTALL_DIR=$1; BRANCH=dev; ARCHIVE_NAME=vpnbot.zip\n'
                               + functions + f'CRED_FILE={self.tmp}/cred\ninstall_from_git\n')
        self.env = os.environ | {'GIT_CONFIG_GLOBAL': str(self.tmp / 'gitconfig'), 'GIT_CONFIG_NOSYSTEM': '1'}
        (self.tmp / 'gitconfig').write_text('[user]\n\tname = t\n\temail = t@example.invalid\n[init]\n\tdefaultBranch = master\n')
        self.origin = self.tmp / 'origin'
        self.git('init', '-q', '-b', 'dev', self.origin)
        (self.origin / 'scripts').mkdir()
        (self.origin / 'update').mkdir()
        (self.origin / 'scripts/image_bundle.py').write_text(STUB)
        (self.origin / 'update/update.sh').write_text('')
        self.released = self.commit('released')
        self.head = self.commit('not released yet')
        self.target = self.tmp / 'vpnbot'

    def git(self, *args, cwd=None):
        return subprocess.run(['git', *map(str, args)], cwd=cwd, env=self.env, check=True,
                              capture_output=True, text=True).stdout.strip()

    def commit(self, message):
        self.git('add', '-A', cwd=self.origin)
        self.git('commit', '-q', '--allow-empty', '-m', message, cwd=self.origin)
        return self.git('rev-parse', 'HEAD', cwd=self.origin)

    def install(self, url=None):
        env = self.env | {'REPO_URL': str(url or self.origin), 'RELEASED': self.released}
        return subprocess.run(['bash', str(self.script), str(self.target)], env=env, capture_output=True, text=True)

    def test_fresh_install_uses_released_commit_and_private_key_files(self):
        result = self.install()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(self.released, self.git('rev-parse', 'HEAD', cwd=self.target))
        self.assertEqual('dev', self.git('rev-parse', '--abbrev-ref', 'HEAD', cwd=self.target))
        self.assertEqual('origin/dev', self.git('rev-parse', '--abbrev-ref', 'dev@{u}', cwd=self.target))
        self.assertEqual('ssh -F .git/vpnbot-readonly-ssh/config', self.git('config', 'core.sshCommand', cwd=self.target))
        keys = self.target / '.git/vpnbot-readonly-ssh'
        self.assertEqual(0o700, stat.S_IMODE(keys.stat().st_mode))
        for name in ('id_ed25519', 'config', 'known_hosts'):
            self.assertEqual(0o600, stat.S_IMODE((keys / name).stat().st_mode), name)
        key = (keys / 'id_ed25519').read_bytes()
        # Активная установка: повторный запуск не трогает ни код, ни ключ.
        (self.target / 'update/image-bundle.json').write_text('{}')
        self.released = self.head
        self.assertEqual(0, self.install().returncode)
        self.assertNotEqual(self.head, self.git('rev-parse', 'HEAD', cwd=self.target))
        self.assertEqual(key, (keys / 'id_ed25519').read_bytes())

    def test_rejected_key_keeps_token_installation_working(self):
        self.git('init', '-q', self.target)
        self.git('remote', 'add', 'origin', 'https://example.invalid/vpnbot.git', cwd=self.target)
        self.git('config', 'credential.helper', 'store --file=' + str(self.tmp / 'cred'), cwd=self.target)
        (self.tmp / 'cred').write_text('kept')
        result = self.install(self.tmp / 'missing')
        self.assertEqual(1, result.returncode)
        self.assertIn('ssh-ed25519 ', result.stderr)
        self.assertEqual('https://example.invalid/vpnbot.git', self.git('config', 'remote.origin.url', cwd=self.target))
        self.assertIn('store --file=', self.git('config', 'credential.helper', cwd=self.target))
        self.assertEqual('kept', (self.tmp / 'cred').read_text())

    def test_accepted_key_removes_token(self):
        self.git('init', '-q', self.target)
        self.git('remote', 'add', 'origin', 'https://example.invalid/vpnbot.git', cwd=self.target)
        self.git('config', 'credential.helper', 'store --file=' + str(self.tmp / 'cred'), cwd=self.target)
        (self.tmp / 'cred').write_text('token')
        self.assertEqual(0, self.install().returncode)
        self.assertEqual(str(self.origin), self.git('config', 'remote.origin.url', cwd=self.target))
        self.assertFalse((self.tmp / 'cred').exists())
        self.assertEqual(1, subprocess.run(['git', 'config', 'credential.helper'], cwd=self.target, env=self.env).returncode)


if __name__ == '__main__':
    unittest.main()
