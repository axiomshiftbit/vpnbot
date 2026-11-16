"""Архивы только из доверенного пути и только на пустую установку; без исполнения проекта."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def function(source, name):
    return re.search(r'^' + re.escape(name) + r'\(\) \{\n.*?^\}', source, re.M | re.S).group()


@unittest.skipUnless(shutil.which('bash') and shutil.which('unzip') and shutil.which('rsync'), 'нужны bash, unzip, rsync')
class ArchiveInstallTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.archive = self.root / 'source.zip'
        with zipfile.ZipFile(self.archive, 'w') as archive:
            archive.writestr('app/example.txt', 'fresh code')
            archive.writestr('config/state.json', '{"synthetic":"default"}')
            # The installer records the commit from the ZIP comment (INS-03).
            archive.write(ROOT / 'scripts/image_bundle.py', 'scripts/image_bundle.py')
            archive.comment = b'e' * 40
        source = (ROOT / 'scripts/init.sh').read_text()
        self.functions = '\n'.join(function(source, name) for name in ('archive_target_empty', 'install_from_archive'))

    def install(self, target):
        return subprocess.run(['bash', '-c', 'set -euo pipefail\n' + self.functions + '\ninstall_from_archive'],
                              env=os.environ | {'ARCHIVE': str(self.archive), 'INSTALL_DIR': str(target), 'BRANCH': 'dev'},
                              capture_output=True, text=True)

    def test_existing_installation_and_git_are_untouched(self):
        target = self.root / 'target'; (target / '.git').mkdir(parents=True); (target / 'config').mkdir()
        files = {'.git/sentinel': b'original repository', 'config/state.json': b'{"synthetic":"runtime"}'}
        for name, data in files.items(): (target / name).write_bytes(data)
        result = self.install(target)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('штатное обновление', result.stderr)
        self.assertEqual({str(p.relative_to(target)): p.read_bytes() for p in target.rglob('*') if p.is_file()}, files)

    def test_empty_installation_succeeds(self):
        for exists in (False, True):
            target = self.root / ('target-' + str(exists))
            if exists: target.mkdir()
            result = self.install(target)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((target / 'app/example.txt').read_text(), 'fresh code')
            self.assertEqual((target / 'update/archive-source').read_text(), 'e' * 40 + '\n')

    def test_archive_without_commit_id_is_refused(self):
        with zipfile.ZipFile(self.archive, 'a') as archive:
            archive.comment = b''
        result = self.install(self.root / 'target')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('commit id', result.stderr)

    def test_symlink_installation_is_rejected(self):
        actual = self.root / 'actual'; actual.mkdir(); target = self.root / 'link'; target.symlink_to(actual)
        self.assertNotEqual(self.install(target).returncode, 0)
        self.assertEqual(list(actual.iterdir()), [])


@unittest.skipUnless(os.geteuid() == 0, 'положительный ownership-контроль требует root тестового namespace')
class ArchiveTrustTest(unittest.TestCase):
    def setUp(self):
        # /tmp намеренно недоверенный. На CI/root namespace используется новый
        # приватный каталог под /root; чужие файлы не читаются.
        Path('/root').mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix='archive-trust-', dir='/root')
        self.addCleanup(self.tmp.cleanup); self.root = Path(self.tmp.name)
        self.archive = self.root / 'vpnbot.zip'; self.archive.write_bytes(b'inert archive selector fixture')
        source = (ROOT / 'scripts/init.sh').read_text(); self.trusted_function = function(source, 'trusted_archive')
        self.selector = (self.trusted_function + '\n' + function(source, 'archive_target_empty') + '\n'
                         + source[source.index('ARCHIVE=""'):source.index('export DEBIAN_FRONTEND=noninteractive')])

    def trusted(self, path):
        return subprocess.run(['bash', '-c', self.trusted_function + '\ntrusted_archive "$1"', 'test', str(path)],
                              capture_output=True).returncode == 0

    def test_file_and_parent_permissions_and_symlinks(self):
        self.assertTrue(self.trusted(self.archive))
        self.archive.chmod(0o666); self.assertFalse(self.trusted(self.archive)); self.archive.chmod(0o600)
        self.root.chmod(0o777); self.assertFalse(self.trusted(self.archive)); self.root.chmod(0o700)
        link = self.root / 'link.zip'; link.symlink_to(self.archive); self.assertFalse(self.trusted(link))
        os.chown(self.archive, 65534, 65534); self.assertFalse(self.trusted(self.archive))

    def select(self, explicit='', script_dir=None, cwd=None):
        return subprocess.run(['bash', '-c', 'set -euo pipefail\n' + self.selector
                               + '\nprintf "SELECTED=%s\\nAPT_REACHED\\n" "$ARCHIVE"'],
                              cwd=cwd, capture_output=True, text=True,
                              env=os.environ | {'VPNBOT_ARCHIVE': str(explicit),
                                  'SCRIPT_DIR': str(script_dir or self.root),
                                  'ARCHIVE_NAME': 'vpnbot.zip', 'INSTALL_DIR': str(self.root / 'target')})

    def test_explicit_invalid_archive_fails_without_fallback(self):
        result = self.select(self.root / 'absent.zip')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('APT_REACHED', result.stdout)
        self.assertEqual(self.select(self.archive).returncode, 0)

    def test_implicit_cwd_archive_is_not_selected(self):
        script_dir = self.root / 'safe/scripts'; script_dir.mkdir(parents=True)
        result = self.select(script_dir=script_dir, cwd=self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('SELECTED=' + str(self.archive), result.stdout)

    def test_populated_installation_rejected_before_package_setup(self):
        target = self.root / 'target'; target.mkdir(); (target / 'sentinel').write_text('preserve')
        result = self.select(self.archive)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('APT_REACHED', result.stdout)
        self.assertEqual((target / 'sentinel').read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main()
