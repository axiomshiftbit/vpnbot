from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/backup_file.py'


class BackupFileTests(unittest.TestCase):
    def test_success_and_export_failures_keep_a_private_usable_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'docker'
            binary.write_text('#!' + sys.executable + '\n'
                              'import pathlib, sys\n'
                              'assert sys.argv[1:] == ["compose", "exec", "-T", "php", "timeout", "900", "php", "backup.php"]\n'
                              'mode = pathlib.Path("mode").read_text()\n'
                              'sys.stdout.write({"ok": \'{"pac":{"limitpage":5}}\', "partial": \'{"pac":\', '
                              '"invalid": "not JSON", "nan": \'{"pac":{"bad":NaN}}\', "empty": ""}.get(mode, "x" * (21 * 1024 * 1024)))\n'
                              'sys.exit(23 if mode in ("partial", "empty") else 0)\n')
            binary.chmod(0o700)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'])
            for mode in ('ok', 'partial', 'invalid', 'nan', 'empty', 'large'):
                with self.subTest(mode=mode):
                    (root / 'mode').write_text(mode)
                    previous = (root / 'backup.json').read_bytes() if mode != 'ok' else None
                    result = subprocess.run([sys.executable, str(SCRIPT)], cwd=root, env=env,
                                            capture_output=True, umask=0o022)
                    if mode == 'ok':
                        self.assertEqual(0, result.returncode)
                        self.assertEqual(b'{"pac":{"limitpage":5}}', (root / 'backup.json').read_bytes())
                        self.assertEqual(0o600, (root / 'backup.json').stat().st_mode & 0o777)
                    else:
                        self.assertNotEqual(0, result.returncode)
                        self.assertEqual(previous, (root / 'backup.json').read_bytes())
                    self.assertEqual([], list(root.glob('.backup-*.tmp')))
                    self.assertNotIn(b'limitpage', result.stdout + result.stderr)

    def test_stalled_export_preserves_previous_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'backup.json').write_bytes(b'previous')
            binary = root / 'docker'
            binary.write_text('#!' + sys.executable + '\nimport time\ntime.sleep(60)\n')
            binary.chmod(0o700)
            code = ('import runpy; from pathlib import Path; m=runpy.run_path(' + repr(str(SCRIPT))
                    + '); m["save"].__globals__["EXPORT_TIMEOUT"]=.01; m["save"](Path("backup.json"))')
            result = subprocess.run([sys.executable, '-c', code], cwd=root,
                                    env=dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH']),
                                    capture_output=True, timeout=8)
            self.assertNotEqual(0, result.returncode)
            self.assertEqual(b'previous', (root / 'backup.json').read_bytes())
            self.assertEqual([], list(root.glob('.backup-*.tmp')))


if __name__ == '__main__':
    unittest.main()
