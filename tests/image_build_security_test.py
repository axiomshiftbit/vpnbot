import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ImageBuildSecurityTests(unittest.TestCase):
    def test_security_pins_keep_newer_transitive_dependencies_and_do_not_add_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / 'modules.json'
            state.write_text(json.dumps({'google.golang.org/grpc': 'v1.50.1',
                                         'golang.org/x/crypto': 'v0.21.0',
                                         'golang.org/x/net': 'v0.60.0'}))
            go = root / 'go'
            go.write_text('''#!/usr/bin/env python3
import json,pathlib,sys
p=pathlib.Path(__file__).with_name('modules.json');modules=json.loads(p.read_text())
if sys.argv[1]=='list':
 for name,version in modules.items():print(name,version)
else:
 name,version=sys.argv[-1].split('@');assert name in modules
 # Model grpc selecting a newer crypto via minimum version selection.
 assert name=='google.golang.org/grpc' and version=='v1.83.2'
 modules[name]=version;modules['golang.org/x/crypto']='v0.57.0'
 p.write_text(json.dumps(modules))
''')
            go.chmod(0o700)
            result = subprocess.run(['sh', str(ROOT / 'dockerfile/go-security.sh')],
                                    env=os.environ | {'PATH': str(root) + ':' + os.environ['PATH']},
                                    capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual({'google.golang.org/grpc': 'v1.83.2', 'golang.org/x/crypto': 'v0.57.0',
                              'golang.org/x/net': 'v0.60.0'}, json.loads(state.read_text()))

    def test_unreviewed_source_is_rejected_before_download(self):
        result = subprocess.run(['sh', str(ROOT / 'dockerfile/go-source.sh'), 'example/core', 'v1.0.0',
                                 '/unused', 'bad-checksum'], capture_output=True, text=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('контрольной суммы', result.stderr)

    def test_moved_tag_keeps_reviewed_commit_and_checksum_enforcement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / 'go-source.sh'
            script.write_bytes((ROOT / 'dockerfile/go-source.sh').read_bytes())
            commit = 'a' * 40
            for name, revision in [('reviewed', commit), ('moved', 'b' * 40)]:
                with tarfile.open(root / (name + '.tar.gz'), 'w:gz',
                                  pax_headers={'comment': revision}) as archive:
                    info = tarfile.TarInfo('core/source.txt')
                    payload = b'reviewed source\n'
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
            checksum = hashlib.sha256((root / 'reviewed.tar.gz').read_bytes()).hexdigest()
            curl = root / 'curl'
            curl.write_text('''#!/usr/bin/env python3
import pathlib,shutil,sys
root=pathlib.Path(__file__).parent
url=next(arg for arg in sys.argv if arg.startswith('https://'))
(root/'requested-url').write_text(url)
archive='moved' if '/refs/tags/' in url else 'reviewed'
shutil.copyfile(root/(archive+'.tar.gz'),sys.argv[sys.argv.index('-o')+1])
''')
            curl.chmod(0o700)
            manifest = root / 'go-sources.sha256'
            destination = root / 'source'
            env = os.environ | {'PATH': str(root) + ':' + os.environ['PATH']}

            def fetch(pin='', digest=checksum):
                manifest.write_text(f'{digest}  example/core/v1  {pin}\n')
                return subprocess.run(['sh', str(script), 'example/core', 'v1', str(destination)],
                                      env=env, capture_output=True, text=True)

            self.assertNotEqual(0, fetch().returncode)
            self.assertFalse((destination / 'source.txt').exists())
            self.assertEqual(0, fetch(commit).returncode)
            self.assertEqual(b'reviewed source\n', (destination / 'source.txt').read_bytes())
            self.assertTrue((root / 'requested-url').read_text().endswith('/' + commit))
            (destination / 'source.txt').unlink()
            self.assertNotEqual(0, fetch(commit, '0' * 64).returncode)
            self.assertFalse((destination / 'source.txt').exists())
            (root / 'requested-url').unlink()
            self.assertNotEqual(0, fetch('unreviewed-branch').returncode)
            self.assertFalse((root / 'requested-url').exists())

            # Callers supplying a checksum explicitly still use the requested tag.
            manifest.write_text('')
            digest = hashlib.sha256((root / 'moved.tar.gz').read_bytes()).hexdigest()
            result = subprocess.run(['sh', str(script), 'example/core', 'v1', str(destination), digest],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue((root / 'requested-url').read_text().endswith('/refs/tags/v1'))

    def test_external_test_code_is_part_of_admission_identity(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        self.addCleanup(lambda: sys.path.remove(str(ROOT / 'scripts')))
        spec = importlib.util.spec_from_file_location('ci_test_bundle', ROOT / 'scripts/ci_test_bundle.py')
        ci = importlib.util.module_from_spec(spec); spec.loader.exec_module(ci)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); suite = root / 'suite'; suite.mkdir()
            (suite / 'run.py').write_text('print("test")')
            dependency = root / 'native.py'; dependency.write_text('assert True')
            (suite / 'dependencies.json').write_text(json.dumps([str(dependency)]))
            before = ci.suite_identity(suite)
            dependency.write_text('assert False')
            self.assertNotEqual(before, ci.suite_identity(suite))
            dependency.unlink()
            with self.assertRaises(OSError): ci.suite_identity(suite)


if __name__ == '__main__':
    unittest.main()
