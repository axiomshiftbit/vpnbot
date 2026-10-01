import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest


class XrayStartupTest(unittest.TestCase):
    def start(self, marker, missing=None, clients=True):
        with tempfile.TemporaryDirectory(prefix='vpnbot-xray-start-') as directory:
            root = Path(directory)
            for name in ('bin', 'active', 'logs', 'ssh'):
                (root / name).mkdir()
            (root / 'key.pub').write_text('test-public-key')
            (root / 'config.json').write_text(json.dumps({'inbounds': [{'settings': {
                'clients': [{'id': 'test-client'}] if clients else []}}]}))
            if marker is not None:
                (root / 'logs/xray_core').write_text(marker + '\n')
            def executable(name, body):
                path = root / 'bin' / name
                path.write_text(body)
                path.chmod(0o755)
            for name in ('ssh-keygen', 'sshd', 'tail'):
                executable(name, '#!/bin/sh\nexit 0\n')
            executable('jq', f'#!{sys.executable}\nimport json,sys\n'
                       'c=json.load(open(sys.argv[-1]))["inbounds"][0]["settings"]["clients"]\n'
                       'print(c[0]["id"] if c else "")\n')
            for name in ('xray', 'xray-2', 'xray-3', 'xray-smux'):
                if name != missing:
                    executable(name, f'#!/bin/sh\nprintf "%s" "{name}" > "{root}/logs/started"\n')
            script = (Path(__file__).resolve().parents[1] / 'scripts/start_xray.sh').read_text()
            for old, new in [('/usr/sbin/sshd', str(root / 'bin/sshd')),
                             ('/root/.ssh', str(root / 'ssh')), ('/ssh/key.pub', str(root / 'key.pub')),
                             ('/usr/local/bin', str(root / 'active')), ('/usr/bin/', str(root / 'bin') + '/'),
                             ('/xray.json', str(root / 'config.json')), ('/logs', str(root / 'logs'))]:
                script = script.replace(old, new)
            # В контейнере tail живёт постоянно. Наш tail завершается сразу;
            # дождёмся фоновых fixtures, прежде чем читать файл запуска.
            script += '\nwait\n'
            result = subprocess.run(['sh', '-c', script], env=os.environ | {
                'PATH': f'{root}/active:{root}/bin:' + os.environ['PATH']}, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            started = root / 'logs/started'
            log = root / 'logs/xray_stdout'
            return ((root / 'active/xray').readlink().name,
                    started.read_text() if started.exists() else '', log.read_text() if log.exists() else '')

    def test_saved_selection_and_legacy_default(self):
        for marker, binary in [(None, 'xray'), ('origin', 'xray'), ('origin2', 'xray-2'),
                               ('origin3', 'xray-3'), ('fork', 'xray-smux'), ('unknown', 'xray')]:
            with self.subTest(marker=marker):
                link, started, _ = self.start(marker)
                self.assertEqual(link, binary)
                self.assertEqual(started, binary)

    def test_missing_selected_binary_does_not_run_another_version(self):
        for marker, binary in [('origin2', 'xray-2'), ('origin3', 'xray-3'), ('fork', 'xray-smux')]:
            with self.subTest(marker=marker):
                _, started, log = self.start(marker, missing=binary)
                self.assertEqual(started, '')
                self.assertIn('selected core', log)
                self.assertIn('missing', log)

    def test_no_clients_does_not_start(self):
        _, started, log = self.start('origin2', clients=False)
        self.assertEqual(started, '')
        self.assertIn('no client uuid', log)


if __name__ == '__main__':
    unittest.main()
