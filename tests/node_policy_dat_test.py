import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


def field(number, data):
    assert len(data) < 128
    return bytes([(number << 3) | 2, len(data)]) + data


class NodePolicyDat(unittest.TestCase):
    def test_selected_category_and_invalid_import(self):
        tool = Path(__file__).resolve().parents[1] / 'app/exit_ruleset.py'
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            output = root / 'out'
            for kind, tag, item, expected in [
                ('domain', 'ads', b'\x08\x03' + field(2, b'ads.example'), ['full:ads.example']),
                ('ip', 'local', field(1, bytes([192, 0, 2, 0])) + b'\x10\x18', ['192.0.2.0/24'])]:
                src = root / 'source.dat'
                src.write_bytes(field(1, field(1,b'unused')) + field(1, field(1,tag.upper().encode()) + field(2,item)))
                cmd = [sys.executable, str(tool), 'dat', str(src), str(output), kind, tag]
                self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
                self.assertEqual(json.loads(output.read_text()), expected)
                for invalid in ('missing', '!'+tag, tag+'@attr'):
                    self.assertNotEqual(subprocess.run([*cmd[:-1],invalid], capture_output=True).returncode, 0)
                    self.assertEqual(json.loads(output.read_text()), expected)
