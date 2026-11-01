"""The controller carrier must have every local Python dependency at runtime."""
import ast
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CarrierMounts(unittest.TestCase):
    def test_readonly_mounts_cover_transitive_local_imports(self):
        mounts = dict(re.findall(r'\./scripts/([a-z_]+\.py):/node-carrier/([a-z_]+\.py):ro',
                                 (ROOT / 'docker-compose.yml').read_text()))
        pending, checked = ['node_awg_client.py'], set()
        while pending:
            name = pending.pop()
            if name in checked:
                continue
            checked.add(name)
            self.assertEqual(mounts.get(name), name, 'missing carrier dependency: ' + name)
            tree = ast.parse((ROOT / 'scripts' / name).read_text())
            for node in ast.walk(tree):
                names = [x.name for x in node.names] if isinstance(node, ast.Import) else (
                    [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                pending.extend(n + '.py' for n in names if (ROOT / 'scripts' / (n + '.py')).is_file())


if __name__ == '__main__':
    unittest.main()
