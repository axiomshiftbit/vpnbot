"""Исполнение обоих реальных JS-шаблонов PAC: все границы DNS-меток."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'app/updatepac.php'


@unittest.skipUnless(shutil.which('node'), 'нужен Node для исполнения PAC')
class PacSuffixTests(unittest.TestCase):
    def evaluate(self, domains, hosts):
        tree = {}
        for domain in domains:
            prefix, tld = domain.rsplit('.', 1)
            tree.setdefault(tld, {}).setdefault(len(prefix), []).append(prefix)
        templates = re.findall(r'\$pac\s*=\s*<<<PAC\n(.*?)\n\s*PAC;', SOURCE.read_text(), re.S)
        self.assertEqual(len(templates), 2)
        program = '''const fs=require('fs'),vm=require('vm');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
const result=input.scripts.map(source=>{const ctx=vm.createContext({});vm.runInContext(source,ctx,{timeout:1000});
return input.hosts.map(host=>{ctx.host=host;return String(vm.runInContext('FindProxyForURL("https://"+host+"/",host)',ctx,{timeout:1000}));});});
process.stdout.write(JSON.stringify(result));'''
        scripts = [t.replace('$domains', json.dumps(tree)) for t in templates]
        result = subprocess.run(['node', '-e', program], input=json.dumps({'scripts': scripts, 'hosts': hosts}),
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_every_suffix_boundary_in_both_modes(self):
        for suffix in ('example.com', 'b.example.com', 'c.b.example.com', 'custom.example.net'):
            hosts = [suffix, 'x.' + suffix, 'y.x.' + suffix, 'z.y.x.' + suffix,
                     'not' + suffix, suffix + '.other.test', 'x.' + suffix.split('.', 1)[1]]
            direct, reverse = self.evaluate([suffix], hosts)
            for index, host in enumerate(hosts):
                with self.subTest(suffix=suffix, host=host):
                    matched = index < 4
                    self.assertEqual(direct[index].startswith('SOCKS5'), matched)
                    self.assertEqual(reverse[index] == 'DIRECT', matched)

    def test_unrelated_custom_domains_keep_their_routes(self):
        hosts = ['x.b.example.com', 'a.private.example.net', 'other.example.com', 'private.example.net.other.test']
        direct, reverse = self.evaluate(['b.example.com', 'private.example.net'], hosts)
        self.assertEqual([x.startswith('SOCKS5') for x in direct], [True, True, False, False])
        self.assertEqual([x == 'DIRECT' for x in reverse], [True, True, False, False])


if __name__ == '__main__':
    unittest.main()
