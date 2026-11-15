"""Native cold-restore oracle/discovery; no claim that unit stubs run a VPN."""
import ast
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'tests/integration/fixtures/backup-protocols-native/node-cold.py'
spec=importlib.util.spec_from_file_location('node_cold',SCRIPT)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
REQUIRED=['node-importer-connected_settled_node','node-importer-common_importer_restores_node_pac_and_files',
          'node-importer-restored_controller_pinned_rpc','node-importer-old_external_profile_payload_after',
          'node-importer-external_profile_not_regenerated','old host pin rejects the reinstalled node',
          'restored controller passes traffic after reinstall','previously exported external peer profile works after reinstall and restore',
          'original disposable node restored']

class NodeColdDiscoveryTest(unittest.TestCase):
    def output(self,names=REQUIRED):
        return ''.join('PASS '+x+'\n' for x in list(names)+['unit-control-'+str(i) for i in range(25)]).encode()
    def test_complete_counts_and_named_native_postconditions(self):
        self.assertEqual(len(module.parse_checks(self.output())),34)
    def test_missing_importer_cannot_pass_on_unrelated_checks(self):
        with self.assertRaises(RuntimeError):module.parse_checks(self.output(REQUIRED[1:]))
    def test_old_profile_after_reinstall_is_mandatory(self):
        with self.assertRaises(RuntimeError):module.parse_checks(self.output([x for x in REQUIRED if 'previously exported' not in x]))
    def test_failed_or_empty_native_result_never_passes(self):
        for value in [b'',self.output()+b'FAIL owned cleanup\n']:
            with self.subTest(value_empty=not value),self.assertRaises(RuntimeError):module.parse_checks(value)
    def test_full_suite_dispatches_exact_candidate_images_and_checks_cleanup(self):
        source=(ROOT/'tests/integration/suite/run.py').read_text();tree=ast.parse(source);entries=None
        for node in ast.walk(tree):
            if isinstance(node,ast.For) and isinstance(node.iter,ast.List) and any(isinstance(x,ast.Tuple) and x.elts and isinstance(x.elts[0],ast.Constant) and x.elts[0].value=='backup-wg-awg-payload' for x in node.iter.elts):
                entries=eval(compile(ast.Expression(node.iter),'<suite-dispatch>','eval'),{'a':SimpleNamespace(checkout=ROOT),'candidate':{'images':{'php':'candidate-php','xr':'candidate-xr','ng':'candidate-ng','wg':'candidate-wg'}}})
        self.assertIsNotNone(entries)
        matches=[row for row in entries if row[0]=='backup-node-cold'];self.assertEqual(len(matches),1)
        _,name,args,minimum=matches[0];self.assertEqual(name,'node-cold.py');self.assertGreaterEqual(minimum,30)
        self.assertEqual(dict(zip(args[::2],args[1::2])),{'--source':str(ROOT),'--php-image':'candidate-php','--xray-image':'candidate-xr','--ng-image':'candidate-ng'})
        self.assertIn("name!='backup-node-cold' or result.get('cleanup') is True",source)

if __name__=='__main__':unittest.main()
