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
          'confirmed block rejects previously reachable destination', 'confirmed SSH lists select block, WARP and direct for TCP and UDP',
          'controller rejects explicit block of the probe domain', 'watchdog rolls back after real confirmation deadline',
          'original disposable node restored']

class NodeColdDiscoveryTest(unittest.TestCase):
    def output(self,names=REQUIRED):
        return ''.join('PASS '+x+'\n' for x in list(names)+['unit-control-'+str(i) for i in range(25)]).encode()
    def test_complete_counts_and_named_native_postconditions(self):
        self.assertEqual(len(module.parse_checks(self.output())),len(REQUIRED)+25)
    def test_missing_importer_cannot_pass_on_unrelated_checks(self):
        with self.assertRaises(RuntimeError):module.parse_checks(self.output(REQUIRED[1:]))
    def test_old_profile_after_reinstall_is_mandatory(self):
        with self.assertRaises(RuntimeError):module.parse_checks(self.output([x for x in REQUIRED if 'previously exported' not in x]))
    def test_failed_or_empty_native_result_never_passes(self):
        for value in [b'',self.output()+b'FAIL owned cleanup\n']:
            with self.subTest(value_empty=not value),self.assertRaises(RuntimeError):module.parse_checks(value)
    def test_full_suite_dispatches_exact_candidate_images_and_checks_cleanup(self):
        # The stand and the separate runners both dispatch through isolated_cases.
        self.assertIn("isolated_case('backup-node-cold')",(ROOT/'tests/integration/suite/run.py').read_text())
        spec=importlib.util.spec_from_file_location('isolated_cases',ROOT/'tests/integration/suite/isolated_cases.py')
        cases=importlib.util.module_from_spec(spec);spec.loader.exec_module(cases)
        import json,tempfile
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);calls=[];passed=[]
            def run(name,cmd,timeout=180):
                calls.append(cmd);(out/name).mkdir();(out/name/'results.json').write_text(json.dumps(result))
            def check(group,name,ok):
                if not ok:raise RuntimeError(name)
                passed.append(group)
            ctx=dict(candidate={'images':{'php':'candidate-php','xr':'candidate-xr','ng':'candidate-ng'}},checkout=ROOT,
                     results=out,run=run,check=check,counts={'backup_restore':0},twice=None)
            result=dict(error=None,checks=[{'passed':True}]*30,cleanup=True)
            cases.run_case('backup-node-cold',ctx)
            self.assertEqual(Path(calls[0][1]),SCRIPT);args=calls[0][4:]
            self.assertEqual(dict(zip(args[::2],args[1::2])),{'--source':str(ROOT),'--php-image':'candidate-php','--xray-image':'candidate-xr','--ng-image':'candidate-ng'})
            self.assertEqual(ctx['counts']['backup_restore'],30)
            for index,broken in enumerate((dict(result,cleanup=False),dict(result,checks=[{'passed':True}]*29),dict(result,error='x'))):
                result=broken;(out/'backup-node-cold/results.json').unlink();(out/'backup-node-cold').rmdir()
                with self.subTest(index=index),self.assertRaises(RuntimeError):
                    cases.run_case('backup-node-cold',ctx)


def oci_archive(path, manifests, corrupt=False):
    """Minimal docker-save/OCI layout: index.json, manifest blobs; no layers needed."""
    import hashlib, io, json, tarfile
    with tarfile.open(path, 'w') as archive:
        entries = []
        for config in manifests:
            body = json.dumps({'schemaVersion': 2, 'config': {'digest': config}} if config else
                              {'schemaVersion': 2, 'manifests': []}).encode()
            digest = 'sha256:' + hashlib.sha256(body).hexdigest()
            entries.append(digest)
            stored = body + (b' ' if corrupt else b'')
            info = tarfile.TarInfo('blobs/sha256/' + digest.split(':', 1)[1]); info.size = len(stored)
            archive.addfile(info, io.BytesIO(stored))
        index = json.dumps({'manifests': [{'digest': d} for d in entries]}).encode()
        info = tarfile.TarInfo('index.json'); info.size = len(index)
        archive.addfile(info, io.BytesIO(index))
    return entries


class NodeColdImageIdentityTest(unittest.TestCase):
    """docker save on the host, docker load in the classic nested daemon."""
    CONFIG = ['sha256:' + '1' * 64, 'sha256:' + '2' * 64]

    def archive(self, **kwargs):
        import tempfile
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        path = Path(directory.name) / 'images.tar'
        return path, oci_archive(path, kwargs.pop('manifests', self.CONFIG), **kwargs)

    def test_containerd_manifest_ids_map_to_nested_config_ids(self):
        path, manifests = self.archive()
        self.assertEqual(module.archive_ids(path, set(manifests)), dict(zip(manifests, self.CONFIG)))

    def test_classic_config_ids_stay_unchanged(self):
        path, _ = self.archive()
        self.assertEqual(module.archive_ids(path, set(self.CONFIG)), {c: c for c in self.CONFIG})

    def test_tampered_manifest_or_missing_image_is_rejected(self):
        path, manifests = self.archive(corrupt=True)
        with self.assertRaisesRegex(RuntimeError, 'digest mismatch'): module.archive_ids(path, set(manifests))
        path, manifests = self.archive()
        with self.assertRaisesRegex(RuntimeError, 'every candidate'): module.archive_ids(path, {manifests[0], 'sha256:' + '9' * 64})

    def test_classic_docker28_untagged_save_lists_configs_only_in_manifest_json(self):
        # docker save of several image IDs (Docker 28, overlay2): index.json names
        # one manifest; manifest.json names every config blob.
        import hashlib, io, json, tarfile, tempfile
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        bodies = [b'{"config":"one"}', b'{"config":"two"}', b'{"config":"three"}']
        configs = ['sha256:' + hashlib.sha256(b).hexdigest() for b in bodies]
        def build(path, tamper=False):
            with tarfile.open(path, 'w') as archive:
                def add(name, data):
                    info = tarfile.TarInfo(name); info.size = len(data); archive.addfile(info, io.BytesIO(data))
                for config, body in zip(configs, bodies):
                    add('blobs/sha256/' + config[7:], body + (b' ' if tamper and config == configs[2] else b''))
                manifest = json.dumps({'schemaVersion': 2, 'config': {'digest': configs[0]}}).encode()
                digest = 'sha256:' + hashlib.sha256(manifest).hexdigest()
                add('blobs/sha256/' + digest[7:], manifest)
                add('index.json', json.dumps({'manifests': [{'digest': digest}]}).encode())
                add('manifest.json', json.dumps([{'Config': 'blobs/sha256/' + c[7:]} for c in configs]).encode())
        path = Path(directory.name) / 'images.tar'; build(path)
        self.assertEqual(module.archive_ids(path, set(configs)), {c: c for c in configs})
        tampered = Path(directory.name) / 'tampered.tar'; build(tampered, tamper=True)
        with self.assertRaisesRegex(RuntimeError, 'config digest mismatch'): module.archive_ids(tampered, set(configs))

    def test_multi_platform_index_is_not_trusted_as_one_image(self):
        path, manifests = self.archive(manifests=[None])
        with self.assertRaisesRegex(RuntimeError, 'single-platform'): module.archive_ids(path, set(manifests))

    def test_offline_name_map_precedes_docker_in_node_runtime_path(self):
        # node_runtime.command() replaces PATH; an alias outside it is bypassed
        # and the nested daemon then fails on the registry digest name.
        runtime = (ROOT / 'scripts/node_runtime.py').read_text()
        path = ast.literal_eval(runtime.split("env={'PATH': ", 1)[1].split(',', 1)[0]).split(':')
        source = SCRIPT.read_text()
        link = source.split("'/lab/docker-offline',", 1)[1].split("'", 2)[1]
        self.assertIn(str(Path(link).parent), path)
        self.assertLess(path.index(str(Path(link).parent)), path.index('/usr/bin'))

if __name__=='__main__':unittest.main()
