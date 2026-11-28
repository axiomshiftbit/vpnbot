"""Фактические asset hashes/buildinfo и отказ при неполном сканировании."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import ci_assets as assets
import ci_check_components as components
import ci_scan_gate as scan
import ci_release_policy as release


class AssetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.versions, cls.bom = assets.inventory(ROOT)

    def fixture(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        for name in ('scripts/ci_asset_inventory.json', 'app/webapp/jquery-3.8.0.min.js', 'app/webapp/jsoneditor.min.js'):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        return root

    def test_actual_release_inventory_contains_browser_dependencies(self):
        packages = {(p['name'], p['version']) for p in self.bom['components']}
        for row in (('jquery', '3.8.0'), ('jsoneditor', '10.4.3'), ('ajv', '6.14.0')):
            self.assertIn(row, packages)
        self.assertEqual(set(self.versions), {'jquery', 'jsoneditor'})
        self.assertTrue(all(p['purl'].startswith('pkg:npm/') for p in self.bom['components']))

    def test_tampered_browser_and_unregistered_asset_are_rejected(self):
        root = self.fixture()
        file = root / 'app/webapp/jquery-3.8.0.min.js'
        file.write_bytes(file.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'browser asset digest'):
            assets.inventory(root)
        shutil.copyfile(ROOT / file.relative_to(root), file)
        (file.parent / 'new-vendor.min.js').write_text('new library')
        with self.assertRaisesRegex(ValueError, 'inventory incomplete'):
            assets.inventory(root)

    def test_cli_reports_missing_inventory(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run([sys.executable, assets.__file__, root, str(Path(root) / 'bom.json')],
                                    capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr.strip(), 'Asset inventory failed')

    def test_every_sbom_component_must_reach_trivy(self):
        packages = [dict(Name=p['name'], Version=p['version'], Identifier={'PURL': p['purl']}) for p in self.bom['components']]
        results = [dict(Class='lang-pkgs', Type='node-pkg', Packages=packages)]
        report = dict(ArtifactType='cyclonedx', Results=results)
        self.assertEqual(assets.verify_scan(report, self.bom), len(packages))
        self.assertEqual(scan.gate(report, 'assets', self.bom)[0], [])
        report['Results'][0]['Packages'].pop()
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            scan.gate(report, 'assets', self.bom)
        with self.assertRaises(ValueError):
            scan.gate(report, 'assets')

    def test_fixable_dependency_blocks_and_native_gaps_are_not_false_findings(self):
        package = self.bom['components'][0]
        bom = dict(components=[package])
        report = dict(ArtifactType='cyclonedx', Results=[dict(Class='lang-pkgs', Type='node-pkg',
            Packages=[dict(Name=package['name'],Version=package['version'],Identifier={'PURL': package['purl']})], Vulnerabilities=[dict(
                VulnerabilityID='SYNTHETIC-HIGH', PkgName=package['name'], InstalledVersion=package['version'],
                Severity='HIGH', FixedVersion='99.0.0')])])
        self.assertEqual(scan.gate(report, 'assets', bom)[0][0][0], 'SYNTHETIC-HIGH')
        self.assertFalse(any(c.get('cpe') == 'google:chrome' for c in components.COMPONENTS))

    def test_purl_normalization_does_not_hide_missing_or_wrong_packages(self):
        package = dict(name='github.com/RyuaNerin/go-krypto',version='v1.3.0',purl='pkg:golang/github.com/RyuaNerin/go-krypto@v1.3.0')
        row = dict(Name=package['name'],Version=package['version'],Identifier={'PURL':package['purl'].lower()})
        report = dict(ArtifactType='cyclonedx',Results=[dict(Class='lang-pkgs',Type='gobinary',Packages=[row])])
        self.assertEqual(assets.verify_scan(report,dict(components=[package])),1)
        row['Version']='v1.2.0'
        with self.assertRaises(ValueError):
            assets.verify_scan(report,dict(components=[package]))
        row['Version']=package['version'];report['Results'][0]['Type']='node-pkg'
        with self.assertRaises(ValueError):
            assets.verify_scan(report,dict(components=[package]))

    def test_actual_browser_versions_are_queried(self):
        items = [c for c in components.COMPONENTS if c['pin'].startswith('asset:')]
        versions = {c['name']: self.versions[c['pin'][6:]] for c in items}
        with patch.object(components, 'COMPONENTS', items), patch.object(components, 'pins', return_value=versions), \
                patch.object(components, 'advisory_findings', return_value=[('SYNTHETIC', 'HIGH', True)]) as advisory:
            rows, blocked = components.check(freshness=False)
        self.assertEqual(len(blocked), 2)
        self.assertEqual({call.args[1] for call in advisory.call_args_list}, set(versions.values()))

    def test_asset_stage_is_required_and_wired(self):
        self.assertIn('security-assets', release.stages())
        workflow = (ROOT / '.github/workflows/images.yml').read_text()
        self.assertIn('bash scripts/ci_scan_image.sh --assets .', workflow)
        self.assertIn('name: admission-security-assets', workflow)


if __name__ == '__main__':
    unittest.main()
