#!/usr/bin/env python3
"""Missing inventories cannot look like zero findings; no network or live data."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import ci_scan_gate as scan

SPECS = {
    'telemt': [('rustbinary', 'usr/local/bin/telemt')],
    'snolc': [('rustbinary', 'opt/snolc/runtime/bin/snolc'), ('rustbinary', 'opt/snolc/sbom/vpnbot-snolc-modules')],
    'ss': [('rustbinary', 'usr/bin/' + n) for n in ('sslocal', 'ssserver', 'ssmanager', 'ssservice', 'ssurl')]
          + [('gobinary', 'usr/bin/' + n) for n in ('ck-client', 'ck-server', 'simple-tls', 'v2ray-plugin')],
    'ad': [('gobinary', 'opt/adguardhome/AdGuardHome'), ('node-pkg', 'Node.js')],
    'php': [('gobinary', 'usr/bin/' + n) for n in ('dnslookup', 'sing-box', 'mihomo')],
    'wg': [('gobinary', 'usr/bin/' + n) for n in ('warp-socks', 'wgcf', 'tun2socks', 'amneziawg-go')],
    'xr': [('gobinary', 'usr/bin/' + n) for n in ('xray', 'xray-smux', 'wireproxy-node')],
    'np': [('gobinary', 'usr/local/bin/caddy')],
    'dnstt': [('gobinary', 'usr/local/bin/dnstt-server')],
    'hysteria': [('gobinary', 'usr/local/bin/hysteria')],
    'protocol': [('gobinary', 'usr/local/bin/' + n) for n in ('sing-box', 'protocol-stats')],
    'mieru': [('gobinary', 'usr/local/bin/' + n) for n in ('mita', 'mieru-control')],
    'masque': [('gobinary', 'usr/local/bin/xray')],
}

def report(image):
    return {'Metadata': {'OS': {'Family': 'alpine'}}, 'Results': [
        {'Class': 'os-pkgs', 'Type': 'alpine', 'Target': 'fixture', 'Packages': [{'Name': 'musl', 'Version': '1.0'}]}]
        + [{'Class': 'lang-pkgs', 'Type': kind, 'Target': '/' + target,
            'Packages': [{'Name': 'synthetic-package', 'Version': '1.0.0'} | (
                {'Identifier': {'PURL': 'pkg:npm/synthetic-package@1.0.0', 'BOMRef': 'synthetic-package@1.0.0'}}
                if kind == 'node-pkg' else {})] +
                ([{'Name': 'stdlib', 'Version': 'v1.27.4'}] if kind == 'gobinary' else [])} for kind, target in SPECS[image]]}

class DependencyInventoryTest(unittest.TestCase):
    def test_os_inventory_must_have_versioned_packages(self):
        for packages in ([], [{'Name': 'musl'}], [{'Version': '1.0'}]):
            data = report('telemt'); data['Results'][0]['Packages'] = packages
            with self.subTest(packages=packages), self.assertRaisesRegex(AssertionError, 'OS package scan missing'):
                scan.gate(data, 'ng')

    def test_os_only_cannot_admit_a_language_application(self):
        for image in SPECS:
            with self.subTest(image=image):
                data = report(image); data['Results'] = data['Results'][:1]
                with self.assertRaisesRegex(AssertionError, 'package scan missing'): scan.gate(data, image)

    def test_each_mandatory_target_must_survive_the_scan(self):
        for image in SPECS:
            full = report(image)
            self.assertEqual(scan.gate(full, image), ([], [], [], 0))
            for index in range(1, len(full['Results'])):
                with self.subTest(image=image, target=index):
                    data = copy.deepcopy(full); del data['Results'][index]
                    with self.assertRaisesRegex(AssertionError, 'package scan missing'): scan.gate(data, image)

    def test_wrong_kind_and_empty_or_unversioned_inventory_are_rejected(self):
        for image in ('telemt', 'ss', 'snolc', 'ad', 'php'):
            for change in ({'Type': 'unknown'}, {'Packages': []}, {'Packages': [{'Name': 'package'}]}):
                with self.subTest(image=image, change=change):
                    data = report(image); data['Results'][-1].update(change)
                    with self.assertRaisesRegex(AssertionError, 'package scan missing'): scan.gate(data, image)

    def test_frontend_inventory_must_come_from_the_embedded_npm_sbom(self):
        for change in ({'Identifier': {'PURL': 'pkg:npm/synthetic-package@1.0.0'}},
                       {'Identifier': {'PURL': 'pkg:golang/synthetic-package@1.0.0', 'BOMRef': 'synthetic-package@1.0.0'}}):
            with self.subTest(change=change):
                data = report('ad'); data['Results'][-1]['Packages'][0].update(change)
                with self.assertRaisesRegex(AssertionError, 'npm package scan missing'): scan.gate(data, 'ad')

    def test_matching_filename_with_unrelated_target_cannot_fill_a_gap(self):
        data = report('telemt'); data['Results'][1]['Target'] = '/tmp/telemt'
        with self.assertRaisesRegex(AssertionError, 'package scan missing'): scan.gate(data, 'telemt')

    def test_go_source_modules_are_not_unversioned_third_party_dependencies(self):
        data = report('hysteria'); packages = data['Results'][1]['Packages']
        packages += [{'Name': 'hysteria', 'Relationship': 'root'}, {'Name': '../core'}, {'Name': '../extras'}]
        self.assertEqual(scan.gate(data, 'hysteria'), ([], [], [], 0))
        packages.append({'Name': 'github.com/unknown/library'})
        with self.assertRaisesRegex(AssertionError, 'Go package scan missing'): scan.gate(data, 'hysteria')
        data = report('php'); data['Results'][1]['Packages'] = [{'Name': 'app', 'Relationship': 'root'}]
        with self.assertRaisesRegex(AssertionError, 'Go package scan missing'): scan.gate(data, 'php')

    def test_real_inventory_does_not_hide_a_fixable_finding(self):
        for image in ('telemt', 'ss', 'snolc', 'ad', 'php'):
            data = report(image)
            data['Results'][-1]['Vulnerabilities'] = [{'VulnerabilityID': 'SYNTHETIC-HIGH', 'PkgName': 'synthetic-package',
                'InstalledVersion': '1.0.0', 'Severity': 'HIGH', 'FixedVersion': '1.0.1'}]
            self.assertEqual(scan.gate(data, image)[0], [('SYNTHETIC-HIGH', 'synthetic-package', '1.0.0', '1.0.1')])

if __name__ == '__main__': unittest.main()
