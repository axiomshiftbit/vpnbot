#!/usr/bin/env python3
"""Решение о допуске образа по отчёту Trivy."""
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import ci_scan_gate as scan  # noqa: E402


def report(vulns=(), secrets=(), family='alpine', eosl=False, os_class=True):
    results = [{'Class': 'os-pkgs' if os_class else 'lang-pkgs', 'Target': 'image (alpine 3.24)', 'Vulnerabilities': list(vulns)}]
    if secrets:
        results.append({'Class': 'secret', 'Target': '/root/.ssh/id_ed25519', 'Secrets': list(secrets)})
    return {'Metadata': {'OS': {'Family': family, 'EOSL': eosl}}, 'Results': results}


def vuln(ident, level, fixed='1.2.3', package='openssl'):
    return {'VulnerabilityID': ident, 'Severity': level, 'FixedVersion': fixed, 'PkgName': package, 'InstalledVersion': '1.0.0'}


class ScanGateTest(unittest.TestCase):
    def run_gate(self, data):
        with tempfile.NamedTemporaryFile('w', suffix='.json') as stream, patch('sys.stdout', io.StringIO()) as out:
            json.dump(data, stream)
            stream.flush()
            return scan.main(stream.name), out.getvalue()

    def test_clean_image_is_admitted(self):
        code, text = self.run_gate(report())
        self.assertEqual(code, 0)
        self.assertIn('Security gate: 0 fixable high/critical findings; 0 secrets; 0 high/critical without a fix; 0 fixable medium', text)

    def test_fixable_high_and_critical_block(self):
        for level in ('HIGH', 'CRITICAL'):
            with self.subTest(level=level):
                code, text = self.run_gate(report([vuln('CVE-1', level)]))
                self.assertEqual(code, 1)
                self.assertIn('BLOCK CVE-1 openssl 1.0.0 1.2.3', text)

    def test_unfixed_and_lower_findings_are_reported_not_blocking(self):
        code, text = self.run_gate(report([vuln('CVE-2', 'HIGH', fixed=''), vuln('CVE-3', 'MEDIUM'), vuln('CVE-4', 'LOW'), vuln('CVE-5', 'MEDIUM', fixed='')]))
        self.assertEqual(code, 0)
        self.assertIn('note unfixed CVE-2 openssl 1.0.0', text)
        self.assertIn('1 high/critical without a fix; 1 fixable medium', text)
        self.assertNotIn('BLOCK', text)

    def test_secret_in_a_layer_blocks_without_printing_the_value(self):
        secret = {'RuleID': 'private-key', 'Match': '-----BEGIN OPENSSH PRIVATE KEY----- s3cr3t', 'Code': {'Lines': [{'Content': 's3cr3t'}]}}
        code, text = self.run_gate(report(secrets=[secret]))
        self.assertEqual(code, 1)
        self.assertIn('BLOCK secret private-key /root/.ssh/id_ed25519', text)
        self.assertNotIn('s3cr3t', text)

    def test_duplicates_are_counted_once(self):
        code, text = self.run_gate(report([vuln('CVE-1', 'HIGH'), vuln('CVE-1', 'HIGH')]))
        self.assertEqual(text.count('BLOCK CVE-1'), 1)
        self.assertIn('Security gate: 1 fixable', text)

    def test_unknown_or_unsupported_system_is_not_admitted(self):
        for data in (report(family='ubuntu'), report(family='debian'), report(eosl=True), report(os_class=False), {'Results': []}, {}):
            with self.subTest(data=str(data)[:40]), self.assertRaises(AssertionError):
                self.run_gate(data)

    def test_empty_lists_from_trivy_are_tolerated(self):
        data = report()
        data['Results'][0]['Vulnerabilities'] = None
        data['Results'].append({'Class': 'secret', 'Target': 'x', 'Secrets': None})
        self.assertEqual(self.run_gate(data)[0], 0)

    def test_scan_script_enables_secret_scanning_and_uses_this_gate(self):
        script = (ROOT / 'scripts/ci_scan_image.sh').read_text()
        self.assertIn('--scanners vuln,secret', script)
        self.assertIn('ci_scan_gate.py" "$work/result.json"', script)
        self.assertIn('stale vulnerability DB', script)


if __name__ == '__main__':
    unittest.main()
