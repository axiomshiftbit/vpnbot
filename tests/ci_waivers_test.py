#!/usr/bin/env python3
"""Vulnerability waivers: exact, time-limited, and only in a run that allows them."""
import contextlib
import datetime
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import ci_waivers  # noqa: E402
import ci_check_components  # noqa: E402
import ci_scan_gate  # noqa: E402

TODAY = datetime.date(2026, 11, 7)
REAL_DATE = datetime.date
ENTRY = dict(id='GHSA-r766-rf9f-588h', component='Caddy', version='v2.11.7', package='github.com/caddyserver/caddy/v2',
             installed='v2.11.7', expires='2026-12-15', reason='fork not released yet')


def trivy(*vulns, secrets=()):
    return {'Metadata': {'OS': {'Family': 'alpine'}}, 'Results': [
        {'Class': 'os-pkgs', 'Target': 'alpine', 'Vulnerabilities': []},
        {'Class': 'lang-pkgs', 'Target': 'usr/bin/caddy', 'Vulnerabilities': [
            dict(VulnerabilityID=i, PkgName=p, InstalledVersion=v, FixedVersion=f, Severity='HIGH') for i, p, v, f in vulns],
         'Secrets': [dict(RuleID=r) for r in secrets]}]}


class Waivers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'waivers.json'
        class Day(datetime.date):
            @classmethod
            def today(cls): return TODAY
        clock = patch.object(ci_waivers.datetime, 'date', Day)
        clock.start(); self.addCleanup(clock.stop)

    def write(self, *entries):
        self.path.write_text(json.dumps(list(entries)))

    def test_file_is_strict_and_time_limited(self):
        self.write(ENTRY)
        self.assertTrue(ci_waivers.load(self.path, TODAY)[0]['active'])
        self.assertFalse(ci_waivers.load(self.path, datetime.date(2026, 12, 16))[0]['active'], 'expired waiver stays inactive')
        for bad in ({k: v for k, v in ENTRY.items() if k != 'reason'}, ENTRY | {'reason': ' '}, ENTRY | {'extra': 'x'},
                    ENTRY | {'id': 'caddy'}, ENTRY | {'expires': '2027-06-01'}, ENTRY | {'expires': 'soon'}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.write(bad); ci_waivers.load(self.path, TODAY)

    def test_repository_file_is_valid(self):
        for entry in ci_waivers.load(today=REAL_DATE.today()):
            self.assertTrue(entry['reason'] and entry['expires'])

    def test_configured_path_and_empty_waivers(self):
        self.write()
        with patch.object(ci_waivers, 'PATH', self.path):
            self.assertEqual(ci_waivers.load(), [])
            finding = ('Caddy', 'v2.11.7', ENTRY['id'], 'HIGH', True, 'GitHub')
            with patch.dict(os.environ, {'CI_ALLOW_WAIVERS': '1'}):
                blocked, _, waived = ci_check_components.apply_waivers([finding])
            self.assertEqual(blocked, [finding])
            self.assertFalse(waived)

    def split(self, findings, match, allow, today=TODAY):
        self.write(ENTRY)
        class Day(datetime.date):
            @classmethod
            def today(cls): return today
        with patch.object(ci_waivers, 'PATH', self.path), patch.object(ci_waivers.datetime, 'date', Day), \
                patch.dict(os.environ, {'CI_ALLOW_WAIVERS': '1' if allow else '0'}):
            return ci_waivers.split(findings, match)

    def test_only_exact_findings_and_only_when_allowed(self):
        match = lambda entries, f: ci_waivers.component_waiver(entries, f[2], f[0], f[1])
        caddy = ('Caddy', 'v2.11.7', 'GHSA-r766-rf9f-588h', 'HIGH', True, 'GitHub')
        other = ('Caddy', 'v2.11.7', 'GHSA-xxxx-xxxx-xxxx', 'HIGH', True, 'GitHub')
        newer = ('Caddy', 'v2.11.6', 'GHSA-r766-rf9f-588h', 'HIGH', True, 'GitHub')
        nginx = ('nginx', 'v2.11.7', 'GHSA-r766-rf9f-588h', 'HIGH', True, 'GitHub')
        blocked, waived, hints = self.split([caddy, other, newer, nginx], match, allow=True)
        self.assertEqual([f for f, _ in waived], [caddy])
        self.assertEqual(blocked, [other, newer, nginx])
        blocked, waived, hints = self.split([caddy], match, allow=False)
        self.assertEqual((blocked, waived, [f for f, _ in hints]), ([caddy], [], [caddy]), 'without the flag it still blocks, with a hint')
        blocked, waived, hints = self.split([caddy], match, allow=True, today=datetime.date(2026, 12, 16))
        self.assertEqual((blocked, waived, hints), ([caddy], [], []), 'expired waiver blocks again')

    def run_gate(self, report, allow):
        path = Path(self.tmp.name) / 'result.json'
        path.write_text(json.dumps(report))
        self.write(ENTRY)
        out = io.StringIO()
        with patch.object(ci_waivers, 'PATH', self.path), patch.dict(os.environ, {'CI_ALLOW_WAIVERS': '1' if allow else '0', 'GITHUB_ACTIONS': 'true'}), \
                contextlib.redirect_stdout(out):
            code = ci_scan_gate.main(str(path))
        return code, out.getvalue()

    def test_trivy_gate(self):
        caddy = ('GHSA-r766-rf9f-588h', 'github.com/caddyserver/caddy/v2', 'v2.11.7', '2.11.8')
        code, out = self.run_gate(trivy(caddy), allow=True)
        self.assertEqual(code, 0, out)
        self.assertIn('WAIVED GHSA-r766-rf9f-588h', out)
        self.assertIn('Security gate waivers: 1', out)
        self.assertIn('Security gate: 0 fixable high/critical findings; 0 secrets;', out)
        self.assertIn('::warning::', out)
        code, out = self.run_gate(trivy(caddy), allow=False)
        self.assertEqual(code, 1); self.assertIn('note waiver', out)
        code, out = self.run_gate(trivy(caddy, ('GHSA-other-0000-0000', 'golang.org/x/net', 'v0.1.0', 'v0.2.0')), allow=True)
        self.assertEqual(code, 1, 'another vulnerability still blocks'); self.assertIn('BLOCK GHSA-other', out)
        code, out = self.run_gate(trivy(caddy, secrets=('private-key',)), allow=True)
        self.assertEqual(code, 1, 'secrets are never waived')

    def test_component_gate_marks_waived_findings(self):
        caddy = ('Caddy', 'v2.11.7', 'GHSA-r766-rf9f-588h', 'HIGH', True, 'GitHub')
        rows = [dict(name='Caddy', version='v2.11.7', findings=[caddy[2:]], newer='v2.11.8', sources=['GitHub'])]
        self.write(ENTRY)
        with patch.object(ci_waivers, 'PATH', self.path), patch.dict(os.environ, {'CI_ALLOW_WAIVERS': '1'}):
            blocked, lines, waived = ci_check_components.apply_waivers([caddy])
        self.assertEqual(blocked, [])
        text = ci_check_components.report(rows, blocked, waived)
        self.assertIn('WAIVE GHSA-r766-rf9f-588h', text)
        self.assertIn('0 blocking findings', text)
        self.assertTrue(any(line.startswith('WAIVED Caddy v2.11.7') for line in lines))
        with patch.object(ci_waivers, 'PATH', self.path), patch.dict(os.environ, {'CI_ALLOW_WAIVERS': '0'}):
            blocked, lines, waived = ci_check_components.apply_waivers([caddy])
        self.assertEqual(blocked, [caddy])
        self.assertIn('BLOCK GHSA-r766-rf9f-588h', ci_check_components.report(rows, blocked, waived))


if __name__ == '__main__':
    unittest.main()
