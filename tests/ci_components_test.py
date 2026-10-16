#!/usr/bin/env python3
"""Проверка известных уязвимостей и свежести закреплённых версий."""
import io
import json
import os
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import ci_check_components as components  # noqa: E402
import ci_retry  # noqa: E402


def cve(ident, level, status='Analyzed'):
    return {'cve': {'id': ident, 'vulnStatus': status, 'metrics': {'cvssMetricV31': [{'cvssData': {'baseSeverity': level}}]}}}


def advisory(ident, level, vulnerable, patched, cve_id=None):
    return {'ghsa_id': ident, 'cve_id': cve_id, 'severity': level,
            'vulnerabilities': [{'vulnerable_version_range': vulnerable, 'patched_versions': patched}]}


class Api:
    """Подмена сети: ответы по подстроке адреса; неизвестный адрес — ошибка теста."""

    def __init__(self, nvd=None, advisories=None, releases=None, broken=(), gitlab=None, go=None):
        self.nvd, self.advisories, self.releases, self.broken, self.calls = nvd or {}, advisories or {}, releases or {}, broken, []
        self.gitlab = gitlab
        self.go = go if go is not None else [{'version': 'go' + components.pins()['Go'], 'stable': True}]

    def __call__(self, url, token=None):
        self.calls.append((url, token))
        if any(part in url for part in self.broken):
            raise urllib.error.URLError('down')
        if 'services.nvd.nist.gov' in url:
            for product, rows in self.nvd.items():
                if product.replace(':', '%3A') in url:
                    return {'vulnerabilities': rows}
            return {'vulnerabilities': []}
        if url.startswith('https://go.dev/dl/'):
            return self.go
        if 'gitlab.com' in url:
            assert 'openconnect%2Focserv' in url, url
            if self.gitlab is None:
                return [{'tag_name': components.pins()['ocserv'], 'description': '- [SECURITY] fixed long ago'}]
            return self.gitlab
        repo = url.split('/repos/')[1].split('/security-advisories')[0].split('/releases')[0]
        if '/security-advisories' in url:
            return self.advisories.get(repo, [])
        if '/releases' in url:
            return [{'tag_name': tag, 'prerelease': pre, 'draft': False} for tag, pre in self.releases.get(repo, [])]
        raise AssertionError('unexpected request: ' + url)


class ComponentsTest(unittest.TestCase):
    def run_check(self, api):
        with patch.object(components, 'http_json', api), patch.object(ci_retry.time, 'sleep'), patch('sys.stdout', io.StringIO()):
            return components.check(token='t0ken')

    def test_every_pinned_version_is_found_in_the_repository(self):
        found = components.pins()
        self.assertEqual(set(found), {item['name'] for item in components.COMPONENTS})
        self.assertTrue(all(components.numbers(v) for v in found.values()))
        self.assertEqual(found['strongSwan'], '6.1.0')

    def test_version_numbers(self):
        self.assertEqual(components.numbers('v26.10.5-1858'), (26, 10, 5, 1858))
        self.assertEqual(components.numbers('app/v2.13.0'), (2, 13, 0))
        self.assertLess(components.numbers('1.30.5'), components.numbers('1.30.10'))
        self.assertEqual(components.numbers('latest'), ())

    def test_advisory_ranges(self):
        cases = [('2.9.1', '< 2.9.2', '2.9.2', True), ('2.9.2', '< 2.9.2', '2.9.2', False), ('v2.13.0', '>= 2.0.0, < 2.9.2', '2.9.2', False),
                 ('2.5.0', '>= 2.0.0, < 2.9.2', '2.9.2', True), ('1.9.0', '>= 2.0.0, < 2.9.2', '2.9.2', False), ('2.9.2', '<= 2.9.2', '2.9.3', True),
                 ('2.9.2', '= 2.9.2', '', True), ('3.0.0', '= 2.9.2', '', False), ('1.0.0', '', '1.2.0', True), ('1.2.0', '', '1.2.0', False),
                 ('1.0.0', 'все версии', '1.2.0', True), ('5.0.0', 'все версии', '1.2.0', False), ('1.0.0', '', '', True)]
        for version, vulnerable, patched, expected in cases:
            with self.subTest(version=version, vulnerable=vulnerable, patched=patched):
                self.assertIs(components.affected(version, vulnerable, patched), expected)

    def test_clean_state_passes_and_asks_every_source(self):
        api = Api()
        rows, blocked = self.run_check(api)
        self.assertEqual(blocked, [])
        self.assertEqual(len(rows), len(components.COMPONENTS))
        with_cpe = sum(1 for item in components.COMPONENTS if item.get('cpe'))
        with_repo = sum(1 for item in components.COMPONENTS if item.get('repo'))
        self.assertEqual(sum('nvd.nist.gov' in url for url, _ in api.calls), with_cpe)
        self.assertEqual(sum('/security-advisories' in url for url, _ in api.calls), with_repo)
        # Без источника уязвимостей — только компиляторы и snolc: их проверяет Trivy.
        self.assertEqual({row['name'] for row in rows if not row['sources']},
                         {item['name'] for item in components.COMPONENTS if item.get('toolchain') or item.get('release')})
        self.assertTrue(all(row.get('freshness') and not row['unchecked'] for row in rows if not row['sources']))
        self.assertEqual(sum('gitlab.com' in url for url, _ in api.calls), 1)

    def test_high_nvd_finding_blocks_and_lower_is_reported(self):
        api = Api(nvd={'f5:nginx': [cve('CVE-1', 'HIGH'), cve('CVE-2', 'MEDIUM'), cve('CVE-3', 'CRITICAL'), cve('CVE-4', 'HIGH', 'Rejected')]})
        rows, blocked = self.run_check(api)
        self.assertEqual([(b[0], b[2], b[3]) for b in blocked], [('nginx', 'CVE-1', 'HIGH'), ('nginx', 'CVE-3', 'CRITICAL')])
        nginx = next(row for row in rows if row['name'] == 'nginx')
        self.assertEqual([f[0] for f in nginx['findings']], ['CVE-1', 'CVE-2', 'CVE-3'])
        text = components.report(rows, blocked)
        self.assertIn('BLOCK CVE-1 HIGH (NVD)', text)
        self.assertIn('note  CVE-2 MEDIUM (NVD)', text)
        self.assertIn('Component gate: 2 blocking findings', text)

    def test_nvd_is_queried_for_the_exact_pinned_version(self):
        api = Api()
        self.run_check(api)
        nginx = next(url for url, _ in api.calls if 'f5%3Anginx' in url)
        self.assertIn('f5%3Anginx%3A' + components.pins()['nginx'], nginx)
        adguard = next(url for url, _ in api.calls if 'adguard%3Aadguardhome' in url)
        self.assertNotIn('%3Av0', adguard)

    def test_repository_advisory_blocks_only_an_affected_version_with_a_fix(self):
        pinned = components.pins()['Hysteria'].lstrip('v')
        newer = '.'.join(str(n) for n in (*components.numbers(pinned)[:2], components.numbers(pinned)[2] + 1))
        api = Api(advisories={'apernet/hysteria': [
            advisory('GHSA-old', 'high', '< 2.9.2', '2.9.2'),
            advisory('GHSA-now', 'critical', '< ' + newer, newer, 'CVE-NOW'),
            advisory('GHSA-low', 'low', '< ' + newer, newer),
            advisory('GHSA-nofix', 'high', '<= ' + pinned, ''),
        ]})
        rows, blocked = self.run_check(api)
        self.assertEqual([(b[0], b[2], b[3]) for b in blocked], [('Hysteria', 'CVE-NOW', 'CRITICAL')])
        hysteria = next(row for row in rows if row['name'] == 'Hysteria')
        self.assertEqual(sorted(f[0] for f in hysteria['findings']), ['CVE-NOW', 'GHSA-low', 'GHSA-nofix'])
        self.assertIn('note  GHSA-nofix HIGH (GitHub)', components.report(rows, blocked))

    def test_newer_release_is_reported_but_does_not_block(self):
        api = Api(releases={'apernet/hysteria': [('app/v9.0.0', False), ('app/v9.9.9-rc1', True), ('v99.0.0', False)],
                            'SagerNet/sing-box': [('v99.0.0-alpha.1', True), (components.pins()['sing-box'], False)]})
        rows, blocked = self.run_check(api)
        self.assertEqual(blocked, [])
        self.assertEqual({row['name']: row['newer'] for row in rows if row['newer']}, {'Hysteria': 'app/v9.0.0'})
        self.assertIn('вышла версия app/v9.0.0', components.report(rows, blocked))

    def test_toolchains_and_snolc_report_freshness_without_blocking(self):
        found = components.pins()
        self.assertEqual(found['snolc'], '0.0.4')
        self.assertEqual(found['Rust (snolc)'], '1.99.1')
        api = Api(go=[{'version': 'go1.99.0rc1', 'stable': False}, {'version': 'go1.98.4', 'stable': True}],
                  releases={'rust-lang/rust': [('1.200.0', False)], 'owenewans/snolc': [('v0.0.5', False), ('v0.1.0-rc1', True)]})
        rows, blocked = self.run_check(api)
        self.assertEqual(blocked, [])
        newer = {row['name']: row['newer'] for row in rows if row['newer']}
        self.assertEqual(newer['Go'], 'go1.98.4')
        self.assertEqual(newer['Rust (snolc)'], '1.200.0')
        self.assertEqual(newer['snolc'], 'v0.0.5')
        # Уязвимости этих компонентов ищет Trivy в бинарниках: сюда не ходим.
        self.assertFalse(any('owenewans/snolc/security-advisories' in url or 'rust-lang/rust/security' in url for url, _ in api.calls))

    def test_unreachable_freshness_source_is_reported_but_not_fatal(self):
        api = Api(broken=('go.dev', 'rust-lang/rust/releases', 'owenewans/snolc/releases'))
        rows, blocked = self.run_check(api)
        self.assertEqual(blocked, [])
        text = components.report(rows, blocked)
        for name in ('Go', 'Rust (snolc)', 'snolc'):
            self.assertIn(f"{name} {components.pins()[name]}: источник свежести недоступен", text)

    def test_ocserv_security_release_newer_than_the_pin_blocks(self):
        pinned = components.pins()['ocserv']
        major, minor, patch_level = components.numbers(pinned)[:3]
        older, newer, newest = f'{major}.{minor - 1}.9', f'{major}.{minor}.{patch_level + 1}', f'{major}.{minor + 1}.0'
        release = lambda tag, notes, **extra: {'tag_name': tag, 'description': notes, **extra}
        cases = [
            ([release(older, '- [SECURITY] old fix'), release(pinned, '- [SECURITY] already included')], [], None),
            ([release(pinned, ''), release(newer, '- Added an option\n- Fixed a crash on reload')], [], newer),
            ([release(pinned, ''), release(newer, '- [SECURITY] Fixed heap overflow (#1)')], ['security fix in ' + newer], newer),
            ([release(pinned, ''), release(newer, 'fixes CVE-2027-12345 and CVE-2027-0001'), release(newest, None)], ['CVE-2027-0001', 'CVE-2027-12345'], newest),
            ([release(pinned, ''), release(newer, '- [SECURITY] not out yet', upcoming_release=True)], [], None),
        ]
        for releases, expected, latest in cases:
            with self.subTest(expected=expected, latest=latest):
                rows, blocked = self.run_check(Api(gitlab=releases))
                self.assertEqual([b[2] for b in blocked], expected)
                row = next(row for row in rows if row['name'] == 'ocserv')
                self.assertEqual((row['newer'], row['sources']), (latest, ['GitLab']))
        text = components.report(*self.run_check(Api(gitlab=cases[2][0])))
        self.assertIn('BLOCK security fix in ' + newer + ' HIGH (GitLab)', text)
        self.assertIn('ocserv ' + pinned + ': проверено по GitLab', text)

    def test_ocserv_pin_missing_from_the_release_list_is_not_a_clean_bill(self):
        for answer in ([], [{'tag_name': '0.0.1', 'description': ''}], {'message': '404'}, [{'description': 'no tag'}]):
            with self.subTest(answer=answer), self.assertRaises(ValueError):
                self.run_check(Api(gitlab=answer))

    def test_unreachable_source_fails_closed_after_retries(self):
        for broken in ('nvd.nist.gov', '/security-advisories', 'api.github.com/repos/XTLS/Xray-core/releases', 'gitlab.com'):
            api = Api(broken=(broken,))
            with self.subTest(broken=broken), self.assertRaises(OSError):
                self.run_check(api)
            self.assertEqual(sum(broken in url for url, _ in api.calls), 4)

    def test_malformed_answer_is_not_a_clean_bill(self):
        with patch.object(components, 'http_json', lambda url, token=None: {'message': 'rate limit'}), patch.object(ci_retry.time, 'sleep'), \
                self.assertRaises(ValueError):
            components.check(token=None)

    def test_command_line_exit_codes_and_no_secret_in_output(self):
        def run(api):
            out, err = io.StringIO(), io.StringIO()
            with patch.object(components, 'http_json', api), patch.object(ci_retry.time, 'sleep'), patch('sys.stdout', out), patch('sys.stderr', err), \
                    patch.dict(os.environ, {'GH_TOKEN': 's3cret-token', 'NVD_API_KEY': 'nvd-s3cret'}, clear=False):
                try:
                    code = components.main()
                except (OSError, ValueError, KeyError) as error:
                    print('Component gate failed:', type(error).__name__, file=err)
                    code = 2
            return code, out.getvalue() + err.getvalue()
        self.assertEqual(run(Api())[0], 0)
        code, text = run(Api(nvd={'f5:nginx': [cve('CVE-1', 'HIGH')]}))
        self.assertEqual(code, 1)
        code, text = run(Api(broken=('nvd.nist.gov',)))
        self.assertEqual(code, 2)
        self.assertNotIn('s3cret', text)

    def test_tokens_go_to_their_own_service_only(self):
        api = Api()
        with patch.dict(os.environ, {'NVD_API_KEY': 'nvd-key'}, clear=False):
            self.run_check(api)
        expected = lambda url: 'nvd-key' if 'nvd.nist.gov' in url else None if 'gitlab.com' in url or 'go.dev' in url else 't0ken'
        self.assertTrue(all(token == expected(url) for url, token in api.calls))


if __name__ == '__main__':
    unittest.main()
