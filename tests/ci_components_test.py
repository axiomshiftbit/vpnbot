#!/usr/bin/env python3
"""Проверка известных уязвимостей и свежести закреплённых версий."""
import io
import json
import os
import re
import sys
import unittest
import urllib.error
import urllib.parse
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


def nginx_entry(title, severity, cve_id, safe, vulnerable):
    return (f'<li><p>{title}<br>Severity: {severity}<br><a href="x">Advisory</a><br><a href="y">{cve_id}</a><br>'
            f'Not vulnerable: {safe}<br>Vulnerable: {vulnerable}<br><a href="p">The patch</a></p></li>')


# Страница nginx.org без объявлений, затрагивающих закреплённую версию.
QUIET_NGINX = '<ul>' + ''.join(nginx_entry(f'Old issue {n}', 'medium', f'CVE-2009-{1000 + n}', '0.8.15+', '0.1.0-0.8.14')
                               for n in range(12)) + '</ul>'


class Api:
    """Подмена сети: ответы по подстроке адреса; неизвестный адрес — ошибка теста."""

    def __init__(self, nvd=None, advisories=None, releases=None, broken=(), gitlab=None, go=None, tags=None,
                 nginx=None, git_head=None, alpine=None):
        self.nvd, self.advisories, self.releases, self.broken, self.calls = nvd or {}, advisories or {}, releases or {}, broken, []
        self.gitlab, self.tags = gitlab, tags or {}
        self.go = go if go is not None else [{'version': 'go' + components.pins()['Go'], 'stable': True}]
        self.nginx = nginx if nginx is not None else QUIET_NGINX
        self.git_head = git_head or components.pins()['DNSTT']
        pinned = 'v' + '.'.join(map(str, components.numbers(components.pins()['Alpine'])[:2]))
        self.alpine = alpine if alpine is not None else {
            'latest_stable': pinned, 'release_branches': [{'rel_branch': pinned, 'repos': [{'name': 'community', 'eol_date': '2999-01-01'}]}]}
        self.texts = []

    def text(self, url):
        self.texts.append(url)
        if any(part in url for part in self.broken):
            raise urllib.error.URLError('down')
        if url == components.NGINX_ADVISORIES:
            return self.nginx
        if url.endswith('/HEAD'):
            return 'ref: refs/heads/master\n'
        if url.endswith('/info/refs'):
            return f'{"1" * 40}\trefs/heads/any-domain\n{self.git_head}\trefs/heads/master\n{"2" * 40}\trefs/tags/v0.1\n'
        raise AssertionError('unexpected text request: ' + url)

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
        if url == 'https://alpinelinux.org/releases.json':
            return self.alpine
        if 'gitlab.com' in url:
            assert 'openconnect%2Focserv' in url, url
            if self.gitlab is None:
                return [{'tag_name': components.pins()['ocserv'], 'description': '- [SECURITY] fixed long ago'}]
            return self.gitlab
        repo = url.split('/repos/')[1].split('/security-advisories')[0].split('/releases')[0].split('/tags')[0]
        if '/tags' in url:
            return [{'name': tag} for tag in self.tags.get(repo, [])]
        if '/security-advisories' in url:
            page = int(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get('page', ['1'])[0])
            return self.advisories.get(repo, [])[100 * (page - 1):100 * page]
        if '/releases' in url:
            return [{'tag_name': tag, 'prerelease': pre, 'draft': False} for tag, pre in self.releases.get(repo, [])]
        raise AssertionError('unexpected request: ' + url)


class ComponentsTest(unittest.TestCase):
    def run_check(self, api):
        with patch.object(components, 'http_json', api), patch.object(components, 'http_text', api.text), \
                patch.object(ci_retry.time, 'sleep'), patch('sys.stdout', io.StringIO()):
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
                 ('2.9.2', '= 2.9.2', '', True), ('3.0.0', '= 2.9.2', '', False),
                 # Free-form ranges seen in repository advisories (pppd, jQuery, Caddy).
                 ('2.5.5', '2.5.0 to 2.5.3', '', False), ('2.5.3', '2.4.9 to 2.5.3', '2.5.4', True),
                 ('3.7.1', '>=1.0.3 <3.5.0', '3.5.0', False), ('3.4.1', '>=1.2 <3.5.0', '3.5.0', True),
                 ('v2.11.9', 'v2.4.0 and later', 'v2.11.3', False), ('v2.11.2', 'v2.4.0 and later', 'v2.11.3', True), ('v2.3.0', 'v2.4.0 and later', 'v2.11.3', False),
                 ('v2.11.9', '(confirmed on main @ e0f8d9b)', 'v2.11.0', False),
                 # Free-form patched versions and an open range already fixed.
                 ('v2.11.9', '< v2.11.5', 'v.2.11.5', False), ('v2.11.4', '< v2.11.5', 'v.2.11.5', True),
                 ('v26.11.9', '>= v26.1.13', '>= v26.7.11', False), ('v26.5.0', '>= v26.1.13', '>= v26.7.11', True),
                 ('3.15.2', '>= 3.0.0, < 3.15.2 || >= 4.0.0, < 4.3.2', '4.3.2, 3.15.2', False),
                 ('3.15.1', '>= 3.0.0, < 3.15.2 || >= 4.0.0, < 4.3.2', '4.3.2, 3.15.2', True)]
        for version, vulnerable, patched, expected in cases:
            with self.subTest(version=version, vulnerable=vulnerable, patched=patched):
                self.assertIs(components.affected(version, vulnerable, patched), expected)
        for vulnerable in ('', 'все версии'):
            with self.subTest(vulnerable=vulnerable), self.assertRaises(ValueError):
                components.affected('1.2.0', vulnerable, '1.2.0')
        # Unreadable text without a strictly older fix still stops the gate.
        for patched in ('', 'v2.12.0', 'v2.11.9', 'v2.10.0, v3.0.0'):
            with self.subTest(patched=patched), self.assertRaises(ValueError):
                components.affected('v2.11.9', '(confirmed on main @ e0f8d9b)', patched)

    def test_clean_state_passes_and_asks_every_source(self):
        api = Api()
        rows, blocked = self.run_check(api)
        self.assertEqual(blocked, [])
        self.assertEqual(len(rows), len(components.COMPONENTS))
        with_cpe = sum(1 for item in components.COMPONENTS if item.get('cpe'))
        with_repo = sum(bool(item.get(key)) for item in components.COMPONENTS for key in ('repo', 'upstream'))
        self.assertEqual(sum('nvd.nist.gov' in url for url, _ in api.calls), with_cpe)
        self.assertEqual(sum('/security-advisories' in url for url, _ in api.calls), with_repo)
        # Без источника уязвимостей — только компиляторы, snolc, Alpine и инструменты сборки.
        self.assertEqual({row['name'] for row in rows if not row['sources']},
                         {item['name'] for item in components.COMPONENTS if any(item.get(k) for k in components.FRESHNESS_ONLY)})
        self.assertEqual(api.texts.count(components.NGINX_ADVISORIES), 1)
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

    def test_every_xray_build_in_the_images_is_checked_against_xray_advisories(self):
        # Slot cores stay old on purpose, but a fixed advisory against them must block like the current core.
        current = components.numbers(components.pins()['Xray'])
        fixed = '.'.join(map(str, current[:3]))
        api = Api(advisories={'XTLS/Xray-core': [advisory('GHSA-slot', 'critical', '< ' + fixed, fixed, 'CVE-SLOT')]},
                  releases={'XTLS/Xray-core': [('v99.0.0', False)]})
        rows, blocked = self.run_check(api)
        names = {b[0] for b in blocked if b[2] == 'CVE-SLOT'}
        self.assertEqual(names, {'Xray (slot 2)', 'Xray (slot 3)'})
        newer = {row['name'] for row in rows if row['newer']}
        self.assertTrue({'Xray', 'Xray (MASQUE)'} <= newer and not {'Xray (slot 2)', 'Xray (slot 3)'} & newer)
        masque = next(row for row in rows if row['name'] == 'Xray (MASQUE)')
        self.assertEqual(masque['sources'], ['GitHub'])

    def test_advisory_beyond_first_page_and_upstream_build_of_fork(self):
        fork = components.pins()['Xray (fork)']
        base = re.fullmatch(r'(v?\d+\.\d+\.\d+)-\d+', fork).group(1)
        old = advisory('GHSA-old', 'low', '< 0.1.0', '0.1.0')
        current = advisory('GHSA-upstream', 'high', '= ' + base, '99.0.0')
        own = advisory('GHSA-fork', 'critical', '= ' + fork, '99.0.0')
        api = Api(advisories={'XTLS/Xray-core': [old] * 100 + [current],
                              'Jolymmiles/Xray-core': [own]})
        _, blocked = self.run_check(api)
        self.assertEqual({row[2] for row in blocked if row[0] == 'Xray (fork)'}, {'GHSA-upstream', 'GHSA-fork'})

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
        self.assertEqual(found['Rust (snolc)'], '1.100.0')
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
        with patch.object(components, 'http_json', lambda url, token=None: {'message': 'rate limit'}), \
                patch.object(components, 'http_text', Api().text), patch.object(ci_retry.time, 'sleep'), \
                self.assertRaises(ValueError):
            components.check(token=None)

    def test_command_line_exit_codes_and_no_secret_in_output(self):
        def run(api):
            out, err = io.StringIO(), io.StringIO()
            with patch.object(components, 'http_json', api), patch.object(components, 'http_text', api.text), \
                    patch.object(ci_retry.time, 'sleep'), patch('sys.stdout', out), patch('sys.stderr', err), \
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
        expected = lambda url: 'nvd-key' if 'nvd.nist.gov' in url else None if any(h in url for h in ('gitlab.com', 'go.dev', 'alpinelinux.org')) else 't0ken'
        self.assertTrue(all(token == expected(url) for url, token in api.calls))

    def test_every_pinned_version_is_checked_or_exempt(self):
        # Страж: новый пин без проверки свежести уходил бы в сборку незамеченным.
        names = {line.split('=', 1)[0] for line in (ROOT / '.env').read_text().splitlines()
                 if re.match(r'^[A-Z0-9_]*(VERSION[A-Z0-9_]*|_REF)=\S', line)} | {'IMAGE'}
        for dockerfile in (ROOT / 'dockerfile').glob('*.dockerfile'):
            names |= set(re.findall(r'^ARG ([A-Z0-9_]*(?:VERSION[A-Z0-9_]*|_REF))=[^"\s]\S*$', dockerfile.read_text(), re.M))
        covered = {item['pin'].split(':')[-1] for item in components.COMPONENTS}
        self.assertEqual(names - covered - set(components.UNCHECKED), set(), 'пин без проверки: дописать в COMPONENTS или UNCHECKED')
        self.assertEqual(set(components.UNCHECKED) - names, set(), 'исключение для несуществующего пина')

    def test_nginx_advisory_blocks_when_fixed_in_the_pinned_branch(self):
        pinned = components.pins()['nginx']
        major, minor, level = components.numbers(pinned)[:3]
        fixed, mainline = f'{major}.{minor}.{level + 1}', f'{major}.{minor + 1}.0'
        page = QUIET_NGINX.replace('</ul>', ''.join([
            nginx_entry('Overflow', 'medium', 'CVE-2099-0001', f'{mainline}+, {fixed}+', f'{major}.{minor}.0-{pinned}'),
            nginx_entry('Old branch only', 'medium', 'CVE-2099-0002', f'{pinned}+', f'{major}.{minor}.0-{major}.{minor}.{max(level - 1, 0)}'),
            nginx_entry('Unfixed', 'low', 'CVE-2099-0003', 'none', 'all'),
            nginx_entry('Windows only', 'major', 'CVE-2099-0004', f'{fixed}+', f'nginx/Windows 0.7.52-{pinned}'),
            '<li><p>Major one<br>Severity: <b>major</b><br><a href="y">CVE-2099-0005</a><br>'
            f'Not vulnerable: {fixed}+<br>Vulnerable: 0.1.0-{pinned}</p></li>',
            # Одна версия без диапазона (так nginx.org пишет, например, «1.25.0-1.25.5, 1.26.0»).
            nginx_entry('Single release', 'low', 'CVE-2099-0006', f'{mainline}+, {fixed}+', f'0.1.0-0.1.1, {pinned}'),
        ]) + '</ul>')
        rows, blocked = self.run_check(Api(nginx=page, releases={'nginx/nginx': [('release-' + mainline, False), ('release-' + fixed, False)]}))
        self.assertEqual([(b[2], b[3], b[5]) for b in blocked], [('CVE-2099-0001', 'MEDIUM', 'nginx.org'), ('CVE-2099-0005', 'HIGH', 'nginx.org'),
                                                                 ('CVE-2099-0006', 'LOW', 'nginx.org')])
        nginx = next(row for row in rows if row['name'] == 'nginx')
        self.assertEqual(sorted(f[0] for f in nginx['findings']), ['CVE-2099-0001', 'CVE-2099-0003', 'CVE-2099-0005', 'CVE-2099-0006'])
        # Свежесть — в своей стабильной ветке: mainline не предлагается.
        self.assertEqual(nginx['newer'], 'release-' + fixed)
        text = components.report(rows, blocked)
        self.assertIn('BLOCK CVE-2099-0001 MEDIUM (nginx.org)', text)
        self.assertIn('note  CVE-2099-0003 LOW (nginx.org)', text)

    def test_nginx_page_that_cannot_be_read_is_not_a_clean_bill(self):
        for page in ('<html>maintenance</html>', QUIET_NGINX.replace('Vulnerable:', 'Affected:'),
                     QUIET_NGINX.replace('0.1.0-0.8.14', '0.1.0 to 0.8.14')):
            with self.subTest(page=page[:20]), self.assertRaises(ValueError):
                self.run_check(Api(nginx=page))

    def test_build_tools_git_refs_and_alpine_report_freshness(self):
        found = components.pins()
        self.assertEqual(found['Trivy'], '0.76.2')
        head = 'f' * 40
        api = Api(git_head=head, tags={'amnezia-vpn/amneziawg-go': ['v9.9.20990101', 'v9.9.20990202-rc1']},
                  releases={'aquasecurity/trivy': [('v9.0.0', False)], 'TrustTunnel/TrustTunnel': [('v9.0.0-beta.1', True), (found['TrustTunnel'], False)],
                            'klzgrad/forwardproxy': [('caddy2-naive-20991231', False), (found['forwardproxy (Naive)'], False)]},
                  alpine={'latest_stable': 'v9.1', 'release_branches': [
                      {'rel_branch': 'v' + '.'.join(map(str, components.numbers(found['Alpine'])[:2])), 'repos': [{'name': 'community', 'eol_date': '2000-01-01'}]}]})
        rows, blocked = self.run_check(api)
        self.assertEqual(blocked, [])
        newer = {row['name']: row['newer'] for row in rows if row['newer']}
        self.assertEqual(newer, {'Trivy': 'v9.0.0', 'DNSTT': head[:12], 'Alpine': 'v9.1', 'AmneziaWG': 'v9.9.20990101'})
        text = components.report(rows, blocked)
        self.assertIn('внимание: поддержка community', text)
        self.assertIn('DNSTT ' + found['DNSTT'] + ': свежесть по git', text)

    def test_odd_alpine_answer_is_only_unchecked_freshness(self):
        # Источник свежести: непривычный ответ не роняет проверку и не блокирует допуск.
        for answer in ({'latest_stable': 'v9.1', 'release_branches': ['v9.1']},
                       {'latest_stable': 'v9.1', 'release_branches': [{'rel_branch': 'v' + '.'.join(map(str, components.numbers(components.pins()['Alpine'])[:2])),
                                                                       'repos': [{'name': 'community', 'eol_date': 'soon'}]}]}):
            with self.subTest(answer=answer):
                api = Api(alpine=answer)
                rows, blocked = self.run_check(api)
                alpine = next(row for row in rows if row['name'] == 'Alpine')
                self.assertEqual((blocked, alpine['unchecked'], alpine['notes']), ([], True, []))
                self.assertEqual(sum('alpinelinux.org' in url for url, _ in api.calls), 1)



class TokenRecipientTest(unittest.TestCase):
    def test_keys_reach_only_their_exact_hosts_over_https(self):
        sent = []

        class Response:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, *a): return b'{}'

        def urlopen(request, timeout):
            sent.append((request.full_url, dict(request.header_items())))
            return Response()

        cases = [('https://services.nvd.nist.gov/rest', 'Apikey'), ('https://api.github.com/repos/x', 'Authorization'),
                 ('https://evil.example/?services.nvd.nist.gov', None), ('https://nvd.nist.gov.evil.example/', None),
                 ('https://api.github.com.evil.example/', None), ('http://api.github.com/repos/x', None),
                 ('https://gitlab.com/api/v4/projects/x', None)]
        with patch.object(components.urllib.request, 'urlopen', urlopen), patch.object(components.json, 'load', lambda r: {}):
            for url, header in cases:
                sent.clear()
                components.http_json(url, 'SYNTHETIC-TOKEN')
                headers = sent[0][1]
                with self.subTest(url=url):
                    leaked = [k for k, v in headers.items() if 'SYNTHETIC-TOKEN' in v]
                    self.assertEqual([header] if header else [], leaked)

if __name__ == '__main__':
    unittest.main()
