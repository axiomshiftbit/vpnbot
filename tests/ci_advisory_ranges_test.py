"""Диапазоны advisory и итоговый gate; без .env, токенов и внешней сети."""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import ci_check_components as c


class AdvisoryRangesTest(unittest.TestCase):
    def test_multiple_fixed_branches_do_not_hide_affected_version(self):
        for fixed in ('2.5.9, 2.6.10', '2.6.10, 2.5.9', '2.6.10', ''):
            with self.subTest(fixed=fixed):
                self.assertTrue(c.affected('2.6.9', '>= 2.6.0, < 2.6.10', fixed))
                self.assertFalse(c.affected('2.6.10', '>= 2.6.0, < 2.6.10', fixed))

    def test_semver_prerelease_and_build_metadata(self):
        for version, expected in [('1.2.3-alpha.2', True), ('1.2.3-alpha.10', True),
                                  ('1.2.3-rc.1', True), ('1.2.3', False), ('1.2.3+build.99', False)]:
            with self.subTest(version=version):
                self.assertIs(c.affected(version, '>= 1.2.3-alpha.2, < 1.2.3', '1.2.3'), expected)
        self.assertFalse(c.affected('1.2.3-alpha.2', '>= 1.2.3-alpha.10, < 1.2.3', '1.2.3'))

    def test_alternative_branches(self):
        affected = '>= 1.0.0, < 1.2.0 || >= 2.0.0, < 2.1.0'
        for version, expected in [('1.1.0', True), ('1.2.0', False), ('2.0.2', True), ('3.0.0', False)]:
            with self.subTest(version=version):
                self.assertIs(c.affected(version, affected, '1.2.0, 2.1.0'), expected)

    def test_unknown_ranges_fail_closed(self):
        for value in ('', None, 'all versions', '>= 1.0.0 ||', '<1.0.0, invalid', '^1.0.0'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                c.affected('2.6.9', value, '2.5.9, 2.6.10')

    def test_affected_high_reaches_final_gate(self):
        item = {'name':'synthetic', 'pin':'SYNTHETIC_VERSION', 'repo':'synthetic/component'}
        def data(fixed):
            return [{'ghsa_id':'SYNTHETIC-HIGH', 'severity':'high', 'vulnerabilities':[
                {'vulnerable_version_range':'>= 2.6.0, < 2.6.10', 'patched_versions':fixed}]}]
        with patch.object(c, 'COMPONENTS', [item]), patch.object(c, 'pins', return_value={'synthetic':'2.6.9'}):
            for fixed in ('2.5.9, 2.6.10', '2.6.10, 2.5.9'):
                with self.subTest(fixed=fixed), patch.object(c, 'fetch', return_value=data(fixed)):
                    _, blocked = c.check(freshness=False)
                    self.assertEqual([row[2] for row in blocked], ['SYNTHETIC-HIGH'])
            with patch.object(c, 'fetch', return_value=data('')):
                rows, blocked = c.check(freshness=False)
                self.assertEqual(blocked, [])
                self.assertEqual(rows[0]['findings'][0][0], 'SYNTHETIC-HIGH')
                self.assertFalse(rows[0]['findings'][0][2])
            with patch.object(c, 'fetch', return_value=data('some future version')):
                with self.assertRaises(ValueError):
                    c.check(freshness=False)


if __name__ == '__main__':
    unittest.main()
