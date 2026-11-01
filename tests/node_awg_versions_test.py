#!/usr/bin/env python3
import copy
import unittest
from node_awg_test import Amnezia, awg


class AmneziaVersions(Amnezia):
    def test_protocol_versions_really_change_both_wire_configs(self):
        before = copy.deepcopy(self.keys)
        for version in ('1.5', '2.0', '3.0', '3.1'):
            with self.subTest(version=version):
                options = {'enabled': True, 'active': True, 'version': version}
                profile = awg.profile(options, '1.1.1.1', self.keys)
                self.assertEqual(profile['version'], version)
                for text in (awg.server(options, self.keys), awg.client(profile, 0)):
                    self.assertEqual('HeaderProtectionKey =' in text, version in ('3.0', '3.1'))
                    self.assertEqual('ContentPaddingAddition =' in text, version in ('3.0', '3.1'))
                    self.assertEqual('S3 =' in text, version != '1.5')
                    self.assertIn('DisableCookies = off', text)
                    if version != '3.1': self.assertNotIn('RandomTrailers = on', text)
                    if version == '1.5':
                        self.assertRegex(text, r'H1 = [0-9]+\n')
                        self.assertRegex(text, r'PersistentKeepalive = [0-9]+\n' if '[TCPClientTunnel]' in text else r'H2 = [0-9]+\n')
        self.assertEqual(self.keys, before, 'switching protocol never rotates or mutates keys')

    def test_version_and_cross_version_fields_are_strict(self):
        for version in ('0', '4.0', 2, True, []):
            with self.subTest(version=version), self.assertRaises(ValueError):
                awg.settings({'version': version})
        for version, patch in [('1.5', {'S3': 0}), ('2.0', {'RekeyTimeout': '5-10'})]:
            with self.subTest(version=version), self.assertRaises(ValueError):
                awg.settings({'version': version, 'parameters': patch})
        old = self.value.copy(); old.pop('version', None)
        self.assertEqual(awg.validate_client(old), old, 'previous backups default to the existing 3.1 protocol')


if __name__ == '__main__':
    unittest.main()
