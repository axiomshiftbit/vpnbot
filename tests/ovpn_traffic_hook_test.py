"""OpenVPN accounting: synthetic metadata/counters, real files and flock."""
import errno
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import ovpn_traffic as traffic

ENV = dict(script_type='client-connect', common_name='alice', trusted_ip='203.0.113.1', trusted_port='1000',
           time_unix='100', daemon_start_time='90', daemon_pid='42')


class TrafficHook(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.path, self.lock = Path(tmp.name)/'traffic.json', Path(tmp.name)/'lock'

    def call(self, **changes): traffic.event(self.path, self.lock, ENV | changes, now=105)
    def saved(self): return json.loads(self.path.read_bytes())

    def finish(self, rx='900', tx='50', **changes):
        self.call(script_type='client-disconnect', bytes_received=rx, bytes_sent=tx, **changes)

    def test_short_session_without_poll_and_duplicate_final(self):
        self.call(); self.finish(); self.finish()
        self.assertEqual((self.saved()['users']['alice']['rx'], self.saved()['users']['alice']['tx']), (900, 50))
        self.assertEqual(self.saved()['users']['alice']['live'], {})
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_collision_rejected_but_next_epoch_and_new_daemon_allowed(self):
        self.call()
        with self.assertRaises(ValueError): self.call()
        self.finish()
        with self.assertRaises(ValueError): self.call()
        self.call(time_unix='101'); self.finish(time_unix='101')
        self.call(daemon_pid='43'); self.finish(daemon_pid='43')
        self.assertEqual(self.saved()['users']['alice']['rx'], 2700)

    def test_reset_baseline_and_final_never_double_count(self):
        self.call(); data = self.saved(); row = data['users']['alice']
        key = next(iter(row['live'])); row['live'][key] = [900, 50, 900, 50]
        traffic.save(self.path, data)
        self.finish('1500', '80')
        self.assertEqual((self.saved()['users']['alice']['rx'], self.saved()['users']['alice']['tx']), (600, 30))

    def test_quota_blocks_immediate_reconnect_before_cron(self):
        self.call(); data = self.saved(); data['users']['alice']['limit'] = 950; traffic.save(self.path, data)
        self.finish()
        with self.assertRaisesRegex(ValueError, 'limit'): self.call(time_unix='101')

    def test_dead_daemon_preserves_last_sample_and_separates_reused_ids(self):
        self.call(); data = self.saved(); row = data['users']['alice']
        key = next(iter(row['live'])); row['live'][key] = [500, 100, 20, 10]; traffic.save(self.path, data)
        self.call(daemon_start_time='110', daemon_pid='42')
        row = self.saved()['users']['alice']
        self.assertEqual((row['rx'], row['tx']), (480, 90)); self.assertEqual(len(row['live']), 1)

    def test_storage_fault_cannot_admit_connect_or_destroy_old_checkpoint(self):
        self.call(); before = self.path.read_bytes()
        with patch.object(traffic.os, 'replace', side_effect=OSError(errno.ENOSPC, 'synthetic')):
            with self.assertRaises(OSError): self.call(time_unix='101')
        self.assertEqual(self.path.read_bytes(), before)
        self.path.write_bytes(b'{invalid')
        with self.assertRaises(ValueError): self.call(time_unix='101')
        self.assertEqual(self.path.read_bytes(), b'{invalid')

    def test_late_disconnect_does_not_resurrect_deleted_user_or_session(self):
        self.call(); data = self.saved(); data['users'] = {}; traffic.save(self.path, data)
        self.finish(); self.assertEqual(self.saved()['users'], {})
        data = self.saved(); data['sessions'] = {}; traffic.save(self.path, data)
        self.finish(); self.assertEqual(self.saved()['sessions'], {})

    def test_ipv6_identity_and_php_empty_arrays(self):
        self.path.write_text('{"users":[],"sessions":[]}')
        self.call(trusted_ip='', trusted_ip6='2001:db8::1')
        self.finish(trusted_ip='', trusted_ip6='2001:db8::1')
        self.assertEqual(self.saved()['users']['alice']['rx'], 900)


if __name__ == '__main__': unittest.main()
