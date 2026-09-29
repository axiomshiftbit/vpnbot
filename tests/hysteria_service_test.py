import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("hysteria_service", Path(__file__).resolve().parents[1] / "scripts/hysteria_service.py")
hy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hy)


class Process:
    def poll(self):
        return None


class HysteriaServiceTest(unittest.TestCase):
    def test_core_from_path_is_validated_and_missing_core_is_reported(self):
        binary = self.root / 'path-only-hysteria'
        binary.write_text('#!/bin/sh\necho "server up and running"\nexec /bin/sleep 5\n')
        binary.chmod(0o700)
        self.s.binary = Path(binary.name)
        with patch.dict(os.environ, {'PATH': str(self.root)}):
            self.s.validate_config({'listen': '127.0.0.1:0'})
            self.assertGreater(self.s.last_validation, 0)
            binary.unlink()
            with self.assertRaisesRegex(RuntimeError, '^core_unavailable$'):
                self.s.validate_config({'listen': '127.0.0.1:0'})

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.users = self.root / "users.json"
        self.runtime = self.root / "runtime"
        self.s = hy.Supervisor(self.root / "config.yaml", self.users, self.runtime)
        self.uid = "ab12345678901234"
        self.user = {"name": "Тест", "enabled": True, "password": "P" * 43, "reset": "ab" * 8, "expires": None, "quota": None}
        self.state = {"schema": 1, "protocol": "hysteria2", "revision": 1, "users": {self.uid: self.user}}
        self.save()
        self.s.state = copy.deepcopy(self.state)
        self.s.process = Process()
        self.s.ready = True
        self.s.config = {"auth": {"type": "password", "password": "старый:общий-пароль"}}
        self.s.stats_time = time.monotonic()
        self.s.usage = {"users": {self.uid: {"reset": self.user["reset"], "upload": 10, "download": 20}}}

    def tearDown(self):
        self.temp.cleanup()

    def save(self):
        self.users.write_text(json.dumps(self.state))

    def auth(self, password=None):
        return self.s.authenticate(self.uid + ":" + (password or self.user["password"]))["ok"]

    def test_credentials_and_legacy(self):
        self.assertTrue(self.auth())
        self.assertFalse(self.auth("invalid"))
        self.assertEqual(self.s.authenticate("старый:общий-пароль"), {"ok": True, "id": "legacy"})
        self.assertFalse(self.s.authenticate("wrong")["ok"])

    def test_revocation_and_expiry_read_current_file(self):
        self.assertTrue(self.auth())
        for change in ({"enabled": False}, {"expires": int(time.time()) - 1}):
            self.state["users"][self.uid] = self.user | change
            self.save()
            self.assertFalse(self.auth())
        self.users.write_text("{")
        self.assertFalse(self.auth())

    def test_rotation_remembers_old_live_credentials(self):
        self.assertTrue(self.auth())
        old = self.user["password"]
        self.user["password"] = "N" * 43
        self.save()
        self.assertFalse(self.auth(old))
        self.assertTrue(self.auth())
        # A reconnect must not erase the older connection waiting to be revoked.
        self.assertIn(old, self.s.authorized[self.uid])
        self.assertIn(self.user["password"], self.s.authorized[self.uid])

    def test_quota_and_stale_statistics(self):
        self.user["quota"] = 31
        self.save()
        self.assertTrue(self.auth())
        self.s.usage["users"][self.uid]["upload"] = 11
        self.assertFalse(self.auth())
        self.s.usage["users"][self.uid]["upload"] = 10
        self.s.stats_time = time.monotonic() - 11
        self.assertFalse(self.auth())

    def test_counters_direction_reset_and_repeat(self):
        counters = {self.uid: {"tx": 200, "rx": 100}}
        with patch.object(self.s, "counters", return_value=counters):
            self.s.collect()
            row = self.s.usage["users"][self.uid]
            self.assertEqual((row["upload"], row["download"]), (110, 220))
            self.s.collect()
            self.assertEqual(self.s.usage["users"][self.uid], row)
            self.s.state["users"][self.uid]["reset"] = "cd" * 8
            self.s.collect()
            self.assertEqual(self.s.usage["users"][self.uid]["upload"], 0)
            self.assertEqual(self.s.usage["users"][self.uid]["download"], 0)
            counters[self.uid] = {"tx": 260, "rx": 140}
            self.s.collect()
            self.assertEqual(self.s.usage["users"][self.uid]["upload"], 40)
            self.assertEqual(self.s.usage["users"][self.uid]["download"], 60)

    def test_failed_write_does_not_acknowledge_collection(self):
        old_time = self.s.stats_time
        before = copy.deepcopy(self.s.usage)
        with patch.object(self.s, "counters", return_value={self.uid: {"tx": 20, "rx": 30}}), \
                patch.object(hy, "atomic_json", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.s.collect()
        self.assertEqual(self.s.stats_time, old_time)
        self.assertEqual(self.s.usage, before)

    def test_unicode_wrong_password_is_rejected_without_crashing_auth(self):
        self.assertFalse(self.s.authenticate(self.uid + ":неверный-пароль")["ok"])
        self.assertTrue(self.auth())

    def test_missing_or_corrupt_usage_never_grants_fresh_quota(self):
        with self.assertRaises(ValueError):
            hy.Supervisor(self.root / "config.yaml", self.users, self.runtime)
        (self.runtime / "usage.json").write_text('{"users": {"ab12345678901234": {"upload": -1}}}')
        with self.assertRaises(ValueError):
            hy.Supervisor(self.root / "config.yaml", self.users, self.runtime)

    def test_invalid_states(self):
        for field, value in (("enabled", 1), ("quota", True), ("quota", -1), ("expires", "100"),
                             ("password", ""), ("name", "bad\nname"), ("reset", "bad")):
            self.state["users"][self.uid] = self.user | {field: value}
            self.save()
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                hy.read_users(self.users)


if __name__ == "__main__":
    unittest.main()
