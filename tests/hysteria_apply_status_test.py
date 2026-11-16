"""MAN-01: status.json names the configuration that actually runs.

The bot confirms an applied hysteria.yaml by its SHA-256. A configuration the
supervisor rejects (validation or start) must leave the previous digest.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("hysteria_service_apply", Path(__file__).resolve().parents[1] / "scripts/hysteria_service.py")
hy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hy)


class Process:
    def poll(self):
        return None

    def terminate(self):
        pass

    def wait(self, timeout=None):
        return 0


class ApplyStatusTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        (root / "cert").write_text("CERT"); (root / "key").write_text("KEY")
        self.config, self.users, self.runtime = root / "config.yaml", root / "users.json", root / "runtime"
        self.users.write_text(json.dumps({"schema": 1, "protocol": "hysteria2", "revision": 1, "users": {}}))
        self.tls = 'tls:\n  cert: %s\n  key: %s\n' % (root / "cert", root / "key")
        self.s = hy.Supervisor(self.config, self.users, self.runtime)
        self.s.collect = lambda: None  # statistics API of the core is not under test

    def tearDown(self):
        self.temp.cleanup()

    def write(self, password):
        self.config.write_text('listen: ":443"\nauth:\n  type: password\n  password: %s\n%s' % (password, self.tls))
        return hashlib.sha256(self.config.read_bytes()).hexdigest()

    def status(self):
        return json.loads((self.runtime / "status.json").read_text())

    def started(self, config):
        self.s.process = Process()

    def test_digest_follows_only_accepted_configuration(self):
        with patch.object(self.s, "validate_config"), patch.object(self.s, "start", side_effect=self.started):
            first = self.write("old-shared")
            self.s.tick()
            self.assertEqual((self.status().get("config_sha256"), self.status()["error"]), (first, ""))
        # Validation rejects the new file: the old configuration keeps running.
        with patch.object(self.s, "validate_config", side_effect=RuntimeError("configuration_rejected")), \
                patch.object(self.s, "start", side_effect=self.started):
            rejected = self.write("new-shared")
            self.s.tick()
            self.assertEqual(self.status().get("config_sha256"), first)
            self.assertEqual(self.status().get("checked_sha256"), rejected, "the rejection names the examined file")
            self.assertEqual(self.status()["error"], "configuration_rejected")
            self.assertEqual(self.s.config["auth"]["password"], "old-shared")

    def test_start_failure_falls_back_and_keeps_previous_digest(self):
        with patch.object(self.s, "validate_config"), patch.object(self.s, "start", side_effect=self.started):
            first = self.write("old-shared")
            self.s.tick()

        def start(config):
            if config["auth"]["password"] == "new-shared":
                raise RuntimeError("start_failed")
            self.started(config)
        with patch.object(self.s, "validate_config"), patch.object(self.s, "start", side_effect=start):
            self.write("new-shared")
            self.s.tick()
            self.assertEqual(self.status().get("config_sha256"), first)
            self.assertEqual(self.status()["error"], "configuration_rejected")
        with patch.object(self.s, "validate_config"), patch.object(self.s, "start", side_effect=self.started):
            second = self.write("new-shared")
            self.s.tick()
            self.assertEqual((self.status().get("config_sha256"), self.status()["error"]), (second, ""))

    def test_failed_tick_still_reports_digests(self):
        # A failing tick (here: unreadable users.json) must not look like an
        # old image without digests, which the bot would accept as applied.
        with patch.object(self.s, "validate_config"), patch.object(self.s, "start", side_effect=self.started):
            first = self.write("old-shared")
            self.s.tick()
        self.users.write_text("{broken")
        self.write("new-shared")
        self.s.stopping = False
        calls = {"n": 0}

        def sleep(_):
            calls["n"] += 1
            self.s.stopping = True
        with patch.object(self.s, "serve_auth"), patch.object(hy.time, "sleep", side_effect=sleep), \
                patch.object(self.s, "auth_server", create=True):
            self.s.auth_server = type("S", (), {"shutdown": lambda self: None, "server_close": lambda self: None})()
            self.s.run()
        status = self.status()
        self.assertFalse(status["running"])
        self.assertEqual(status.get("config_sha256"), first)
        self.assertIn("checked_sha256", status)


if __name__ == "__main__":
    unittest.main()
