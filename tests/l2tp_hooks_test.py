import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


class L2tpHooksTest(unittest.TestCase):
    def test_session_identity_survives_hook_reparenting(self):
        source = (Path(__file__).resolve().parents[1] / "scripts/start_ipsec.sh").read_text()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            hooks = {}
            for name in ("ip-up", "ip-down"):
                body = re.search(r"cat > /etc/ppp/" + name + r" <<'HOOKEOF'\n(.*?)\nHOOKEOF", source, re.S)[1]
                hooks[name] = root / name
                hooks[name].write_text(body.replace("/logs/ipsec-connections.log", str(root / "events.log"))
                                      .replace("/var/run/l2tp-sessions", str(root / "sessions")))

            def invoke(name, pid):
                env = dict(os.environ, PPPD_PID=str(pid), PEERNAME="alice", IPREMOTE="10.9.1.2")
                subprocess.run(["sh", str(hooks[name]), "ppp0"], env=env, check=True)

            invoke("ip-up", 12345)
            invoke("ip-up", 23456)
            first, second = root / "sessions/alice.12345", root / "sessions/alice.23456"
            self.assertTrue(first.exists() and second.exists(), "Each pppd owns a separate session")
            self.assertEqual(first.read_text().split(), ["10.9.1.2", "12345", "alice"])
            self.assertEqual(first.stat().st_mode & 0o777, 0o600)
            legacy = root / "sessions/alice"
            legacy.write_text("10.9.1.3 23456\n")
            invoke("ip-down", 12345)
            self.assertFalse(first.exists())
            self.assertTrue(second.exists() and legacy.exists())
            invoke("ip-down", 23456)
            self.assertFalse(second.exists() or legacy.exists())


if __name__ == "__main__":
    unittest.main()
