"""A fresh node writes the full Docker daemon policy: no firewall rules, no
forwarding, no userland proxy (containers use the host network only)."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import node_setup as setup

EXPECTED = {'ip-forward': False, 'ip6tables': False, 'iptables': False, 'userland-proxy': False}


class NodeDockerDaemonTest(unittest.TestCase):
    def run_prepare(self, initial):
        with tempfile.TemporaryDirectory() as tmp:
            daemon = Path(tmp)/'docker'/'daemon.json'
            daemon.parent.mkdir()
            if initial is not None:
                daemon.write_text(initial)
            calls = []
            # Path ownership checks are covered elsewhere; the test runs unprivileged.
            with patch.object(setup.state, 'trusted', lambda path: None), \
                    patch.object(setup, 'command', side_effect=lambda args, **kw: calls.append(args)), \
                    patch.object(setup, 'docker_firewall_disabled',
                                 side_effect=lambda d=None, proc=None: self.check(daemon)):
                changed = setup.prepare_docker(daemon)
            return changed, json.loads(daemon.read_text()), calls

    @staticmethod
    def check(daemon):
        value = json.loads(daemon.read_text()) if daemon.exists() else {}
        if any(value.get(k) is not False for k in ('iptables', 'ip6tables', 'ip-forward')):
            raise ValueError('Docker firewall management is enabled')

    def test_fresh_server_gets_exactly_the_node_policy(self):
        changed, value, calls = self.run_prepare(None)
        self.assertTrue(changed)
        self.assertEqual(value, EXPECTED)
        self.assertEqual(calls, [['systemctl', 'restart', 'docker.service']])

    def test_userland_proxy_is_added_even_when_firewall_is_already_off(self):
        changed, value, calls = self.run_prepare('{"iptables": false, "ip6tables": false, "ip-forward": false, "log-driver": "local"}')
        self.assertTrue(changed)
        self.assertEqual(value, EXPECTED | {'log-driver': 'local'})
        self.assertEqual(len(calls), 1)

    def test_complete_policy_is_left_alone(self):
        changed, value, calls = self.run_prepare(json.dumps(EXPECTED))
        self.assertFalse(changed)
        self.assertEqual(value, EXPECTED)
        self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
