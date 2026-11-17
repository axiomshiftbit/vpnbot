#!/usr/bin/env python3
"""A fresh node install on a clean server: init.sh installs Docker, whose
first start (still with iptables=true) creates iptables-nft DOCKER chains;
restarting dockerd with iptables=false keeps them, and the final firewall
check rolled the whole installation back. The installer now loads the
persistent profile (flush ruleset + profile + node guard) like the next boot."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import node_setup as setup

DOCKER = {'nftables': [{'table': {'family': 'ip', 'name': 'filter'}},
                       {'chain': {'family': 'ip', 'table': 'filter', 'name': 'DOCKER-USER'}},
                       {'chain': {'family': 'ip', 'table': 'filter', 'name': 'FORWARD'}}]}
CLEAN = {'nftables': [{'table': {'family': 'ip', 'name': 'filter'}},
                      {'chain': {'family': 'ip', 'table': 'filter', 'name': 'input'}},
                      {'chain': {'family': 'ip', 'table': 'filter', 'name': 'dockernat'}}]}


class StaleDockerRules(unittest.TestCase):
    def run_drop(self, live):
        calls = []
        def command(args, **kw):
            calls.append([str(a) for a in args])
            return subprocess.CompletedProcess(args, 0, json.dumps(live).encode() if args[:3] == ['nft', '-j', 'list'] else b'', b'')
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp)/'nftables.conf'
            profile.write_text('flush ruleset\n')
            with patch.object(setup, 'command', side_effect=command), \
                    patch.object(setup, 'docker_firewall_disabled') as disabled, \
                    patch.object(setup, 'LOCK_NFT', Path(tmp)/'nft.lock', create=True):
                changed = setup.drop_stale_docker_rules(profile)
            return changed, calls, disabled.called, str(profile)

    def test_stale_docker_chains_are_dropped_by_loading_the_profile(self):
        changed, calls, disabled, profile = self.run_drop(DOCKER)
        self.assertTrue(changed and disabled)
        self.assertEqual(calls[1:], [['nft', '-c', '-f', profile], ['nft', '-f', profile]])

    def test_clean_ruleset_is_not_reloaded(self):
        changed, calls, disabled, _ = self.run_drop(CLEAN)
        self.assertFalse(changed)
        self.assertEqual(calls, [['nft', '-j', 'list', 'ruleset']])

    def test_installer_drops_stale_rules_before_the_final_check(self):
        source = (Path(__file__).resolve().parents[1]/'scripts/node_setup.py').read_text()
        body = source[source.index('def setup('):source.index('def prompt(')]
        self.assertLess(body.index('drop_stale_docker_rules()'), body.index('verify_firewall(backend)'))


if __name__ == '__main__':
    unittest.main()
