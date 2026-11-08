import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import node_setup as setup


class FirewallHealth(unittest.TestCase):
    def test_service_and_live_policy_failures_are_not_success(self):
        base = {'nftables': [
            {'table': {'family': 'ip', 'name': 'filter'}},
            {'chain': {'family': 'ip', 'table': 'filter', 'name': 'input', 'type': 'filter', 'hook': 'input', 'prio': 0, 'policy': 'drop'}},
            {'rule': {'family': 'ip', 'table': 'filter', 'chain': 'input', 'expr': [{'drop': None}]}}
        ]}
        guard = {'nftables': [
            {'table': {'family': 'inet', 'name': 'vpnbot_node'}},
            {'chain': {'family': 'inet', 'table': 'vpnbot_node', 'name': 'input', 'type': 'filter', 'hook': 'input', 'prio': -20, 'policy': 'drop'}}
        ]}
        healthy = dict(LoadState='loaded', ActiveState='active', SubState='exited', Result='success', UnitFileState='enabled')
        cases = [(None, None)] + [(field, value) for field, value in [
            ('LoadState', 'not-found'), ('ActiveState', 'inactive'), ('ActiveState', 'failed'),
            ('SubState', 'dead'), ('Result', 'exit-code'), ('UnitFileState', 'disabled')]]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base_path, guard_path = root/'base', root/'guard'
            base_path.write_text('table ip filter { }')
            guard_path.write_text('guard fixture')
            for field, value in cases:
                status = healthy | ({field: value} if field else {})
                live = dict(nftables=base['nftables']+guard['nftables'])
                def command(args, **kwargs):
                    body = '\n'.join(k+'='+v for k, v in status.items()) if args[0] == 'systemctl' else json.dumps(live)
                    return SimpleNamespace(stdout=body.encode(), returncode=0)
                with self.subTest(field=field, value=value), patch.object(setup, 'command', side_effect=command), \
                        patch.object(setup.os, 'open', return_value=100), patch.object(setup.os, 'close'), \
                        patch.object(setup.fcntl, 'flock'), patch.object(setup.state, 'trusted'), \
                        patch.object(setup.node_host, 'read_profile', return_value=base_path.read_text()), \
                        patch.object(setup.nft_host_setup, 'compile_rules', side_effect=lambda text: guard if text == 'guard fixture' else base):
                    backend = SimpleNamespace(guard=guard_path)
                    if field:
                        with self.assertRaisesRegex(ValueError, 'service is not active'):
                            setup.verify_firewall(backend, base_path)
                    else:
                        setup.verify_firewall(backend, base_path)
                        for mutation in ('missing_guard', 'accept_policy', 'extra_accept'):
                            live = copy.deepcopy(dict(nftables=base['nftables']+guard['nftables']))
                            if mutation == 'missing_guard': live['nftables'] = live['nftables'][:3]
                            elif mutation == 'accept_policy': live['nftables'][1]['chain']['policy'] = 'accept'
                            else: live['nftables'].append({'rule': {'family':'ip','table':'filter','chain':'input','expr':[{'accept':None}]}})
                            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'live rules differ'):
                                setup.verify_firewall(backend, base_path)


if __name__ == '__main__':
    unittest.main()
