import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('node_sets', Path(__file__).resolve().parents[1]/'scripts/nft_node_sets.py')
sets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sets)


class NodeSetsTest(unittest.TestCase):
    def test_minimal_host_node_does_not_get_unused_container_snat(self):
        text = '# VPNBOT_MANAGED_NODE_HOST\ntable ip6 filter {}\n'
        prepared = sets.prepare(text)
        self.assertNotIn('egress6_snat', prepared)
        self.assertEqual(sets.prepare(prepared), prepared)
        self.assertEqual(set(sets.declarations(prepared)), {'node6_sources', 'node6_public', 'ipv6_routers'})

    def test_fresh_install_creates_only_empty_sets(self):
        text = sets.prepare('#!/usr/sbin/nft -f\n')
        for name in sets.DECLARATIONS:
            self.assertIn(name+' {', text)
        self.assertNotIn('elements', text)
        self.assertNotIn('chain ', text)
        self.assertNotIn('flush ', text)
        self.assertEqual(sets.prepare(text), text)

    def test_populated_and_empty_sets_preserved_byte_for_byte(self):
        text = 'table ip6 filter {\n'+ '\n'.join(sets.DECLARATIONS.values()) + '\n}\n'
        text = text.replace('set node6_public { type ipv6_addr; }', 'set node6_public { type ipv6_addr; elements = { 2606:4700:4700::1111 }; }')
        self.assertEqual(text, sets.prepare(text))

    def test_missing_set_inserted_before_rule_references(self):
        text = 'table ip6 filter {\n # { braces in a comment }\n chain input { type filter hook input priority 0; policy drop; ip6 saddr @node6_sources accept; log prefix "{hello}"; }\n}\n'
        result = sets.prepare(text)
        self.assertLess(result.index('set node6_sources'), result.index('@node6_sources'))
        self.assertIn('policy drop;', result)
        self.assertIn('log prefix "{hello}";', result)

    def test_same_name_in_another_table_does_not_hide_missing_set(self):
        text = 'table inet unrelated { set node6_sources { type ipv6_addr; } }\ntable ip6 filter {}\n'
        self.assertEqual(sets.prepare(text).count('set node6_sources'), 2)

    def test_malformed_table_rejected(self):
        with self.assertRaises(ValueError):
            sets.prepare('table ip6 filter {\n')


if __name__ == '__main__': unittest.main()
