import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / 'nftables/logging/nft-log-verdicts.py'
SPEC = importlib.util.spec_from_file_location('nft_log_verdicts', PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def document(*rules):
    return {'nftables': [{'rule': {'family': 'inet', 'table': 'filter', 'chain': 'input', 'expr': rule}} for rule in rules]}


LOG = {'log': {'prefix': 'INPUT-DROP: '}}
MATCH = {'match': {'op': '==', 'left': {'payload': {'protocol': 'tcp', 'field': 'dport'}}, 'right': 443}}


class VerdictEvidence(unittest.TestCase):
    def test_terminal_verdict_does_not_follow_prefix_name(self):
        for verdict in ('accept', 'drop', 'reject'):
            with self.subTest(verdict=verdict):
                self.assertEqual(MODULE.verdicts(document([LOG, {'counter': None}, {verdict: None}])), {'INPUT-DROP:': verdict.upper()})

    def test_next_rule_requires_same_conditions(self):
        self.assertEqual(MODULE.verdicts(document([MATCH, LOG], [MATCH, {'drop': None}])), {'INPUT-DROP:': 'DROP'})
        other = {'match': {'op': '==', 'left': {'meta': {'key': 'l4proto'}}, 'right': 'udp'}}
        self.assertEqual(MODULE.verdicts(document([MATCH, LOG], [other, {'drop': None}])), {'INPUT-DROP:': 'UNKNOWN'})

    def test_unknown_paths_are_not_reported_as_blocked(self):
        for tail in ([{'jump': {'target': 'other'}}], [{'return': None}],
                     [{'limit': {'rate': 1}}, {'drop': None}], []):
            with self.subTest(tail=tail):
                self.assertEqual(MODULE.verdicts(document([LOG] + tail)), {'INPUT-DROP:': 'UNKNOWN'})

    def test_reused_prefix_conflict_stays_unknown(self):
        self.assertEqual(MODULE.verdicts(document([LOG, {'accept': None}], [LOG, {'drop': None}])), {'INPUT-DROP:': 'UNKNOWN'})

    def test_untrusted_prefix_text_is_not_emitted_as_configuration(self):
        for prefix in ('INPUT-DROP: \n', "INPUT-X'); stop; # ", 'INPUT-X: embedded', 'unrelated: '):
            with self.subTest(prefix=prefix):
                self.assertEqual(MODULE.verdicts(document([{'log': {'prefix': prefix}}, {'drop': None}])), {})


if __name__ == '__main__':
    unittest.main()
