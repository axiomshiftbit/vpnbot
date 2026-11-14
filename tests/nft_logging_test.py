#!/usr/bin/env python3
"""Журналирование nftables соответствует профилям nftables/: каждый префикс — в свой журнал."""
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOGGING = ROOT / 'nftables/logging'
EXTRACT = re.compile(r'(^| )((INPUT6?|FORWARD6?|OUTPUT6?|FWD|DOCKER|RELAY|PREROUTE|BR)-[A-Z0-9-]+:|IPTABLES-RK:) ')


def groups():
    text = (LOGGING / 'install-nft-logging.sh').read_text()
    result = [tuple(r.split(' ', 1)) for r in re.findall(r"printf '%s\\n' '((?:rkn-blacklist|security)\.log [^']+)'", text)]
    for block in re.findall(r"cat <<'GROUPS' ?\n(.*?)\nGROUPS", text, re.S):
        result += [tuple(line.split(' ', 1)) for line in block.splitlines()]
    return result


def prefixes():
    sources = [ROOT / 'nftables/nftables.conf', ROOT / 'nftables/noda.conf']
    listed = subprocess.run(['git', '-C', str(ROOT), 'grep', '-l', 'log prefix', '--', 'scripts'],
                            capture_output=True, text=True).stdout.split()
    sources += [ROOT / f for f in listed]
    found = {}
    for path in sources:
        for value in re.findall(r'log prefix \\?"([^"\\]+?)\\?"', path.read_text()):
            found.setdefault(value, path.name)
    return found


class LoggingProfile(unittest.TestCase):
    def test_every_prefix_lands_in_a_named_log(self):
        rules = groups()
        self.assertGreaterEqual(len(rules), 6)
        found = prefixes()
        self.assertGreater(len(found), 50)
        for value, source in found.items():
            with self.subTest(prefix=value, source=source):
                m = EXTRACT.search(' ' + value if value.endswith(' ') else ' ' + value + ' ')
                self.assertIsNotNone(m, 'rsyslog не выделит этот префикс')
                target = next((name for name, pattern in rules if re.match(pattern, m.group(2))), 'other.log')
                self.assertNotEqual('other.log', target, 'префикс попадёт в other.log')

    def test_single_neutral_profile_and_wrappers(self):
        text = (LOGGING / 'install-nft-logging.sh').read_text()
        self.assertIn("[[ $nft_profile == main ]] || die", text)
        for name in ('nftables.sh', 'noda.sh'):
            self.assertIn('--profile main', (LOGGING / name).read_text())
        for path in LOGGING.iterdir():
            if path.is_file():
                self.assertNotRegex(path.read_text(), r'(?i)nuxt|\bpl\b|video-bot|telbot|generic')


if __name__ == '__main__':
    unittest.main()
