"""Apply the configured per-exit delay to Xray's native health observations."""
import json
from pathlib import Path
import re
import subprocess
import time
from typing import NamedTuple


POLICY = re.compile(r'vpnbot-exit-timed-([a-f0-9]{8})-(main|[a-f0-9]{8})-(30|60|120|300)-(direct|block|vpnbot-exit-[a-z0-9-]+)')
CONFIG = Path('/xray.json')
POLL = 3


class Policy(NamedTuple):
    tag: str
    primary: str
    delay: int
    standby: str


def policies(path):
    # Keep only routing tags in the worker. Credentials never reach its output.
    query = ('.routing.balancers[]? | select((.tag // "") | startswith("vpnbot-exit-timed-")) | '
             'select((.selector | length) == 1 and .selector[0] == .fallbackTag) | [.tag, .fallbackTag] | @tsv')
    result = subprocess.run(['jq', '-r', query, str(path)],
                            check=True, capture_output=True, timeout=3)
    active = []
    for line in result.stdout.decode().splitlines():
        tag, _, primary = line.partition('\t')
        match = POLICY.fullmatch(tag)
        if match:
            node, backup, delay, target = match.groups()
            prefix = 'vpnbot-exit-'
            if primary != prefix + node and not re.fullmatch(r'vpnbot-exit-group-member-[0-7]', primary):
                continue
            if target in {'block', 'direct' if backup == 'main' else prefix + backup,
                          prefix + 'fallback-' + node, prefix + 'resolve-fallback-' + node}:
                active.append(Policy(tag, primary, int(delay), target))
    return active


def api(arguments):
    result = subprocess.run(['xray', 'api', *arguments], capture_output=True, check=True, timeout=4)
    return result.stdout


def check(policy, since, now, call=api):
    tag, primary, delay, standby = policy
    state = json.loads(call(['bi', '-json', '-s', '127.0.0.1:8080', tag]))['balancer']
    selected = state['principleTarget']['tag']
    override = state['override'].get('target', '')
    if selected == [primary]:
        if override:
            call(['bo', '-s', '127.0.0.1:8080', '-b', tag, '-r'])
        return None
    if selected != ['']:
        raise ValueError('unknown observation')
    if since is None:
        since = now
    if now - since >= delay and override != standby:
        call(['bo', '-s', '127.0.0.1:8080', '-b', tag, standby])
    return since


def main(path=CONFIG, call=api):
    stamp = None
    active = []
    failures = {}
    while True:
        try:
            st = path.stat()
            current = (st.st_ino, st.st_mtime_ns, st.st_size)
            if stamp != current:
                active = policies(path)
                failures = {p: failures.get(p) for p in active}
                stamp = current
            for policy in active:
                try:
                    failures[policy] = check(policy, failures.get(policy), time.monotonic(), call)
                except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, AttributeError):
                    # Losing the control API does not establish a node outage.
                    failures[policy] = None
        except (OSError, subprocess.SubprocessError, ValueError):
            failures.clear()
            stamp = None
        time.sleep(POLL)


if __name__ == '__main__':
    main()
