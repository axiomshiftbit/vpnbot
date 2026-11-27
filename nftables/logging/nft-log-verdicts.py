#!/usr/bin/python3
"""Определяет действие логируемых правил по JSON действующего nftables."""
import collections
import json
import re
import subprocess
import sys

PREFIX = re.compile(r"(?:(?:INPUT6?|FORWARD6?|OUTPUT6?|FWD|DOCKER|RELAY|PREROUTE|BR)-[A-Z0-9-]+|IPTABLES-RK): ")
# Правила проекта, которые загружаются уже после настройки журналов: защита
# происхождения контейнерного трафика (scripts/container_origin_guard.py, цепочка
# denied: log, затем drop) появляется позже установки rsyslog. Действие
# берётся из живых правил, если они есть, иначе — отсюда.
LATER = {"BR-ORIGIN-DROP:": "DROP"}


def terminal(expressions, matched):
    """Принимаем только доказанный verdict, без переходов и новых условий."""
    for expression in expressions:
        if len(expression) != 1:
            return "UNKNOWN"
        kind = next(iter(expression))
        if kind in ("accept", "drop", "reject"):
            return kind.upper()
        if kind == "counter":
            continue
        if kind == "match" and expression in matched:
            # Эти выражения могут дать другой результат при повторной проверке.
            if any(word in json.dumps(expression) for word in ('"numgen"', '"quota"', '"limit"')):
                return "UNKNOWN"
            continue
        return "UNKNOWN"
    return None


def verdicts(document):
    chains = collections.defaultdict(list)
    for item in document["nftables"]:
        if "rule" in item:
            rule = item["rule"]
            chains[tuple(rule[key] for key in ("family", "table", "chain"))].append(rule["expr"])
    found = collections.defaultdict(set)
    for rules in chains.values():
        for index, expressions in enumerate(rules):
            for pos, expression in enumerate(expressions):
                prefix = expression.get("log", {}).get("prefix")
                if not isinstance(prefix, str) or not PREFIX.fullmatch(prefix):
                    continue
                before = expressions[:pos]
                unchanged = all(len(item) == 1 and next(iter(item)) in
                                ("match", "limit", "counter", "log") for item in before)
                matched = [item for item in before if "match" in item] if unchanged else []
                action = terminal(expressions[pos + 1:], matched)
                if action is None and unchanged:
                    if index + 1 < len(rules):
                        action = terminal(rules[index + 1], matched)
                found[prefix.rstrip()].add(action or "UNKNOWN")
    # Один префикс может использоваться в нескольких таблицах/семействах.
    return {prefix: next(iter(actions)) if len(actions) == 1 else "UNKNOWN"
            for prefix, actions in sorted(found.items())}


def with_later(actions):
    """Карта для rsyslog: правила проекта, загружаемые позже, получают своё действие."""
    return {prefix: action for prefix, action in LATER.items() if prefix not in actions} | actions


def main():
    try:
        # --terse исключает содержимое IP-наборов; firewall только читается.
        result = subprocess.run(["nft", "-j", "-s", "-t", "list", "ruleset"],
                                check=True, capture_output=True, text=True, timeout=30)
        actions = with_later(verdicts(json.loads(result.stdout)))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print("Не удалось прочитать действия nftables: " + type(error).__name__, file=sys.stderr)
        return 1
    print('set $.nft_action = "UNKNOWN";')
    for action in ("ACCEPT", "DROP", "REJECT"):
        prefixes = [prefix[:-1] for prefix, value in actions.items() if value == action]
        if prefixes:
            # PREFIX допускает только безопасные для RainerScript символы.
            print("if re_match($.nft_prefix, '^(" + "|".join(prefixes) + "):$') then {")
            print('set $.nft_action = "' + action + '";\n}')
    counts = collections.Counter(actions.values())
    print("Действия nftables: " + ", ".join(f"{key}={counts[key]}" for key in sorted(counts)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
