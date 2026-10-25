#!/usr/bin/env python3
"""Ограниченный процесс для распаковки и нормализации внешних .srs/.mrs.

Большой или повреждённый набор должен дать отказ, сохранив прежний кэш,
а не исчерпать память воркера PHP или диск контейнера.
"""
import json
import os
from pathlib import Path
import resource
import sys

UNPACKED_BYTES = 32 * 1024 * 1024
NORMALIZED_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 200000


def normalize(source, destination, fmt):
    resource.setrlimit(resource.RLIMIT_AS, (192 * 1024 * 1024,) * 2)
    if Path(source).stat().st_size > UNPACKED_BYTES:
        raise ValueError('oversized ruleset')
    if fmt == 'srs':
        with open(source, encoding='utf-8') as stream:
            data = json.load(stream)
        if not isinstance(data, dict) or not isinstance(data.get('rules'), list):
            raise ValueError('invalid ruleset')
        combined = {key: [] for key in ('domain', 'domain_suffix', 'domain_keyword', 'domain_regex', 'ip_cidr')}
        count = 0
        for rule in data['rules']:
            if not isinstance(rule, dict) or 'type' in rule:
                continue
            for key, values in combined.items():
                entries = rule.get(key, [])
                if not isinstance(entries, list):
                    raise ValueError('invalid rule field')
                count += len(entries)
                if count > MAX_ENTRIES or any(not isinstance(v, str) for v in entries):
                    raise ValueError('invalid rule entries')
                values.extend(entries)
        body = json.dumps({'rules': [combined]}, ensure_ascii=False, separators=(',', ':')).encode()
    elif fmt == 'mrs':
        lines = []
        length = 0
        with open(source, encoding='utf-8') as stream:
            for line in stream:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                length += len(line.encode()) + 1
                if len(lines) >= MAX_ENTRIES or length > NORMALIZED_BYTES:
                    raise ValueError('oversized ruleset')
                lines.append(line)
        body = ('\n'.join(lines) + '\n').encode()
    else:
        raise ValueError('unknown format')
    if len(body) > NORMALIZED_BYTES:
        raise ValueError('oversized ruleset')
    Path(destination).write_bytes(body)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (UNPACKED_BYTES,) * 2)
    if sys.argv[1] == 'tool':
        # RLIMIT_DATA ограничивает выделяемую память, сохраняя виртуальный
        # резерв адресов, необходимый среде Go при запуске.
        resource.setrlimit(resource.RLIMIT_DATA, (256 * 1024 * 1024,) * 2)
        os.execvp(sys.argv[2], sys.argv[2:])
    normalize(*sys.argv[2:])


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, TypeError, MemoryError, RecursionError, IndexError):
        # Внешний файл не выводится ни в stderr, ни в журналы бота.
        sys.exit(1)
