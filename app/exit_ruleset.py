#!/usr/bin/env python3
"""Ограниченный процесс для распаковки и нормализации внешних .srs/.mrs.

Большой или повреждённый набор должен дать отказ, сохранив прежний кэш,
а не исчерпать память воркера PHP или диск контейнера.
"""
import ipaddress
import json
import mmap
import os
from pathlib import Path
import resource
import sys

UNPACKED_BYTES = 32 * 1024 * 1024
NORMALIZED_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 200000


class UnsupportedRule(ValueError):
    pass


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
            # Плоский список маршрутов не выражает отрицание, логические
            # группы и ограничения по порту/сети. Частичный импорт меняет
            # смысл набора, поэтому отказываем целиком, сохраняя старый кэш.
            if (not isinstance(rule, dict)
                    or rule.get('type', 'default') != 'default'
                    or rule.get('invert', False) is not False
                    or set(rule) - (set(combined) | {'type', 'invert'})):
                raise UnsupportedRule('unsupported rule semantics')
            before_count = count
            for key, values in combined.items():
                entries = rule.get(key, [])
                # sing-box Listable serializes a single value as a string.
                if isinstance(entries, str):
                    entries = [entries]
                if not isinstance(entries, list):
                    raise ValueError('invalid rule field')
                count += len(entries)
                if count > MAX_ENTRIES or any(not isinstance(v, str) for v in entries):
                    raise ValueError('invalid rule entries')
                values.extend(entries)
            if count == before_count:
                raise UnsupportedRule('empty rule cannot be represented')
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


def protobuf_fields(data):
    def integer(offset):
        value = 0
        for shift in range(0, 70, 7):
            if offset >= len(data):
                break
            byte = data[offset]
            offset += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value, offset
        raise ValueError('invalid protobuf integer')

    offset = 0
    while offset < len(data):
        key, offset = integer(offset)
        field, wire = divmod(key, 8)
        if field == 0:
            raise ValueError('invalid protobuf field')
        if wire == 0:
            value, offset = integer(offset)
        elif wire == 2:
            size, offset = integer(offset)
            if offset + size > len(data):
                raise ValueError('truncated protobuf field')
            value = data[offset:offset + size]
            offset += size
        else:
            raise UnsupportedRule('unsupported protobuf field')
        yield field, value


def extract_dat(source, destination, kind, category):
    """Expand a single configured GeoSite/GeoIP category for the node."""
    if kind not in ('domain', 'ip') or not category or '@' in category or '!' in category:
        raise UnsupportedRule('unsupported category selector')
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
    entries = []
    with open(source, 'rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        data = memoryview(mapped)
        try:
            for field, group in protobuf_fields(data):
                if field != 1 or not isinstance(group, memoryview):
                    raise ValueError('invalid category')
                tag = next((bytes(v).decode() for f, v in protobuf_fields(group) if f == 1), '')
                if tag.lower() != category.lower():
                    continue
                for f, item in protobuf_fields(group):
                    if f == 1:
                        continue
                    if f != 2:
                        raise UnsupportedRule('unsupported category condition')
                    values = dict(protobuf_fields(item))
                    if kind == 'domain':
                        dtype = values.get(1, 0)
                        if dtype not in range(4) or not isinstance(values.get(2), memoryview):
                            raise ValueError('invalid geosite entry')
                        entry = ('keyword:', 'regexp:', 'domain:', 'full:')[dtype] + bytes(values[2]).decode()
                    else:
                        if not isinstance(values.get(1), memoryview):
                            raise ValueError('invalid geoip entry')
                        address = ipaddress.ip_address(bytes(values[1]))
                        entry = str(ipaddress.ip_network((address, values.get(2, 0)), strict=False))
                    entries.append(entry)
                    if len(entries) > MAX_ENTRIES:
                        raise ValueError('oversized category')
                break
        finally:
            # Drop exported slices before closing the memory map.
            group = item = values = None
            data.release()
    if not entries:
        raise ValueError('category is missing or empty')
    body = json.dumps(entries, ensure_ascii=False).encode()
    if len(body) > NORMALIZED_BYTES:
        raise ValueError('oversized category')
    Path(destination).write_bytes(body)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (UNPACKED_BYTES,) * 2)
    if sys.argv[1] == 'tool':
        # RLIMIT_DATA ограничивает выделяемую память, сохраняя виртуальный
        # резерв адресов, необходимый среде Go при запуске.
        resource.setrlimit(resource.RLIMIT_DATA, (256 * 1024 * 1024,) * 2)
        os.execvp(sys.argv[2], sys.argv[2:])
    if sys.argv[1] == 'dat':
        extract_dat(*sys.argv[2:])
    else:
        normalize(*sys.argv[2:])


if __name__ == '__main__':
    try:
        main()
    except UnsupportedRule:
        # Отличаем доказанную потерю семантики от временного отказа инструмента.
        sys.exit(2)
    except (OSError, ValueError, TypeError, MemoryError, RecursionError, IndexError):
        # Внешний файл не выводится ни в stderr, ни в журналы бота.
        sys.exit(1)
