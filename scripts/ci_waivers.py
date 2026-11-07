#!/usr/bin/env python3
"""Временные исключения для известных уязвимостей (scripts/ci_vuln_waivers.json).

Исключение действует, только когда запуск явно разрешил их (CI_ALLOW_WAIVERS=1,
флажок allow_waivers ручного запуска images) и запись совпадает точно:
идентификатор уязвимости, компонент и закреплённая версия (проверка версий) или
пакет и установленная версия (Trivy). Любая другая находка, другая версия или
истёкший срок по-прежнему блокируют допуск. Каждая запись обязана иметь срок
не дальше MAX_DAYS и причину; ошибка в файле — отказ проверки.
"""
import datetime
import json
import os
from pathlib import Path
import re

PATH = Path(__file__).resolve().with_name('ci_vuln_waivers.json')
MAX_DAYS = 120
FIELDS = {'id', 'component', 'version', 'package', 'installed', 'expires', 'reason'}


def enabled():
    return os.environ.get('CI_ALLOW_WAIVERS') == '1'


def load(path=PATH, today=None):
    """All valid entries; expired ones are returned with active=False."""
    today = today or datetime.date.today()
    if not Path(path).exists():
        return []
    entries = json.loads(Path(path).read_text())
    if not isinstance(entries, list):
        raise ValueError('waivers must be a list')
    result = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != FIELDS or not all(isinstance(entry[k], str) and entry[k].strip() for k in FIELDS):
            raise ValueError('waiver needs exactly: ' + ', '.join(sorted(FIELDS)))
        if not re.fullmatch(r'(GHSA(-[23456789cfghjmpqrvwx]{4}){3}|CVE-\d{4}-\d{4,})', entry['id']):
            raise ValueError('waiver id must be one GHSA or CVE identifier')
        expires = datetime.date.fromisoformat(entry['expires'])
        if expires > today + datetime.timedelta(days=MAX_DAYS):
            raise ValueError(f"waiver {entry['id']} expires later than {MAX_DAYS} days ahead")
        result.append(dict(entry, active=expires >= today))
    return result


def component_waiver(entries, ident, component, version):
    return next((e for e in entries if e['id'] == ident and e['component'] == component and e['version'] == version), None)


def package_waiver(entries, ident, package, installed):
    return next((e for e in entries if e['id'] == ident and e['package'] == package and e['installed'] == installed), None)


def split(findings, match):
    """Partition blocking findings into (blocked, waived, hints) for this run."""
    entries = load()
    blocked, waived, hints = [], [], []
    for finding in findings:
        entry = match(entries, finding)
        if entry and entry['active'] and enabled():
            waived.append((finding, entry))
        else:
            blocked.append(finding)
            if entry and entry['active']:
                hints.append((finding, entry))
    return blocked, waived, hints


def describe(entry):
    return f"до {entry['expires']}: {entry['reason']}"


def annotate(kind, text):
    """GitHub Actions annotation; plain text elsewhere."""
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        print(f'::{kind}::' + text.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A'))
