#!/usr/bin/env python3
"""Опись поставляемых браузерных библиотек и проверка их SBOM в Trivy."""
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import quote


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inventory(root):
    root = Path(root)
    manifest = json.loads((root / 'scripts/ci_asset_inventory.json').read_text())
    if manifest.get('schema') != 1:
        raise ValueError('unknown asset inventory schema')
    packages, versions = [], {}
    for asset in manifest['browser']:
        if digest((root / asset['path']).read_bytes()) != asset['sha256']:
            raise ValueError('browser asset digest mismatch')
        versions[asset['name']] = asset['version']
        packages += [('npm', p['name'], p['version']) for p in [asset] + asset['dependencies']]
    # Новая сторонняя JS библиотека требует явного включения в inventory.
    actual_js = {str(p.relative_to(root)) for p in (root / 'app/webapp').glob('*.js')}
    if actual_js != {a['path'] for a in manifest['browser']}:
        raise ValueError('browser asset inventory incomplete')
    components = []
    for kind, name, version in sorted(set(packages)):
        if not name or not version:
            raise ValueError('empty package identity')
        purl = 'pkg:' + kind + '/' + quote(name, safe='/') + '@' + quote(version, safe='')
        components.append(dict(type='library', name=name, version=version, purl=purl, **{'bom-ref': purl}))
    bom = dict(bomFormat='CycloneDX', specVersion='1.5', version=1, components=components)
    return versions, bom


def verify_scan(report, bom):
    if report.get('ArtifactType') != 'cyclonedx' or not bom.get('components'):
        raise ValueError('asset scan missing')
    # Trivy канонизирует регистр GitHub namespace в PURL, но сохраняет
    # точные Name/Version. Сравниваем их вместе с типом анализатора.
    expected = {(c['purl'].split('/', 1)[0].removeprefix('pkg:'), c['name'], c['version'])
                for c in bom['components']}
    ecosystems = {'gobinary': 'golang', 'node-pkg': 'npm'}
    actual = {(ecosystems.get(r.get('Type')), p.get('Name'), p.get('Version'))
              for r in report.get('Results', []) if r.get('Class') == 'lang-pkgs'
              for p in r.get('Packages', [])}
    if not expected <= actual:
        raise ValueError('asset package scan incomplete')
    return len(expected)


if __name__ == '__main__':
    try:
        versions, bom = inventory(Path(sys.argv[1]))
        Path(sys.argv[2]).write_text(json.dumps(bom, sort_keys=True) + '\n')
        print('Asset inventory:', len(bom['components']), 'npm packages')
    except (OSError, ValueError, KeyError):
        print('Asset inventory failed', file=sys.stderr)
        raise SystemExit(2)
