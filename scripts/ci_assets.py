#!/usr/bin/env python3
"""Проверяемая опись поставляемых JS/Windows файлов и SBOM для Trivy.

Go buildinfo извлекается из фактического EXE без исполнения. Native DLL
проверяется по hash/provenance, WinSW — также по product advisories отдельно;
это не заявка на полную опись встроенных C++/.NET зависимостей.
"""
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import quote
import zipfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def go_info(data):
    pos = data.find(b'\xff Go buildinf:')
    if pos < 0 or pos + 32 > len(data) or not data[pos + 15] & 2:
        raise ValueError('Go buildinfo missing or unsupported')

    def read_string(start):
        size = shift = 0
        for offset in range(10):
            if start + offset >= len(data):
                break
            byte = data[start + offset]
            size |= (byte & 127) << shift
            if byte < 128:
                begin = start + offset + 1
                if size > 1024 * 1024 or begin + size > len(data):
                    break
                return data[begin:begin + size], begin + size
            shift += 7
        raise ValueError('invalid Go buildinfo string')

    compiler, end = read_string(pos + 32)
    raw, _ = read_string(end)
    compiler = compiler.decode('ascii')
    if not re.fullmatch(r'go\d+\.\d+\.\d+', compiler):
        raise ValueError('unversioned Go compiler')
    # Go surrounds the module text with 16-byte framing hashes.
    if len(raw) < 33 or raw[-17] != 10:
        raise ValueError('invalid Go module framing')
    modules, main, settings = [], None, {}
    for line in raw[16:-16].decode('utf-8').splitlines():
        fields = line.split('\t')
        if fields[0] == 'build' and len(fields) == 2 and '=' in fields[1]:
            key, value = fields[1].split('=', 1)
            settings[key] = value
        if fields[0] in ('mod', 'dep', '=>'):
            if len(fields) < 3 or not fields[1] or not (fields[2].startswith('v')
                    or fields[0] == 'mod' and fields[2] == '(devel)'):
                raise ValueError('unversioned Go module')
            item = dict(name=fields[1], version=fields[2])
            if fields[0] == '=>':
                if not modules:
                    raise ValueError('orphan Go replacement')
                modules[-1] = item
            else:
                modules.append(item)
                if fields[0] == 'mod':
                    main = item
    if not main or len(modules) < 2:
        raise ValueError('Go dependency inventory missing')
    return dict(compiler=compiler[2:], main=main, modules=modules, settings=settings)


def application_version(root, release, info, binary):
    """Не выдаём source checkout (devel) за upstream release EXE."""
    if info['main']['name'] != 'github.com/sagernet/sing-box':
        raise ValueError('Windows application module mismatch')
    kind = release.get('build_kind', 'upstream_release')
    if kind == 'upstream_release':
        if info['main']['version'] != 'v' + release['version']:
            raise ValueError('Windows application version mismatch')
        return info['main']['version']
    if kind != 'source_security_rebuild' or info['main']['version'] != '(devel)':
        raise ValueError('unsupported Windows build provenance')
    proof = release.get('rebuild', {})
    source = proof.get('source_version', '')
    if not re.fullmatch(r'\d+\.\d+\.\d+', source) or not re.fullmatch(
            re.escape(source) + r'\+vpnbot\.security\.\d{8}', release['version']):
        raise ValueError('invalid security rebuild version')
    if proof.get('source_url') != 'https://codeload.github.com/SagerNet/sing-box/tar.gz/refs/tags/v' + source \
            or not re.fullmatch(r'[0-9a-f]{64}', proof.get('source_sha256', '')) \
            or not re.fullmatch(r'[0-9a-f]{40}', proof.get('source_commit', '')):
        raise ValueError('security rebuild source provenance missing')
    expected = {'go.mod', 'go.sum', 'Dockerfile', 'DEFAULT_BUILD_TAGS_WINDOWS', 'LDFLAGS'}
    inputs = proof.get('inputs', {})
    if set(inputs) != expected:
        raise ValueError('security rebuild inputs incomplete')
    directory = Path(root) / 'singbox_windows/security-rebuild'
    for name, checksum in inputs.items():
        if not re.fullmatch(r'[0-9a-f]{64}', checksum) or digest((directory/name).read_bytes()) != checksum:
            raise ValueError('security rebuild input digest mismatch')
    tags = (directory/'DEFAULT_BUILD_TAGS_WINDOWS').read_text().strip()
    if proof.get('go_version') != info['compiler'] or info['settings'].get('-tags') != tags \
            or not {'with_clash_api', 'with_naive_outbound', 'with_purego'} <= set(tags.split(',')) \
            or any(info['settings'].get(k) != v for k, v in
                   {'GOOS': 'windows', 'GOARCH': 'amd64', 'GOAMD64': 'v1', 'CGO_ENABLED': '0'}.items()):
        raise ValueError('security rebuild compiler/features mismatch')
    if release['version'].encode('ascii') not in binary:
        raise ValueError('security rebuild runtime version missing')
    # Версия приложения — проверенный исходный release; версия каждого
    # dependency/stdlib ниже остаётся фактически извлечённой из EXE.
    return 'v' + source


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
    bundle = root / 'singbox_windows/singbox.zip'
    release = json.loads((root / 'singbox_windows/components.json').read_text())
    if release.get('schema') != 1 or release.get('platform') != 'windows-amd64' \
            or digest(bundle.read_bytes()) != release['bundle_sha256']:
        raise ValueError('Windows bundle digest/schema mismatch')
    expected = release['sing_box']['files'] | release['preserved_files']
    with zipfile.ZipFile(bundle) as archive:
        entries = archive.infolist()
        if len(entries) != len(expected) or {e.filename for e in entries} != set(expected) \
                or any(e.file_size > 256 * 1024 * 1024 for e in entries):
            raise ValueError('Windows bundle members mismatch')
        files = {e.filename: archive.read(e) for e in entries}
    if any(digest(data) != expected[name] for name, data in files.items()):
        raise ValueError('Windows member digest mismatch')
    binary_names = {n for n in files if Path(n).suffix.lower() in ('.exe', '.dll')}
    if binary_names != {'sing-box.exe'} | set(manifest['windows_native']):
        raise ValueError('Windows executable inventory incomplete')
    info = go_info(files['sing-box.exe'])
    app_version = application_version(root, release['sing_box'], info, files['sing-box.exe'])
    versions['sing-box Windows'] = app_version
    packages += [('golang', p['name'], app_version if p is info['main'] else p['version']) for p in info['modules']]
    packages.append(('golang', 'stdlib', info['compiler']))
    for name, asset in manifest['windows_native'].items():
        if digest(files[name]) != asset['sha256']:
            raise ValueError('Windows native provenance mismatch')
        if name == 'libcronet.dll' and b'\0' + asset['version'].encode('ascii') + b'\0' not in files[name]:
            raise ValueError('Cronet version mismatch')
        if name == 'libcronet.dll':
            module = 'github.com/sagernet/cronet-go/lib/windows_amd64'
            prefix = 'https://proxy.golang.org/' + module + '/@v/'
            url = asset.get('module_archive_url', '')
            if not url.startswith(prefix) or not url.endswith('.zip') or not any(
                    p['name'] == module and p['version'] == url[len(prefix):-4] for p in info['modules']):
                raise ValueError('Cronet DLL/module provenance mismatch')
        versions[asset['name']] = asset['version']
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
        print('Asset inventory:', len(bom['components']), 'npm/Go packages; native C++/.NET transitive dependencies not fully scanned')
    except (OSError, ValueError, KeyError, zipfile.BadZipFile):
        print('Asset inventory failed', file=sys.stderr)
        raise SystemExit(2)
