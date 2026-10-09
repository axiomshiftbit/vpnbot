#!/usr/bin/env python3
"""Publish an admitted set without rebuilding any runtime image."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from ci_retry import retrying
from image_bundle import BUNDLE_REPO, REGISTRY, admit, command, fingerprint, read, source_reference


def network(*args):
    return retrying(command, *args)


def main():
    manifest, evidence = map(Path, sys.argv[1:])
    bundle = read(manifest)
    admit(bundle, json.loads(evidence.read_text()), json.loads(os.environ['CHECKS']))
    if fingerprint(bundle) != os.environ['EXPECTED_BUNDLE'] or bundle['source'] != os.environ['GITHUB_SHA']:
        raise ValueError('wrong candidate')
    branch = os.environ['GITHUB_REF_NAME']
    channel = ('latest' if branch == 'master' else 'dev') if branch in ('master', 'dev') else None
    if os.environ['GITHUB_EVENT_NAME'] == 'schedule':
        channel = 'nightly'
    if channel:
        remote = network('gh', 'api', 'repos/' + os.environ['GITHUB_REPOSITORY'] + '/commits/' + branch, '--jq', '.sha')
        if remote != bundle['source']:
            raise ValueError('newer code exists; stale run cannot publish')
    release = 'release-' + str(bundle['run']) + '-' + str(bundle['attempt'])
    # Retention tags protect every referenced image, including the preceding
    # working release. They are never reused by another run or a rerun.
    for name, ref in bundle['images'].items():
        network('docker', 'buildx', 'imagetools', 'create', '--prefer-index=false',
                '--tag', REGISTRY + name + ':' + release, ref)
    # This is only a tiny transport envelope, not a runtime image rebuild.
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'bundle.json').write_bytes(manifest.read_bytes())
        (root / 'Dockerfile').write_text('FROM scratch\nCOPY bundle.json /bundle.json\nCMD ["/bundle.json"]\n')
        ref = BUNDLE_REPO + ':bundle-' + release
        network('docker', 'buildx', 'build', '--platform', 'linux/amd64', '--provenance=false', '--sbom=false',
                '--label', 'org.opencontainers.image.source=https://github.com/axiomshiftbit/vpnbot',
                '--label', 'org.opencontainers.image.revision=' + bundle['source'], '--push', '-t', ref, directory)
        if channel:
            def move_channel():
                # Check again immediately before the one mutable pointer changes.
                # Повтор после сбоя сети проверяет ветку заново: пауза между
                # попытками не должна стать окном для устаревшей публикации.
                remote = command('gh', 'api', 'repos/' + os.environ['GITHUB_REPOSITORY'] + '/commits/' + branch, '--jq', '.sha')
                if remote != bundle['source']:
                    raise ValueError('branch moved during publication')
                command('docker', 'buildx', 'imagetools', 'create', '--prefer-index=false',
                        '--tag', BUNDLE_REPO + ':bundle-' + channel, ref)

            retrying(move_channel)
            if channel == 'dev':
                # По этой ссылке master, перемотанный ровно на этот коммит,
                # берёт уже проверенный комплект без пересборки.
                network('docker', 'buildx', 'imagetools', 'create', '--prefer-index=false',
                        '--tag', source_reference(bundle['source']), ref)
    print('Published image set:', release, 'channel:', channel or 'candidate only', 'source:', bundle['source'])


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print('Publication rejected: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
