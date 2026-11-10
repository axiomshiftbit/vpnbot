#!/usr/bin/env python3
"""Выдать master комплект, уже допущенный в dev для того же коммита.

Пересборка того же коммита дала бы другие образы того же кода и проверяла бы
их второй раз. Здесь в канал latest попадают ровно те образы, что прошли
сборку, проверки CVE и стенд. Нет допущенного комплекта — обычный полный прогон.
"""
import os
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile

from ci_retry import retrying
from image_bundle import BUNDLE_REPO, command, fetch_reference, source_reference
import ci_release_policy as release_policy


def network(*args):
    return retrying(command, *args)


def admitted(source):
    """Комплект, опубликованный для этого коммита, либо None."""
    with tempfile.TemporaryDirectory() as directory:
        try:
            # Отсутствие ссылки и сбой сети реестр не различает, а ошибка здесь
            # стоит полной пересборки вместо переноса — повторяем и это.
            digest = network('docker', 'buildx', 'imagetools', 'inspect', '--format', '{{.Manifest.Digest}}', source_reference(source))
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
                raise ValueError('invalid admitted envelope digest')
            reference = BUNDLE_REPO+'@'+digest
            proof_path = Path(directory)/'admission.json'
            bundle = retrying(lambda: fetch_reference(reference, Path(directory) / 'bundle.json', admission=proof_path),
                              errors=(RuntimeError, subprocess.SubprocessError))
        except (RuntimeError, subprocess.SubprocessError):
            # Ссылки нет или реестр недоступен: безопасная сторона — собрать заново.
            return None
        proof = release_policy.validate_proof(json.loads(proof_path.read_text()), bundle, release_policy.policy())
        release_policy.announce([{k: v for k, v in row.items() if k != 'stage'} for row in proof['warnings']], 'master')
    if bundle['source'] != source:
        raise ValueError('admitted set belongs to another commit')
    return bundle, reference


def promote():
    branch, event, source = (os.environ[name] for name in ('GITHUB_REF_NAME', 'GITHUB_EVENT_NAME', 'GITHUB_SHA'))
    # Расписание существует ради пересборки со свежими пакетами.
    if branch != 'master' or event == 'schedule' or os.environ.get('FULL_BUILD') == 'true':
        return False
    candidate = admitted(source)
    if candidate is None:
        return False
    bundle, reference = candidate
    for ref in bundle['images'].values():
        network('docker', 'buildx', 'imagetools', 'inspect', ref)
    def move_channel():
        # Повтор после сбоя сети проверяет ветку заново: пауза между попытками
        # не должна стать окном для публикации устаревшего комплекта.
        remote = command('gh', 'api', 'repos/' + os.environ['GITHUB_REPOSITORY'] + '/commits/' + branch, '--jq', '.sha')
        if remote != source:
            raise ValueError('newer code exists; stale run cannot publish')
        command('docker', 'buildx', 'imagetools', 'create', '--prefer-index=false',
                '--tag', BUNDLE_REPO + ':bundle-latest', reference)

    retrying(move_channel)
    print('Promoted admitted image set: release-' + str(bundle['run']) + '-' + str(bundle['attempt']),
          'channel: latest source:', source)
    return True


def main():
    promoted = promote()
    if not promoted:
        print('No admitted image set is promoted: full build')
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write('promoted=' + ('true' if promoted else 'false') + '\n')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print('Promotion rejected: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
