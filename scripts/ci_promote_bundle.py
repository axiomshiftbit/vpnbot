#!/usr/bin/env python3
"""Выдать master комплект, уже допущенный в dev для того же коммита.

Пересборка того же коммита дала бы другие образы того же кода и проверяла бы
их второй раз. Здесь в канал latest попадают ровно те образы, что прошли
сборку, проверки CVE и стенд. Нет допущенного комплекта — обычный полный прогон.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from ci_retry import retrying
from image_bundle import BUNDLE_REPO, command, fetch_reference, source_reference


def network(*args):
    return retrying(command, *args)


def admitted(source):
    """Комплект, опубликованный для этого коммита, либо None."""
    with tempfile.TemporaryDirectory() as directory:
        try:
            # Отсутствие ссылки и сбой сети реестр не различает, а ошибка здесь
            # стоит полной пересборки вместо переноса — повторяем и это.
            bundle = retrying(fetch_reference, source_reference(source), Path(directory) / 'bundle.json',
                              errors=(RuntimeError, subprocess.SubprocessError))
        except (RuntimeError, subprocess.SubprocessError):
            # Ссылки нет или реестр недоступен: безопасная сторона — собрать заново.
            return None
    if bundle['source'] != source:
        raise ValueError('admitted set belongs to another commit')
    return bundle


def promote():
    branch, event, source = (os.environ[name] for name in ('GITHUB_REF_NAME', 'GITHUB_EVENT_NAME', 'GITHUB_SHA'))
    # Расписание существует ради пересборки со свежими пакетами.
    if branch != 'master' or event == 'schedule' or os.environ.get('FULL_BUILD') == 'true':
        return False
    bundle = admitted(source)
    if bundle is None:
        return False
    for ref in bundle['images'].values():
        network('docker', 'buildx', 'imagetools', 'inspect', ref)
    def move_channel():
        # Повтор после сбоя сети проверяет ветку заново: пауза между попытками
        # не должна стать окном для публикации устаревшего комплекта.
        remote = command('gh', 'api', 'repos/' + os.environ['GITHUB_REPOSITORY'] + '/commits/' + branch, '--jq', '.sha')
        if remote != source:
            raise ValueError('newer code exists; stale run cannot publish')
        command('docker', 'buildx', 'imagetools', 'create', '--prefer-index=false',
                '--tag', BUNDLE_REPO + ':bundle-latest', source_reference(source))

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
