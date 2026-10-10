#!/usr/bin/env python3
"""Передвинуть master на коммит dev, комплект которого только что опубликован.

Выполняется последним заданием полного прогона dev и только по флажку
promote_master. Ветка двигается строго вперёд: если в master есть коммит,
которого нет в проверенном коммите, или dev успел уйти дальше, перенос
отклоняется и ничего не меняется. После переноса запускается короткий прогон
master — он ставит канал latest на те же образы без пересборки.

Встроенный токен прогона здесь не годится: им нельзя двигать ветку на коммиты,
меняющие файлы workflow, а запущенный им прогон не попадёт на свой runner.
Нужен отдельный токен в секрете PROMOTE_TOKEN (fine-grained, только этот
репозиторий: Contents, Workflows и Actions — чтение и запись).
"""
import json
import os
import sys
import urllib.error
import urllib.request

from ci_retry import retrying


class Rejected(Exception):
    """Перенос невозможен без потери чужих правок или проверенности."""


def api(path, secret, body=None, method=None):
    request = urllib.request.Request(
        os.environ.get('GITHUB_API_URL', 'https://api.github.com') + '/repos/' + os.environ['GITHUB_REPOSITORY'] + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={'Accept': 'application/vnd.github+json', 'Authorization': 'Bearer ' + secret,
                 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'vpnbot-ci-promote-master'},
        method=method or ('GET' if body is None else 'POST'))
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
    except urllib.error.HTTPError as error:
        if error.code >= 500:
            raise RuntimeError('GitHub is unavailable') from None
        raise
    except OSError:
        raise RuntimeError('GitHub is unreachable') from None
    return json.loads(raw) if raw else {}


def head(branch, secret):
    return retrying(api, '/git/ref/heads/' + branch, secret)['object']['sha']


def promote(secret):
    source = os.environ['GITHUB_SHA']
    if os.environ['GITHUB_REF'] != 'refs/heads/dev' or os.environ['GITHUB_EVENT_NAME'] != 'workflow_dispatch':
        raise Rejected('only a manual run of dev is promoted')
    if head('dev', secret) != source:
        raise Rejected('dev has moved on; the tested commit is no longer its head')
    master = head('master', secret)
    if master != source:
        ahead = retrying(api, '/compare/' + master + '...' + source, secret)
        if ahead.get('status') != 'ahead' or ahead.get('behind_by') != 0:
            raise Rejected('master has commits that the tested commit lacks')
        try:
            # force=false: GitHub сам откажет, если за это время ветка разошлась.
            retrying(api, '/git/refs/heads/master', secret, {'sha': source, 'force': False}, 'PATCH')
        except urllib.error.HTTPError as error:
            if error.code == 422:
                raise Rejected('master moved during promotion') from None
            raise
        print('master moved forward to', source)
    else:
        print('master already points at', source)
    retrying(api, '/actions/workflows/images.yml/dispatches', secret, {'ref': 'master', 'inputs': {'test_runner': 'true'}})
    print('Started the master run that moves the latest channel to the same image set')


def main():
    secret = os.environ.get('PROMOTE_TOKEN', '')
    if not secret:
        raise Rejected('secret PROMOTE_TOKEN is not set')
    promote(secret)


if __name__ == '__main__':
    try:
        main()
    except Rejected as error:
        print('Promotion to master rejected: ' + str(error), file=sys.stderr)
        sys.exit(1)
    except urllib.error.HTTPError as error:
        print('Promotion to master failed: GitHub answered ' + str(error.code) + ' — check the token and its permissions', file=sys.stderr)
        sys.exit(1)
    except (KeyError, ValueError, RuntimeError) as error:
        print('Promotion to master failed: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
