#!/usr/bin/env python3
"""Нода удаляет образы xr/ng, которые не нужны ни одному поколению отката.

Найдено 2026-11-14 на тестовой ноде: каждое обновление скачивало новые образы и
ни одного не удаляло (22 образа, 3 ГБ). Образы текущего и обоих
поколений незавершённого изменения остаются: на поколение «до» нода сама
откатывается без реестра, пока бот не подтвердил изменение. Кнопка ручного
отката скачивает недостающие образы до остановки ноды.
"""
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import node_runtime
import node_state as state
from node_state_test import VALUE
from node_config_test import HOST


def ref(name, char):
    return f'ghcr.io/axiomshiftbit/vpnbot-{name}@sha256:' + char*64


class NodeImagePrune(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vpnbot-node-prune-')
        self.addCleanup(self.temp.cleanup)
        self.store = state.Store(Path(self.temp.name)/'state')
        self.runtime = node_runtime.Runtime(self.store, HOST)

    def generation(self, xr, ng=None):
        value = copy.deepcopy(VALUE)
        value['images'] = {'xr': xr} | ({'ng': ng} if ng else {})
        return self.store.create(value)

    def confirmed(self, generation):
        pending = self.store.begin(generation)
        self.store.activate(generation)
        self.store.confirm(pending['nonce'])

    def prune(self, listed, fail_rm=(), list_rc=0):
        removed = []

        def command(args, *, timeout=30, required=True, data=None):
            if args[:3] == ['docker', 'image', 'ls']:
                return SimpleNamespace(returncode=list_rc, stdout='\n'.join(listed).encode())
            if args[:3] == ['docker', 'image', 'rm']:
                if args[3] in fail_rm:
                    return SimpleNamespace(returncode=1, stdout=b'')
                removed.append(args[3])
                return SimpleNamespace(returncode=0, stdout=b'')
            raise AssertionError(args)
        with patch.object(node_runtime, 'command', command):
            count = self.runtime.prune_images()
        return count, removed

    def test_after_confirmation_only_current_images_remain(self):
        first = self.generation(ref('xr', '1'), ref('ng', '1'))
        self.store.activate(first)
        self.confirmed(self.generation(ref('xr', '2'), ref('ng', '2')))
        self.confirmed(self.generation(ref('xr', '3'), ref('ng', '3')))
        # Образ-манифест комплекта (vpnbot-php) и образы полного бота ноде не нужны.
        listed = [ref(n, c) for n in ('xr', 'ng') for c in '1234'] + [ref('php', '5'), ref('wg', '6'),
                  'ghcr.io/axiomshiftbit/vpnbot-xr@<none>', 'alpine@sha256:'+'7'*64, ref('xr', '1')]
        count, removed = self.prune(listed)
        self.assertEqual(sorted(removed), sorted([ref(n, c) for n in ('xr', 'ng') for c in '124'] + [ref('php', '5'), ref('wg', '6')]))
        self.assertEqual(count, 8)

    def test_pending_change_keeps_both_sides(self):
        first = self.generation(ref('xr', '1'))
        self.store.activate(first)
        self.confirmed(self.generation(ref('xr', '2')))
        third = self.generation(ref('xr', '3'))
        self.store.begin(third)
        self.store.activate(third)
        count, removed = self.prune([ref('xr', c) for c in '1234'])
        # current=after=3 и before=2 нужны автоматическому откату; 1 и 4 — нет.
        self.assertEqual(sorted(removed), [ref('xr', '1'), ref('xr', '4')])

    def test_unreadable_state_or_docker_errors_remove_nothing(self):
        self.store.activate(self.generation(ref('xr', '1')))
        with patch.object(self.store, 'load', side_effect=ValueError('broken snapshot')):
            self.assertEqual(self.prune([ref('xr', '9')]), (0, []))
        self.assertEqual(self.prune([ref('xr', '9')], list_rc=1), (0, []))
        # Образ в контейнере: Docker отказывает, ошибка не всплывает.
        self.assertEqual(self.prune([ref('xr', '9')], fail_rm=(ref('xr', '9'),)), (0, []))

        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired('docker', 20)
        with patch.object(node_runtime, 'command', timeout):
            self.assertEqual(self.runtime.prune_images(), 0)

    def test_foreign_or_malformed_references_are_never_removed(self):
        self.store.activate(self.generation(ref('xr', '1')))
        listed = ['ghcr.io/other/vpnbot-xr@sha256:'+'2'*64, 'ghcr.io/axiomshiftbit/vpnbot-xr:latest', 'ghcr.io/axiomshiftbit/vpnbot-@sha256:'+'2'*64,
                  'ghcr.io/axiomshiftbit/vpnbot-XR@sha256:'+'2'*64, 'docker.io/axiomshiftbit/vpnbot-xr@sha256:'+'2'*64,
                  'ghcr.io/axiomshiftbit/vpnbot-xr@sha256:'+'2'*63, 'ghcr.io/axiomshiftbit/vpnbot-xr@sha256:'+'G'*64]
        self.assertEqual(self.prune(listed), (0, []))


if __name__ == '__main__':
    unittest.main()
