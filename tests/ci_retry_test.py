#!/usr/bin/env python3
"""Повторы сетевых шагов CI: помощники и их подключение в workflow."""
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import ci_retry  # noqa: E402


class ShellRetryTest(unittest.TestCase):
    def run_script(self, failures, shell='sh', delays='0.05 0.05 0.05'):
        with tempfile.TemporaryDirectory() as directory:
            counter = Path(directory) / 'count'
            counter.write_text('0')
            probe = Path(directory) / 'probe.sh'
            probe.write_text('n=$(cat "$1"); n=$((n + 1)); echo "$n" > "$1"; [ "$n" -gt "$2" ] || exit 7\n')
            result = subprocess.run([shell, str(ROOT / 'scripts/ci_retry.sh'), 'sh', str(probe), str(counter), str(failures)],
                                    env=os.environ | {'CI_RETRY_DELAYS': delays}, capture_output=True, text=True)
            return result, int(counter.read_text())

    def test_success_runs_once_and_stays_quiet(self):
        result, attempts = self.run_script(0)
        self.assertEqual((result.returncode, attempts, result.stderr), (0, 1, ''))

    def test_transient_failure_is_retried_until_success(self):
        for failures in (1, 2, 3):
            with self.subTest(failures=failures):
                result, attempts = self.run_script(failures)
                self.assertEqual((result.returncode, attempts), (0, failures + 1))
                self.assertEqual(result.stderr.count('ci_retry:'), failures)

    def test_persistent_failure_keeps_the_exit_code_after_four_attempts(self):
        result, attempts = self.run_script(99)
        self.assertEqual((result.returncode, attempts), (7, 4))

    def test_zero_and_empty_delays_do_not_disable_retries(self):
        # Нулевая пауза не должна совпасть с признаком последней попытки,
        # а пустая переменная — оставить команду без повторов.
        result, attempts = self.run_script(99, delays='0 0 0')
        self.assertEqual((result.returncode, attempts), (7, 4))
        result, attempts = self.run_script(2, delays='0 0 0')
        self.assertEqual((result.returncode, attempts), (0, 3))
        source = (ROOT / 'scripts/ci_retry.sh').read_text()
        self.assertIn('${CI_RETRY_DELAYS:-15 45 90} last', source)

    def test_arguments_with_spaces_and_quotes_survive(self):
        result = subprocess.run(['sh', str(ROOT / 'scripts/ci_retry.sh'), 'printf', '%s|', 'a b', "c'd", '$HOME', ''],
                                capture_output=True, text=True)
        self.assertEqual(result.stdout, "a b|c'd|$HOME||")

    def test_script_is_posix_shell_for_alpine(self):
        self.assertTrue((ROOT / 'scripts/ci_retry.sh').read_text().startswith('#!/bin/sh\n'))
        if subprocess.run(['sh', '-c', 'command -v dash'], capture_output=True).returncode == 0:
            result, attempts = self.run_script(2, 'dash')
            self.assertEqual((result.returncode, attempts), (0, 3))


class GoRetryTest(unittest.TestCase):
    """dockerfile/go-retry.sh: повтор только при сбое загрузки модулей."""
    NETWORK = 'go: github.com/x/y@v1.0.0: Get "https://proxy.golang.org/github.com/x/y/@v/v1.0.0.mod": net/http: TLS handshake timeout'

    def run_go(self, failures, message, extra=''):
        with tempfile.TemporaryDirectory() as directory:
            counter = Path(directory) / 'count'
            counter.write_text('0')
            fake = Path(directory) / 'go'
            fake.write_text('#!/bin/sh\nn=$(cat "%s"); n=$((n + 1)); echo "$n" > "%s"\n'
                            'echo "stdout-line"\n[ "$n" -gt %d ] && exit 0\necho \'%s\' >&2\n%s\nexit 1\n'
                            % (counter, counter, failures, message.replace("'", "'\\''"), extra))
            fake.chmod(0o755)
            result = subprocess.run(['sh', str(ROOT / 'dockerfile/go-retry.sh'), str(fake), 'build', './...'],
                                    env=os.environ | {'GO_RETRY_DELAYS': '0.05 0.05 0.05'}, capture_output=True, text=True)
            return result, int(counter.read_text())

    def test_success_passes_output_through_once(self):
        result, attempts = self.run_go(0, self.NETWORK)
        self.assertEqual((result.returncode, attempts, result.stdout), (0, 1, 'stdout-line\n'))

    def test_module_download_failure_is_retried(self):
        # Вторая запись — дословный вид отказа go build из прогона 37936217179.
        for message in (self.NETWORK, 'core/icmp.go:7:2: gvisor.dev/gvisor@v0.0.0-20260701204157-69c2d17aea96: Get "https://proxy.golang.org/gvisor.dev/gvisor/@v/v0.0.0-20260701204157-69c2d17aea96.zip": net/http: TLS handshake timeout',
                        'main.go:10:2: gopkg.in/yaml.v3@v3.0.1: reading https://proxy.golang.org/gopkg.in/yaml.v3/@v/v3.0.1.zip: 502 Bad Gateway',
                        'go: verifying module: Get "https://sum.golang.org/lookup/x": dial tcp: i/o timeout',
                        'go: module lookup: unexpected EOF', 'go: downloading: read: connection reset by peer'):
            with self.subTest(message=message[:40]):
                result, attempts = self.run_go(2, message)
                self.assertEqual((result.returncode, attempts), (0, 3))
                self.assertEqual(result.stderr.count('go-retry:'), 2)

    def test_persistent_network_failure_gives_up_after_four_attempts(self):
        result, attempts = self.run_go(99, self.NETWORK)
        self.assertEqual((result.returncode, attempts), (1, 4))
        self.assertIn('TLS handshake timeout', result.stderr)

    def test_proxy_falls_back_to_direct_download(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / 'go'
            fake.write_text('#!/bin/sh\necho "$GOPROXY"\n')
            fake.chmod(0o755)
            env = {k: v for k, v in os.environ.items() if k != 'GOPROXY'}
            result = subprocess.run(['sh', str(ROOT / 'dockerfile/go-retry.sh'), str(fake)], env=env, capture_output=True, text=True)
            self.assertEqual(result.stdout.strip(), 'https://proxy.golang.org|direct')
            result = subprocess.run(['sh', str(ROOT / 'dockerfile/go-retry.sh'), str(fake)], env=env | {'GOPROXY': 'off'}, capture_output=True, text=True)
            self.assertEqual(result.stdout.strip(), 'off')

    def test_compile_and_test_failures_are_not_retried(self):
        for message in ('./main.go:10:2: undefined: missing', '--- FAIL: TestDial (0.00s)\n    dial_test.go:9: dial tcp 127.0.0.1:1: i/o timeout',
                        'FAIL\tgithub.com/x/y\t0.012s', 'panic: runtime error', 'go: errors parsing go.mod'):
            with self.subTest(message=message[:30]):
                result, attempts = self.run_go(99, message)
                self.assertEqual((result.returncode, attempts), (1, 1))
                self.assertNotIn('go-retry:', result.stderr)

    def test_every_go_command_in_image_builds_goes_through_the_wrapper(self):
        bare = re.compile(r'(?<![\w/.-])go (?:build|test|get|list|mod) ')
        files = sorted((ROOT / 'dockerfile').glob('*.dockerfile')) + [ROOT / 'dockerfile/build-xray.sh', ROOT / 'dockerfile/go-security.sh']
        wrapped = 0
        for path in files:
            for line in path.read_text().splitlines():
                if line.lstrip().startswith('#'):
                    continue
                wrapped += line.count('go-retry.sh')
                with self.subTest(path.name, line=line.strip()[:60]):
                    self.assertIsNone(bare.search(re.sub(r'go-retry\.sh"? go \w+ ', '', line)))
        self.assertGreaterEqual(wrapped, 25)
        for name in ('protocol', 'mieru', 'masque', 'dnstt'):
            self.assertIn('go-retry.sh', re.findall(r'^COPY .*$', (ROOT / 'dockerfile' / (name + '.dockerfile')).read_text(), re.M).__str__(), name)


class PythonRetryTest(unittest.TestCase):
    def test_retries_then_returns_the_value(self):
        calls = []

        def flaky(*args):
            calls.append(args)
            if len(calls) < 3:
                raise RuntimeError('network')
            return 'value'

        with patch.object(ci_retry.time, 'sleep') as sleep, patch('sys.stdout'):
            self.assertEqual(ci_retry.retrying(flaky, 'docker', 'pull', 'x'), 'value')
        self.assertEqual(calls, [('docker', 'pull', 'x')] * 3)
        self.assertEqual([c.args[0] for c in sleep.call_args_list], list(ci_retry.DELAYS[:2]))

    def test_gives_up_after_four_attempts(self):
        calls = []

        def broken(*args):
            calls.append(args)
            raise RuntimeError('network')

        with patch.object(ci_retry.time, 'sleep'), patch('sys.stdout'), self.assertRaises(RuntimeError):
            ci_retry.retrying(broken, 'x')
        self.assertEqual(len(calls), 4)

    def test_delays_from_environment(self):
        script = 'import sys; sys.path.insert(0, sys.argv[1]); import ci_retry; print(ci_retry.DELAYS)'
        for value, expected in ((None, '(15.0, 45.0, 90.0)'), ('', '(15.0, 45.0, 90.0)'), ('0 0 0', '(0.0, 0.0, 0.0)'),
                                ('0.5 1', '(0.5, 1.0)')):
            env = {k: v for k, v in os.environ.items() if k != 'CI_RETRY_DELAYS'}
            if value is not None:
                env['CI_RETRY_DELAYS'] = value
            with self.subTest(value=value):
                result = subprocess.run([sys.executable, '-c', script, str(ROOT / 'scripts')], env=env, capture_output=True, text=True)
                self.assertEqual(result.stdout.strip(), expected, result.stderr)

    def test_default_is_four_attempts(self):
        self.assertEqual(len(ci_retry.DELAYS), 3)

    def test_decisions_are_not_retried(self):
        calls = []

        def stale(*args):
            calls.append(args)
            raise ValueError('newer code exists')

        with patch.object(ci_retry.time, 'sleep') as sleep, self.assertRaises(ValueError):
            ci_retry.retrying(stale, 'x')
        self.assertEqual((len(calls), sleep.call_count), (1, 0))

    def test_failure_text_is_not_printed(self):
        def leaky(*args):
            raise RuntimeError('https://user:secret@registry')

        with patch.object(ci_retry.time, 'sleep'), patch('builtins.print') as output, self.assertRaises(RuntimeError):
            ci_retry.retrying(leaky, 'x')
        self.assertNotIn('secret', repr(output.call_args_list))


class WorkflowRetryTest(unittest.TestCase):
    workflows = sorted((ROOT / '.github/workflows').glob('*.yml'))
    actions = sorted((ROOT / '.github/actions').glob('*/action.yml'))

    def test_network_actions_are_used_only_through_retrying_wrappers(self):
        direct = re.compile(r'uses:\s*(?:actions/(?:download|upload)-artifact|docker/login-action|docker/setup-buildx-action)@')
        for path in self.workflows:
            with self.subTest(path.name):
                self.assertIsNone(direct.search(path.read_text()))
        self.assertEqual({p.parent.name for p in self.actions},
                         {'download-artifact', 'upload-artifact', 'registry-login', 'setup-buildx'})

    def test_each_wrapper_makes_four_attempts_and_only_the_last_decides(self):
        for path in self.actions:
            with self.subTest(path.parent.name):
                steps = yaml.safe_load(path.read_text())['runs']['steps']
                attempts = [s for s in steps if 'uses' in s]
                waits = [s for s in steps if s.get('run', '').startswith('sleep ')]
                self.assertEqual(len(attempts), 4)
                self.assertEqual(len({s['uses'] for s in attempts}), 1)
                self.assertRegex(attempts[0]['uses'], r'@[0-9a-f]{40}$')
                self.assertEqual(len({str(s['with']) for s in attempts}), 1)
                self.assertTrue(all(s.get('continue-on-error') is True for s in attempts[:3]))
                self.assertNotIn('continue-on-error', attempts[3])
                if path.parent.name in ('upload-artifact', 'download-artifact'):
                    self.assertEqual(attempts[0]['if'], "runner.environment != 'self-hosted'")
                    local = [s for s in steps if s.get('if') == "runner.environment == 'self-hosted'"]
                    self.assertEqual(len(local), 1)
                    self.assertIn('sudo env -i', local[0]['run'])
                    self.assertIn('scripts/ci_local_artifacts.py', local[0]['run'])
                else:
                    self.assertNotIn('if', attempts[0])
                for index in (1, 2, 3):
                    self.assertEqual(attempts[index]['if'], f"steps.attempt{index}.outcome == 'failure'")
                self.assertEqual([s['run'] for s in waits], ['sleep 15', 'sleep 45', 'sleep 90'])
                self.assertEqual([s['if'] for s in waits], [f"steps.attempt{i}.outcome == 'failure'" for i in (1, 2, 3)])

    def test_workflow_commands_that_reach_the_network_are_retried(self):
        bare = re.compile(r'^\s*(?:sudo\s+)?(?:docker pull|apt-get (?:update|install)|apk add)\b', re.M)
        for path in self.workflows:
            with self.subTest(path.name):
                self.assertEqual(bare.findall(path.read_text()), [])
        for path in self.workflows:
            for line in path.read_text().splitlines():
                if re.search(r'\bcurl\b.*https?://', line):
                    self.assertIn('--retry-all-errors', line, line.strip())

    def test_stand_client_image_build_survives_a_network_failure(self):
        source = (ROOT / 'tests/integration/clients.dockerfile').read_text().replace('\\\n', ' ')
        for line in source.splitlines():
            for command in re.findall(r'\bcurl\b[^&;]*https?://[^&;]*', line):
                with self.subTest(command[:60]):
                    self.assertIn('--retry-all-errors', command)
        # git clone сам не повторяется: он стоит в цикле, и неудачная попытка убирает за собой.
        self.assertRegex(source, r'for attempt in 1 2 3 4 5; do\s+git clone \S+ /dnstt && break;\s+rm -rf /dnstt; sleep 10;\s+done')
        self.assertEqual(len(re.findall(r'\bgit clone\b', source)), 1)
        script = (ROOT / 'scripts/ci_hosted_test.py').read_text()
        self.assertIn('retrying(lambda: subprocess.run(args, check=True, timeout=1200), errors=(subprocess.CalledProcessError,))', script)

    def test_build_preflight_and_process_check_do_not_race(self):
        workflow = (ROOT / '.github/workflows/images.yml').read_text()
        # Проверочный контейнер соседнего задания живёт секунды: проверка ждёт, но в конце всё равно требует пустого списка.
        start = workflow.index('Проверить домашний тестовый хост перед сборкой')
        preflight = workflow[start:workflow.index('./.github/actions/setup-buildx', start)]
        self.assertRegex(preflight, r'for attempt in \$\(seq 1 24\); do\n\s+foreign=\$\(docker ps[^\n]+\n\s+\[ -z "\$foreign" \] && break\n\s+sleep 5\n\s+done\n\s+test -z "\$foreign"')
        # Имя процесса проверяется после exec, а не сразу после запуска в фоне.
        start = workflow.index('/bin/sleep 30 & child=$!')
        check = workflow[start:workflow.index('Идентификатор проверенного образа', start)]
        self.assertLess(check.index('until [ "$(cat /proc/$child/comm 2>/dev/null)" = sleep ]'), check.index('pgrep -x sleep | grep -qx "$child"'))
        # Пауза перед повторной сборкой длиннее типичного сбоя Docker Hub.
        self.assertIn("      - if: steps.image.outcome == 'failure'\n        run: sleep 120\n", workflow)

    def test_release_scripts_route_registry_and_api_calls_through_retries(self):
        for name in ('ci_publish_bundle.py', 'ci_promote_bundle.py', 'ci_hosted_test.py'):
            with self.subTest(name):
                source = (ROOT / 'scripts' / name).read_text()
                # Прямой вызов допустим только внутри блока, который повторяется целиком.
                outside = re.sub(r"\n( +)def move_channel\(\):\n(?:\1 .*\n|\n)+", '\n', source)
                self.assertIsNone(re.search(r"(?<!def )\bcommand\('(?:gh|docker)', '(?:api|pull|buildx)'", outside))
                if 'move_channel' in source:
                    self.assertIn('retrying(move_channel)', source)
        scan = (ROOT / 'scripts/ci_scan_image.sh').read_text()
        self.assertEqual(len(re.findall(r'^sh "\$retry" "\$work/trivy" image ', scan, re.M)), 2)
        self.assertIn('--retry-all-errors', scan)


if __name__ == '__main__':
    unittest.main()
