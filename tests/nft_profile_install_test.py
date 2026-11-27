#!/usr/bin/env python3
"""Установка профиля nftables из nftables/: вопросы, откат без подтверждения, шаблоны без реальных адресов."""
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('installer', ROOT / 'scripts/nft_profile_install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)

HOST = dict(interface='ens3', public4='11.77.0.4', public6='', routers=[])


def fake_run(calls, assigned4=('11.77.0.4',), ports=(22,), fail=()):
    def run(args, data=None, check=True, timeout=120):
        args = list(map(str, args))
        calls.append(args)
        out, code = '', 0
        if args[:2] == ['sshd', '-T']:
            out = ''.join(f'port {p}\n' for p in ports)
        elif args[:3] == ['ip', '-j', 'address']:
            out = json.dumps([{'addr_info': [{'scope': 'global', 'family': 'inet', 'local': a} for a in assigned4]}])
        elif args[:3] == ['ip', 'link', 'show']:
            code = 0 if args[-1] == 'ens3' else 1
        elif args[:3] == ['nft', 'list', 'ruleset']:
            out = 'table inet previous { }\n'
        if args[0] in fail:
            code = 1
        if check and code:
            raise ValueError('Команда не выполнена: ' + args[0])
        return SimpleNamespace(returncode=code, stdout=out, stderr='')
    return run


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='vpnbot-nftinst-')
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.config, self.lists, self.backups, self.daemon = root / 'nftables.conf', root / 'list', root / 'backups', root / 'daemon.json'
        self.candidate = root / 'nftables.conf.vpnbot-candidate'
        for name, value in (('CONFIG', self.config), ('LISTS', self.lists), ('BACKUPS', self.backups), ('DAEMON', self.daemon),
                            ('CANDIDATE', self.candidate)):
            p = patch.object(installer, name, value, create=True)
            p.start()
            self.addCleanup(p.stop)
        self.calls = []


class Templates(unittest.TestCase):
    ALLOWED = {'8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'}
    NETS = [ipaddress.ip_network(n) for n in ('91.105.192.0/23', '91.108.0.0/16', '95.161.64.0/20', '149.154.160.0/20',
                                                '185.76.151.0/24', '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24',
                                                '198.18.0.0/15', '2001:db8::/32', '2000::/3')]

    def test_templates_hold_only_examples_and_public_services(self):
        for path in sorted((ROOT / 'nftables').rglob('*')):
            if not path.is_file() or '__pycache__' in path.parts:
                continue
            text = path.read_text()
            for m in re.finditer(r'(?<![\w.:])((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7})(?:/\d+)?(?![\w.:])', text, re.I):
                try:
                    ip = ipaddress.ip_address(m.group(1))
                except ValueError:
                    continue
                with self.subTest(path=path.name, address=m.group(0)):
                    self.assertTrue(not ip.is_global or ip.is_multicast or str(ip) in self.ALLOWED
                                    or any(ip in n for n in self.NETS), 'реальный адрес в шаблоне')

    def test_node_template_access_sets_are_empty_for_the_node_installer(self):
        # node_host читает наборы доступа из /etc/nftables.conf и требует в них
        # только публичные адреса: примеры из документационных сетей роняли
        # установку ноды на первом же этапе.
        import node_host
        text = (ROOT / 'nftables/noda.conf').read_text()
        self.assertEqual({'sources': [], 'admins': [], 'ssh_networks': []}, node_host.access(text))

    def test_ssh_port_and_markers(self):
        main = (ROOT / 'nftables/nftables.conf').read_text()
        node = (ROOT / 'nftables/noda.conf').read_text()
        self.assertIn('define SSH_PORT = 22\n', main)
        self.assertIn('define SERVER_SSH_PORTS = { 22 }\n', node)
        self.assertIn(installer.NODE_MARKER, node.splitlines())
        self.assertNotIn(installer.NODE_MARKER, main.splitlines())
        for text in (main, node):
            self.assertTrue(text.splitlines()[1].startswith('# VPNBot:'))
            self.assertNotRegex(text, r'(?i)7384|nuxt')

    def test_lists_are_examples_except_telegram(self):
        for name in ('asn_nft', 'my_server', 'rkn'):
            text = (ROOT / 'nftables/list' / name / 'geoip-ipv4.nft').read_text()
            nets = re.findall(r'(\d+\.\d+\.\d+\.\d+/\d+)', text)
            self.assertTrue(nets and all(any(ipaddress.ip_network(n).subnet_of(x) for x in self.NETS[5:9]) for n in nets), name)


class Interaction(Base):
    def env(self, **values):
        return patch.dict(os.environ, {'VPNBOT_NFT_' + k: v for k, v in values.items()}, clear=False)

    def collect(self, ports=(22,), **values):
        with patch.object(installer, 'run', fake_run(self.calls, ports=ports)), \
                patch.object(installer.nft, 'discover', return_value=dict(HOST)), self.env(**values):
            return installer.collect(False)

    def test_values_from_environment_are_validated(self):
        got = self.collect(WAN='ens3', PUBLIC4='11.77.0.4', PUBLIC6='-', SSH_PORT='22', ADMINS='198.51.100.7, 198.51.100.0/24')
        self.assertEqual(['198.51.100.0/24', '198.51.100.7/32'], got['admins'])
        self.assertEqual(('ens3', '11.77.0.4', '', 22), (got['interface'], got['public4'], got['public6'], got['ssh_port']))
        for bad in (dict(WAN='eth9'), dict(PUBLIC4='11.77.0.9'), dict(PUBLIC4='10.0.0.1'), dict(SSH_PORT='2222'),
                    dict(ADMINS=''), dict(ADMINS='0.0.0.0/0'), dict(ADMINS='2001:db8::1')):
            values = dict(WAN='ens3', PUBLIC4='11.77.0.4', PUBLIC6='-', SSH_PORT='22', ADMINS='198.51.100.7') | bad
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.collect(**values)

    def test_admin_default_is_current_ssh_client(self):
        with patch.dict(os.environ, {'SSH_CONNECTION': '198.51.100.9 50000 11.77.0.4 22'}):
            self.assertEqual('198.51.100.9', installer.client_address())

    def test_interactive_prompt_repeats_until_valid(self):
        answers = iter(['2222', '', ])
        with patch('builtins.input', lambda prompt: next(answers)), patch('builtins.print'):
            self.assertEqual(22, installer.ask('Порт', '22', lambda v: int(v) if v == '22' else int('x'), 'X', True))

    def test_render_full_uses_answers(self):
        values = dict(HOST, public4='11.77.0.4', sources6=[], ssh_port=22, admins=['198.51.100.7/32'])
        text = installer.render_full(values)
        self.assertIn('define WAN = "ens3"', text)
        self.assertIn('define PUBLIC_IP = 11.77.0.4', text)
        self.assertIn('define SSH_PORT = 22', text)

    def test_my_server_list_replaces_examples(self):
        text = installer.my_server(['198.51.100.7/32'])
        self.assertIn('198.51.100.7/32 : $MY_SERVER', text)
        self.assertNotIn('203.0.113', text)


class Apply(Base):
    def test_failed_atomic_restore_keeps_filter_and_config(self):
        directory = self.backups / 'failed'
        directory.mkdir(parents=True)
        (directory / 'ruleset.nft').write_text('table inet broken {\n')
        (directory / 'nftables.conf').write_text('# old\n')
        self.config.write_text('# active\n')
        with patch.object(installer, 'run', fake_run(self.calls, fail=('nft',))), self.assertRaises(ValueError):
            installer.restore(directory)
        self.assertEqual([['nft', '-f', '-']], self.calls)
        self.assertEqual('# active\n', self.config.read_text())
        self.assertFalse((directory / 'rolled-back').exists())
        self.assertTrue((directory / 'rollback-failed').exists())
        with patch.object(installer, 'run', fake_run(self.calls)):
            installer.restore(directory)
        self.assertEqual('# old\n', self.config.read_text())
        self.assertTrue((directory / 'rolled-back').exists())
        self.assertFalse((directory / 'rollback-failed').exists())

    def test_restore_file_failure_is_reported_after_kernel_restore(self):
        directory = self.backups / 'file-failed'
        directory.mkdir(parents=True)
        (directory / 'ruleset.nft').write_text('table inet previous { }\n')
        (directory / 'nftables.conf').write_text('# old\n')
        self.config.write_text('# active\n')
        with patch.object(installer, 'run', fake_run(self.calls)), \
                patch.object(installer.sets, 'atomic', side_effect=OSError('synthetic disk failure')), \
                self.assertRaises(ValueError):
            installer.restore(directory)
        self.assertEqual([['nft', '-f', '-']], self.calls)
        self.assertFalse((directory / 'rolled-back').exists())
        self.assertTrue((directory / 'rollback-failed').exists())

    def prepare(self):
        self.config.write_text('# previous\n')
        values = dict(HOST, sources6=[], ssh_port=22, admins=['198.51.100.7/32'])
        return [patch.object(installer, 'run', fake_run(self.calls)), patch.object(installer, 'collect', return_value=values),
                patch.object(installer.nft, 'compile_rules', return_value={}),
                patch.object(installer.subprocess, 'Popen', lambda *a, **k: SimpleNamespace(terminate=lambda: None)),
                patch('builtins.print')]

    def start(self, patches):
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_without_confirmation_previous_rules_and_file_return(self):
        self.start(self.prepare())
        with patch.object(installer, 'confirmed', return_value=False):
            self.assertFalse(installer.install_full(True))
        self.assertEqual('# previous\n', self.config.read_text())
        restored = [c for c in self.calls if c[:2] == ['nft', '-f'] and c[2] == '-']
        self.assertTrue(restored, 'прежний ruleset не загружен')
        self.assertFalse(self.daemon.exists(), 'Docker не трогается без подтверждения')
        self.assertTrue(any(p.name == 'rolled-back' for p in self.backups.rglob('*')))

    def test_confirmation_keeps_profile_and_moves_docker_rules(self):
        self.start(self.prepare())
        with patch.object(installer, 'confirmed', return_value=True):
            self.assertTrue(installer.install_full(True))
        self.assertIn('define SSH_PORT = 22', self.config.read_text())
        self.assertEqual({'iptables': False, 'ip6tables': False, 'userland-proxy': False}, json.loads(self.daemon.read_text()))
        self.assertIn(['systemctl', 'enable', 'nftables.service'], self.calls)
        self.assertIn('198.51.100.7/32', (self.lists / 'my_server/geoip-ipv4.nft').read_text())
        self.assertTrue(any(p.name == 'confirmed' for p in self.backups.rglob('*')))

    def test_failed_load_restores_and_reports(self):
        self.start(self.prepare())
        original = installer.run

        def failing(args, data=None, check=True, timeout=120):
            if list(map(str, args)) == ['nft', '-f', str(self.candidate)]:
                raise ValueError('Команда не выполнена: nft')
            return original(args, data, check, timeout)
        with patch.object(installer, 'run', failing), self.assertRaises(ValueError):
            installer.install_full(True)
        self.assertEqual('# previous\n', self.config.read_text())

    def test_no_terminal_changes_nothing(self):
        self.config.write_text('# previous\n')
        with patch('builtins.print'):
            self.assertFalse(installer.install_full(False))
        self.assertEqual('# previous\n', self.config.read_text())
        self.assertFalse(self.backups.exists())

    def test_watchdog_respects_confirmation(self):
        directory = self.backups / 'x'
        directory.mkdir(parents=True)
        with patch.object(installer, 'restore') as restore, patch.object(installer.time, 'sleep'):
            (directory / 'confirmed').write_text('1')
            installer.watchdog(directory, 1)
            restore.assert_not_called()
            (directory / 'confirmed').unlink()
            installer.watchdog(directory, 1)
            restore.assert_called_once_with(directory)

    def test_confirmation_prompt_times_out(self):
        reader, writer = os.pipe()
        try:
            with patch('builtins.print'), os.fdopen(reader) as stream:
                self.assertFalse(installer.confirmed(0.2, stream))
        finally:
            os.close(writer)

    def test_docker_settings_merge_keeps_other_keys(self):
        self.daemon.write_text('{"log-driver": "local", "iptables": true}')
        with patch.object(installer, 'run', fake_run(self.calls)):
            self.assertTrue(installer.docker_rules())
            self.assertFalse(installer.docker_rules())
        value = json.loads(self.daemon.read_text())
        self.assertEqual('local', value['log-driver'])
        self.assertIs(False, value['iptables'])
        self.assertTrue(self.daemon.with_name('daemon.json.before-vpnbot').exists())


class State(Base):
    def test_profile_state(self):
        self.assertEqual('missing', installer.profile_state(self.config, 'full'))
        self.config.write_text('#!/usr/sbin/nft -f\nflush ruleset\n')
        self.assertEqual('foreign', installer.profile_state(self.config, 'full'))
        self.config.write_text((ROOT / 'nftables/nftables.conf').read_text())
        self.assertEqual('ok', installer.profile_state(self.config, 'full'))
        with self.assertRaises(ValueError):
            installer.profile_state(self.config, 'node')
        self.config.write_text((ROOT / 'nftables/noda.conf').read_text())
        self.assertEqual('ok', installer.profile_state(self.config, 'node'))

    def test_declined_own_profile_counts_as_protection_and_keeps_docker(self):
        self.config.write_text('#!/usr/sbin/nft -f\n# own profile\n')
        self.daemon.write_text('{"iptables": true}')
        for mode, expected in (('full', True), ('node', False)):
            out = io.StringIO()
            with patch.object(sys, 'argv', ['nft_profile_install.py', '--mode', mode]), patch.object(installer.os, 'geteuid', return_value=0), \
                    patch.object(sys.stdin, 'isatty', return_value=True), patch('builtins.input', return_value='n'), \
                    patch.object(installer, 'run', side_effect=AssertionError('nothing may run')), patch('sys.stdout', out):
                self.assertIs(expected, installer.main())
            self.assertEqual('#!/usr/sbin/nft -f\n# own profile\n', self.config.read_text())
            self.assertEqual('{"iptables": true}', self.daemon.read_text())
            if mode == 'full':
                self.assertIn('оставлен собственный', out.getvalue())
                self.assertIn('userland-proxy = false', out.getvalue())

    def test_node_template_and_lists_installed_without_overwriting_admin_lists(self):
        (self.lists / 'my_server').mkdir(parents=True)
        (self.lists / 'my_server/geoip-ipv4.nft').write_text('# own list\n')
        self.config.write_text('# debian default\n')
        calls = []
        with patch.object(installer, 'run', fake_run(calls)), patch('builtins.print'), \
                patch.object(installer.shutil, 'which', return_value='/usr/bin/docker'):
            self.assertTrue(installer.install_node())
        # Аудит 26.11.2026 (В03): Docker настраивает установщик ноды после проверки хоста,
        # а не этот шаг до неё.
        self.assertFalse(self.daemon.exists())
        self.assertNotIn(['systemctl', 'restart', 'docker.service'], calls)
        self.assertIn(['docker', 'ps', '--format', '{{.Names}}'], calls)
        self.assertIn(installer.NODE_MARKER, self.config.read_text())
        self.assertEqual('# own list\n', (self.lists / 'my_server/geoip-ipv4.nft').read_text())
        self.assertTrue((self.lists / 'tg/geoip-ipv4.nft').exists())
        self.assertEqual('# debian default\n', self.config.with_name('nftables.conf.before-vpnbot').read_text())


class AuditFixes(Apply):
    """Аудит 26.11.2026: В03, С06–С09."""

    def docker(self, names, labels=None, fail=False):
        labels = labels or {}
        def run(args, data=None, check=True, timeout=120):
            args = list(map(str, args))
            self.calls.append(args)
            if args[:2] == ['docker', 'ps']:
                return SimpleNamespace(returncode=1 if fail else 0, stdout='\n'.join(names), stderr='')
            if args[:2] == ['docker', 'inspect']:
                return SimpleNamespace(returncode=0, stdout=labels.get(args[-1], ''), stderr='')
            return fake_run(self.calls)(args, data, check, timeout)
        return run

    def test_foreign_containers_stop_the_node_template_before_any_change(self):
        self.config.write_text('# debian default\n')
        for names, labels, fail in ((['web'], {}, False), (['vpnbot-node-xray'], {'vpnbot-node-xray': ''}, False), ([], {}, True)):
            with self.subTest(names=names, fail=fail), patch.object(installer, 'run', self.docker(names, labels, fail)), \
                    patch.object(installer.shutil, 'which', return_value='/usr/bin/docker'), patch('builtins.print'):
                try:
                    self.assertFalse(installer.install_node())
                except ValueError:
                    self.assertTrue(fail, 'only an unreachable daemon raises')
            self.assertEqual('# debian default\n', self.config.read_text())
            self.assertFalse(self.lists.exists() or self.daemon.exists())
        with patch.object(installer, 'run', self.docker(['vpnbot-node-xray'], {'vpnbot-node-xray': '1'})), \
                patch.object(installer.shutil, 'which', return_value='/usr/bin/docker'), patch('builtins.print'):
            self.assertTrue(installer.install_node(), 'containers of this node do not block it')

    def test_foreign_profile_without_terminal_needs_an_explicit_choice(self):
        self.config.write_text('#!/usr/sbin/nft -f\n# own profile\n')
        for mode in ('full', 'node'):
            with self.subTest(mode=mode), patch.object(sys, 'argv', ['nft_profile_install.py', '--mode', mode]), \
                    patch.object(installer.os, 'geteuid', return_value=0), patch.object(sys.stdin, 'isatty', return_value=False), \
                    patch.dict(os.environ, {'VPNBOT_NFT_REPLACE': ''}), \
                    patch.object(installer, 'run', side_effect=AssertionError('nothing may run')), patch('builtins.print'):
                self.assertIs(False, installer.main())
            self.assertEqual('#!/usr/sbin/nft -f\n# own profile\n', self.config.read_text())
        with patch.object(sys, 'argv', ['nft_profile_install.py', '--mode', 'node']), patch.object(installer.os, 'geteuid', return_value=0), \
                patch.object(sys.stdin, 'isatty', return_value=False), patch.dict(os.environ, {'VPNBOT_NFT_REPLACE': 'yes'}), \
                patch.object(installer, 'run', self.docker([])), patch.object(installer.shutil, 'which', return_value='/usr/bin/docker'), \
                patch('builtins.print'):
            self.assertIs(True, installer.main())
        self.assertIn(installer.NODE_MARKER, self.config.read_text())

    def test_rolled_back_attempt_leaves_no_trusted_list(self):
        self.start(self.prepare())
        with patch.object(installer, 'confirmed', return_value=False):
            self.assertFalse(installer.install_full(True))
        self.assertFalse((self.lists / 'my_server').exists(), 'C06: the next attempt must not inherit these addresses')
        # The backup directory is named by the second: the retry gets its own.
        with patch.object(installer, 'confirmed', return_value=True), patch.object(installer.time, 'strftime', return_value='retry'):
            self.assertTrue(installer.install_full(True))
        self.assertIn('198.51.100.7/32', (self.lists / 'my_server/geoip-ipv4.nft').read_text())

    def test_boot_file_changes_only_after_confirmation(self):
        self.start(self.prepare())
        seen = []
        def confirm(seconds):
            seen.append((self.config.read_text(), self.candidate.exists()))
            return False
        with patch.object(installer, 'confirmed', side_effect=confirm):
            self.assertFalse(installer.install_full(True))
        self.assertEqual(seen, [('# previous\n', True)], 'C07: a reboot in the window boots the previous profile')
        self.assertFalse(self.candidate.exists())
        self.assertIn(['nft', '-f', str(self.candidate)], self.calls)

    def test_daemon_json_mode_is_never_widened(self):
        for before, expected in ((0o600, 0o600), (0o640, 0o600), (None, 0o600)):
            self.daemon.unlink(missing_ok=True)
            self.daemon.with_name('daemon.json.before-vpnbot').unlink(missing_ok=True)
            if before is not None:
                self.daemon.write_text('{"proxies": {"http-proxy": "http://user:synthetic@198.51.100.9:3128"}}')
                os.chmod(self.daemon, before)
            with self.subTest(before=before), patch.object(installer, 'run', fake_run(self.calls)):
                installer.docker_rules()
                self.assertEqual(self.daemon.stat().st_mode & 0o777, expected)
                if before is not None:
                    self.assertEqual(self.daemon.with_name('daemon.json.before-vpnbot').stat().st_mode & 0o777, 0o600)

    def test_ssh_port_published_by_dnat_is_refused(self):
        values = dict(HOST, sources6=[], admins=['198.51.100.7/32'])
        for port, service in ((443, 'UPSTREAM_INPUT'), (8388, 'SS_INPUT'), (9443, 'TELEMT_INPUT')):
            with self.subTest(port=port), self.assertRaises(ValueError) as error:
                installer.render_full(dict(values, ssh_port=port))
            self.assertIn(service, str(error.exception))
        self.assertIn('define SSH_PORT = 2222', installer.render_full(dict(values, ssh_port=2222)))
        # UDP-only Hysteria does not take TCP.
        self.assertIn('define SSH_PORT = 5443', installer.render_full(dict(values, ssh_port=5443)))


if __name__ == '__main__':
    unittest.main()
