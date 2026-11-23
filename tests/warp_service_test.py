import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WarpServiceTest(unittest.TestCase):
    def test_proc_udp_range_is_read_by_production_shell(self):
        source = (ROOT / 'scripts/start_wp.sh').read_text()
        guard = source[source.index('udp_range=$('):source.index('cat > /run/warp-socks.json')]
        expected = ':'.join(Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split())
        for shell in ('sh', 'bash'):
            with self.subTest(shell=shell):
                result = subprocess.run([shell, '-c', 'set -e\n' + guard],
                                        env=dict(os.environ, SOCKS_UDP_PORTS=expected), capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode())

    def run_fixup_up(self, tmp, answering_port):
        """warp_fixup.sh up with wg/wg-quick replaced in PATH: the real shell code runs."""
        conf = Path(tmp) / 'wgcf-profile.conf'
        conf.write_text('[Interface]\nPrivateKey = fixture\nAddress = 172.16.0.2/32\n[Peer]\nEndpoint = engage.example.test:2408\n')
        conf.chmod(0o600)
        bin_dir = Path(tmp) / 'bin'
        bin_dir.mkdir()
        stubs = {
            'wg': '#!/bin/sh\n[ -e "$T/interface" ] || exit 1\n[ "$3" = latest-handshakes ] || exit 0\n'
                  'if grep -q ":$ANSWER$" "$T/wgcf-profile.conf"; then printf "peer\\t1700000000\\n"; else printf "peer\\t0\\n"; fi\n',
            'wg-quick': '#!/bin/sh\necho "$1 $(sed -n "s/^Endpoint = //p" "$2")" >> "$T/log"\n'
                        'if [ "$1" = up ]; then touch "$T/interface"; else rm -f "$T/interface"; fi\n',
            'sleep': '#!/bin/sh\nexit 0\n',
        }
        for name, body in stubs.items():
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        env = dict(os.environ, T=tmp, ANSWER=answering_port, WGCF_CONF=str(conf), PATH=f"{bin_dir}:{os.environ['PATH']}")
        result = subprocess.run(['sh', str(ROOT / 'scripts/warp_fixup.sh'), 'up'], env=env, capture_output=True)
        ups = [line for line in (Path(tmp) / 'log').read_text().splitlines() if line.startswith('up ')]
        return result, conf, ups

    def test_failed_handshake_does_not_leave_ready_interface(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, conf, ups = self.run_fixup_up(tmp, 'none')
            self.assertEqual(result.returncode, 1, result.stderr.decode())
            self.assertFalse((Path(tmp) / 'interface').exists())
            self.assertEqual(len(ups), 4)
            self.assertEqual(conf.stat().st_mode & 0o777, 0o600)

    def test_blocked_endpoint_port_moves_the_profile_to_an_answering_port(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, conf, ups = self.run_fixup_up(tmp, '1701')
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertTrue((Path(tmp) / 'interface').exists())
            self.assertIn('Endpoint = engage.example.test:1701\n', conf.read_text())
            self.assertIn('PrivateKey = fixture', conf.read_text())
            self.assertEqual(conf.stat().st_mode & 0o777, 0o600)
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ['bin', 'interface', 'log', 'wgcf-profile.conf'])
            self.assertEqual(ups, ['up engage.example.test:2408', 'up engage.example.test:500', 'up engage.example.test:1701'])

    def test_answering_endpoint_keeps_its_port(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, conf, ups = self.run_fixup_up(tmp, '2408')
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(ups, ['up engage.example.test:2408'])

    def test_watchdog_uses_the_shared_bring_up(self):
        source = (ROOT / 'scripts/start_wp.sh').read_text()
        self.assertIn('warp_up() {\n    WGCF_CONF="$WGCF_CONF" sh "${WARP_FIXUP:-/warp_fixup.sh}" up\n}', source)
        bot = (ROOT / 'app/bot.php').read_text()
        self.assertIn("private const WARP_UP = '{ sh /warp_fixup.sh up || exit 1; }';", bot)

if __name__ == '__main__':
    unittest.main()


class WarpModeTest(unittest.TestCase):
    """Режимы WireGuard и MASQUE в start_wp.sh: функции исполняются настоящей оболочкой."""

    def setUp(self):
        self.source = (ROOT / 'scripts/start_wp.sh').read_text()
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / 'run').mkdir()
        (self.dir / 'warp').mkdir()
        self.log = self.dir / 'log'
        # Имена с дефисом нельзя объявить функцией оболочки: подменяются файлами в PATH.
        (self.dir / 'bin').mkdir()
        for name, body in (('warp-socks', 'echo "core $*" >> "$LOG"; case "$4" in *.json) ;; *) exit 9 ;; esac; [ "$FAIL" != core ]'),
                           ('wg-quick', 'echo "wg-quick $*" >> "$LOG"')):
            path = self.dir / 'bin' / name
            path.write_text('#!/bin/sh\n' + body + '\n')
            path.chmod(0o700)

    def tearDown(self):
        self.tmp.cleanup()

    def piece(self, start, end):
        text = self.source[self.source.index(start):self.source.index(end)]
        return text.replace('/run/', str(self.dir / 'run') + '/').replace('/warp_masque.sh', str(self.dir / 'masque.sh')) \
            .replace('/config/pac.json', str(self.dir / 'pac.json'))

    def shell(self, script, **env):
        prelude = '''
SOCKS_PORT=1080; SOCKS_UDP_PORTS=20000:29999; WGCF_IF=wgcf-profile; WGCF_CONF=/nonexistent/wgcf-profile.conf; PROXY_UID=30000
iptables() { echo "iptables $*" >> "$LOG"; }
ip6tables() { echo "ip6tables $*" >> "$LOG"; }
'''
        environ = dict(os.environ, LOG=str(self.log), PATH=str(self.dir / 'bin') + ':' + os.environ['PATH'], FAIL='',
                       WGCF_DIR=str(self.dir / 'warp'))
        environ.update(env)
        return subprocess.run(['sh', '-c', prelude + script], env=environ, capture_output=True, text=True, timeout=30)

    def rules(self, family):
        return [line.split(' ', 1)[1] for line in (self.log.read_text().splitlines() if self.log.exists() else []) if line.startswith(family + ' ')]

    def firewall(self, **settings):
        self.log.write_text('')
        chain = self.piece('MASQUE_ENDPOINT=""\nMASQUE_PROTO=udp', 'proxy_firewall\n\n# Конфиг не содержит')
        assign = ''.join('%s=%s\n' % item for item in settings.items())
        result = self.shell(chain + assign + 'proxy_firewall\necho "exit=$?"\n')
        return result.stdout.strip()

    def test_wireguard_mode_lets_the_proxy_out_only_through_the_tunnel_interface(self):
        self.assertEqual(self.firewall(MODE='wireguard'), 'exit=0')
        for family in ('iptables', 'ip6tables'):
            rules = self.rules(family)
            self.assertIn(rules[0], ('-N WARP_PROXY_OUT',), 'цепочка создаётся или очищается первой')
            self.assertEqual(rules[-2:], ['-A WARP_PROXY_OUT -o wgcf-profile -j RETURN', '-A WARP_PROXY_OUT -j REJECT'])
            self.assertFalse([rule for rule in rules if '--dport 443' in rule])

    def test_masque_mode_lets_the_proxy_out_only_to_the_endpoint(self):
        for proto in ('udp', 'tcp'):
            with self.subTest(proto=proto):
                self.assertEqual(self.firewall(MODE='masque', MASQUE_ENDPOINT='162.159.198.2', MASQUE_PROTO=proto), 'exit=0')
                rules = self.rules('iptables')
                self.assertEqual(rules[-2:], ['-A WARP_PROXY_OUT -d 162.159.198.2 -p %s --dport 443 -j RETURN' % proto, '-A WARP_PROXY_OUT -j REJECT'])
                self.assertFalse([rule for rule in rules if '-o wgcf-profile' in rule], 'интерфейса туннеля в этом режиме нет')
                rejects = [index for index, rule in enumerate(rules) if rule.endswith('-j REJECT') and ' -d ' in rule]
                self.assertEqual(len(rejects), 10, 'частные и служебные сети запрещены')
                self.assertLess(max(rejects), len(rules) - 2, 'запрет частных сетей стоит раньше разрешения узла')
                returns = [rule for rule in rules if rule.endswith('-j RETURN')]
                self.assertEqual(len(returns), 3, 'кроме узла разрешены только ответы клиентам SOCKS')
                six = self.rules('ip6tables')
                self.assertEqual(six[-1], '-A WARP_PROXY_OUT -j REJECT')
                self.assertEqual(len([rule for rule in six if rule.endswith('-j RETURN')]), 2, 'по IPv6 узел не разрешён: всё прикладное запрещено')

    def test_masque_mode_without_a_known_endpoint_lets_nothing_out(self):
        self.assertEqual(self.firewall(MODE='masque'), 'exit=0')
        self.assertEqual([rule for rule in self.rules('iptables') if '--dport 443' in rule or '-o wgcf' in rule], [])
        self.assertEqual(self.rules('iptables')[-1], '-A WARP_PROXY_OUT -j REJECT')

    def test_chain_is_never_rebuilt_under_a_running_proxy(self):
        self.assertEqual(self.firewall(MODE='masque', MASQUE_ENDPOINT='162.159.198.2', MS_PID='$$'), 'exit=1')
        self.assertEqual(self.rules('iptables') + self.rules('ip6tables'), [], 'пока цепочка пуста, она пропускает всё')

    def masque_up(self, account=True, alpn='h3', **fail):
        self.log.write_text('')
        fake = self.dir / 'masque.sh'
        fake.write_text('''#!/bin/sh
echo "masque $*" >> "$LOG"
case "$1" in
  exists) [ -e "$STATE/account" ] ;;
  register) [ "$FAIL" != register ] || exit 1; touch "$STATE/account"; echo VPNBOT_MASQUE_REGISTERED ;;
  commit) : ;;
  endpoint) [ "$FAIL" != endpoint ] || exit 1; echo 162.159.198.2 ;;
  config) [ "$FAIL" != config ] || exit 1; echo '{"private":"key"}' ;;
esac
''')
        if account:
            (self.dir / 'account').write_text('')
        functions = self.piece('MASQUE_READY=0\nMASQUE_ACCOUNT=""', 'socks_running() {')
        script = '''
MODE=masque; ALPN=%s; MASQUE_ENDPOINT=""; MASQUE_PROTO=udp
proxy_firewall() { echo "firewall $MODE $MASQUE_ENDPOINT $MASQUE_PROTO" >> "$LOG"; }
chown() { echo "chown $*" >> "$LOG"; }
tunnel_up() { return 1; }
date() { echo "$NOW"; }
''' % alpn + functions + '''
link_up; echo "up=$? ready=$MASQUE_READY"
link_ready && echo link-ready || echo link-not-ready
mode_mark; cat "%s/run/warp-mode"
link_down; echo "after-down ready=$MASQUE_READY"
''' % self.dir
        result = self.shell(script, STATE=str(self.dir), FAIL=fail.get('fail', ''), NOW=str(fail.get('now', 1000000)))
        return result.stdout.splitlines(), self.log.read_text().splitlines()

    def test_masque_link_validates_the_config_with_the_core_and_protects_the_key(self):
        out, log = self.masque_up()
        self.assertEqual(out[:3] + out[-1:], ['[warp] MASQUE: endpoint 162.159.198.2 udp/443 (h3)', 'up=0 ready=1', 'link-ready', 'after-down ready=0'])
        self.assertIn('masque h3', out)
        self.assertNotIn('masque register', log, 'готовое устройство заново не регистрируется')
        config = str(self.dir / 'run/warp-socks-masque.new.json')
        self.assertIn('core run -test -config ' + config, log, 'имя кончается на .json: ядро узнаёт формат по расширению')
        self.assertIn('chown root:warp-proxy ' + config, log)
        self.assertEqual(log.index('firewall masque 162.159.198.2 udp') > log.index('core run -test -config ' + config), True, 'фильтр ставится после проверки конфига')
        self.assertFalse((self.dir / 'run/warp-socks-masque.json').exists(), 'после выхода из режима конфиг с ключом убран')
        self.assertIn('wg-quick down /nonexistent/wgcf-profile.conf', log)

    def test_masque_link_writes_a_config_only_the_proxy_can_read(self):
        functions = self.piece('MASQUE_READY=0\nMASQUE_ACCOUNT=""', '# Общие для обоих режимов')
        fake = self.dir / 'masque.sh'
        fake.write_text('#!/bin/sh\ncase "$1" in exists) exit 0 ;; endpoint) echo 162.159.198.2 ;; config) echo "{}" ;; esac\n')
        script = 'MODE=masque; ALPN=h2\nproxy_firewall() { :; }\nchown() { :; }\n' + functions + 'masque_up; echo "up=$? proto=$MASQUE_PROTO"\n'
        result = self.shell(script)
        self.assertEqual(result.stdout.splitlines()[-1], 'up=0 proto=tcp', 'HTTP/2 — это TCP 443')
        config = self.dir / 'run/warp-socks-masque.json'
        self.assertEqual(oct(config.stat().st_mode & 0o777), '0o640')

    def test_first_start_in_masque_mode_registers_the_device(self):
        out, log = self.masque_up(account=False)
        self.assertIn('up=0 ready=1', out)
        self.assertEqual([line for line in log if line.startswith('masque ')][:3], ['masque exists', 'masque register', 'masque commit'])

    def test_masque_link_fails_closed(self):
        for fail, registered in (('register', False), ('endpoint', True), ('config', True), ('core', True)):
            with self.subTest(fail=fail):
                for name in ('account',):
                    (self.dir / name).unlink(missing_ok=True)
                out, log = self.masque_up(account=registered, fail=fail)
                self.assertIn('up=1 ready=0', out)
                self.assertIn('link-not-ready', out)
                self.assertFalse([line for line in log if line.startswith('firewall ')], 'узел не разрешается, пока режим не готов')
                self.assertFalse((self.dir / 'run/warp-socks-masque.new.json').exists() and fail == 'core')

    def test_failed_device_registration_is_retried_with_a_growing_pause(self):
        retry = self.dir / 'warp/masque.retry'

        def attempt(now, fail='register'):
            out, log = self.masque_up(account=False, fail=fail, now=now)
            return out, log.count('masque register')

        out, tried = attempt(1000000)
        self.assertEqual((tried, retry.read_text()), (1, '1 1000000\n'))
        self.assertIn('[warp] MASQUE: registration failed, next attempt in 2 min', out)
        self.assertIn('up=1 ready=0', out)
        out, tried = attempt(1000119)
        self.assertEqual((tried, retry.read_text()), (0, '1 1000000\n'), 'до конца паузы Cloudflare не трогаем')
        self.assertIn('[warp] MASQUE: no device, next registration attempt in 1 min', out)
        self.assertIn('up=1 ready=0', out)
        self.assertEqual((attempt(1000120)[1], retry.read_text()), (1, '2 1000120\n'), 'пауза вышла — вторая попытка')
        self.assertEqual(attempt(1000120 + 239)[1], 0, 'после второго отказа пауза вдвое длиннее')
        self.assertEqual((attempt(1000120 + 240)[1], retry.read_text()), (1, '3 1000360\n'))
        retry.write_text('40 1000000\n')
        self.assertEqual(attempt(1000000 + 21599)[1], 0, 'пауза растёт не дальше шести часов')
        self.assertEqual(attempt(1000000 + 21600)[1], 1)
        for mark, label in (('3 2000000\n', 'часы ушли назад'), ('x y\n', 'повреждённая отметка'), ('', 'пустая отметка'),
                            ('08 0999990\n', 'числа с ведущим нулём')):
            with self.subTest(label):
                retry.write_text(mark)
                self.assertEqual(attempt(1000000)[1], 1)
        retry.write_text('5 999999\n')
        (self.dir / 'account').write_text('')
        out, tried = attempt(1000000, fail='')
        self.assertEqual((tried, retry.exists()), (0, False), 'устройство уже есть (его завёл бот): отметка снята, пауза не действует')
        (self.dir / 'account').unlink()
        retry.write_text('1 1\n')
        out, tried = attempt(1000000, fail='')
        self.assertIn('up=0 ready=1', out)
        self.assertEqual((tried, retry.exists()), (1, False), 'удачная регистрация снимает отметку')

    def test_watchdog_does_not_restart_the_container_while_waiting_to_register(self):
        loop = self.source[self.source.index('while true; do\n    wait_tick'):]
        failed = loop[loop.index('if ! link_ready; then'):loop.index('if ! socks_running; then')]
        self.assertLess(failed.index('[ "$MASQUE_WAITING" = 1 ]; then\n                continue'), failed.index('BOUNCES=$((BOUNCES + 1))'))

    def socks_start(self, mode, ready):
        self.log.write_text('')
        (self.dir / 'run/warp-mode').unlink(missing_ok=True)
        functions = self.piece('mode_name() {', '# Отпечаток аккаунта MASQUE') + self.piece('socks_running() {', 'socks_stop() {')
        script = '''
MODE=%s; ALPN=h3; MASQUE_READY=%s; MS_PID=""; PROXY_FIREWALL_READY=1
wg() { echo "wg $*" >> "$LOG"; echo 0xca6c; }
su() { echo "su $*" >> "$LOG"; }
# Правила с меткой ещё нет: проверка -C отвечает «нет», и скрипт обязан его вставить.
iptables() { echo "iptables $*" >> "$LOG"; case "$*" in '-C WARP_PROXY_OUT -p udp -m mark '*) return 1;; esac; }
ip6tables() { echo "ip6tables $*" >> "$LOG"; case "$*" in '-C WARP_PROXY_OUT -p udp -m mark '*) return 1;; esac; }
''' % (mode, ready) + functions + 'socks_start; echo "start=$?"; cat "%s/run/warp-mode" 2>/dev/null\n' % self.dir
        return self.shell(script).stdout.splitlines(), self.log.read_text()

    def test_proxy_start_depends_on_the_mode(self):
        out, log = self.socks_start('masque', 1)
        self.assertEqual(out[-2:], ['start=0', 'masque h3'])
        self.assertIn('exec warp-socks run -config %s/run/warp-socks-masque.json warp-proxy' % self.dir, log)
        self.assertNotIn('wg show', log, 'метка WireGuard в режиме MASQUE не нужна')
        self.assertNotIn('--mark', log)
        out, log = self.socks_start('masque', 0)
        self.assertEqual(out[-1], 'start=1', 'без готового режима прокси не запускается')
        self.assertNotIn('su ', log)
        out, log = self.socks_start('wireguard', 0)
        self.assertEqual(out[-2:], ['start=0', 'wireguard'])
        self.assertIn('-I WARP_PROXY_OUT 1 -p udp -m mark --mark 0xca6c -j RETURN', log)
        self.assertIn('exec warp-socks run -config %s/run/warp-socks.json warp-proxy' % self.dir, log)

    def mode(self, pac, script=True):
        (self.dir / 'pac.json').write_text(pac)
        if script:
            (self.dir / 'masque.sh').write_text('')
        else:
            (self.dir / 'masque.sh').unlink(missing_ok=True)
        functions = self.piece('warp_mode() {', 'MODE=$(warp_mode)')
        return self.shell(functions + 'echo "$(warp_mode) $(masque_alpn)"\n').stdout.strip()

    @unittest.skipUnless(shutil.which('jq'), 'нужен jq: им скрипт читает pac.json')
    def test_mode_comes_from_pac_json_and_needs_the_mode_script(self):
        self.assertEqual(self.mode('{}'), 'wireguard h3')
        self.assertEqual(self.mode('{"warp_mode":"masque"}'), 'masque h3')
        self.assertEqual(self.mode('{"warp_mode":"masque","warp_masque_h2":1}'), 'masque h2')
        self.assertEqual(self.mode('{"warp_mode":"something"}'), 'wireguard h3')
        self.assertEqual(self.mode('{broken'), 'wireguard h3', 'повреждённый pac.json — прежний режим WireGuard')
        self.assertEqual(self.mode('{"warp_mode":"masque"}', script=False), 'wireguard h3', 'контейнер без скрипта режима остаётся на WireGuard')

    def test_watchdog_switches_modes_with_the_proxy_down_first(self):
        loop = self.source[self.source.index('while true; do\n    wait_tick'):]
        switch = loop[loop.index('want_mode=$(warp_mode)'):loop.index('# Выключен намеренно')]
        order = [switch.index(step) for step in ('socks_stop', 'link_down', 'MODE=$want_mode', 'proxy_firewall')]
        self.assertEqual(order, sorted(order), 'прокси гасится до снятия туннеля и перестройки фильтра')
        self.assertLess(loop.index('want_mode=$(warp_mode)'), loop.index('if warp_disabled; then'))
        self.assertIn('[ "$(masque_account)" != "$MASQUE_ACCOUNT" ]', switch, 'смена устройства MASQUE тоже пересобирает прокси')
        self.assertIn('if ! link_ready; then\n        if link_up; then', loop)
        self.assertNotIn('warp_up; then', loop, 'сторож пользуется общими функциями режима')

    def test_wireguard_account_is_not_required_to_start_in_masque_mode(self):
        self.assertIn('if [ "$MODE" = wireguard ]; then\n    wg_bootstrap\nfi', self.source)
        self.assertEqual(self.source.count('wg_bootstrap'), 3, 'функцию вызывают только запуск в режиме WireGuard и первое переключение на него')
        body = self.source[self.source.index('wg_bootstrap() {'):self.source.index('if [ "$MODE" = wireguard ]; then\n    wg_bootstrap')]
        self.assertEqual(body.count('|| return 1'), 3, 'сбой регистрации, генерации и правки профиля возвращается вызывающему')
        self.assertIn('[ -f "$WGCF_CONF" ] || wg_bootstrap || return 1', self.source, 'аккаунт заводится при первом переключении на WireGuard')
