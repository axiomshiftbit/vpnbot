"""WARP через MASQUE: скрипт режима контейнера wp.

Скрипт исполняется по-настоящему, подменены только обращения наружу: wgcf
(регистрация в Cloudflare), curl (привязка ключа MASQUE и trace), ядро прокси
и wg. Ключи создаёт настоящий openssl, JSON собирает настоящий jq. Если задан
VLESS_TEST_XRAY (ядро 26.10.10+), собранный конфиг дополнительно проверяет
само ядро.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/warp_masque.sh'
TOOLS = all(shutil.which(tool) for tool in ('jq', 'openssl', 'sh', 'awk', 'sha256sum', 'base64'))

FAKE = r'''#!/bin/sh
name=${0##*/}
printf '%s %s\n' "$name" "$*" >> "$WARP_TEST_ROOT/calls"
arg_after() { want=$1; shift; while [ $# -gt 1 ]; do if [ "$1" = "$want" ]; then printf '%s' "$2"; return 0; fi; shift; done; return 1; }
case "$name" in
  sleep) exit 0 ;;
  wg)
    [ "$1 $2 $3" = "show wgcf-profile fwmark" ] || exit 1
    [ -n "${WARP_TEST_FWMARK:-}" ] || exit 1
    echo "$WARP_TEST_FWMARK" ;;
  wgcf)
    config=$(arg_after --config "$@") || exit 2
    case "$1" in
      register)
        [ "${WARP_TEST_FAIL:-}" != register ] || exit 1
        [ ! -s "$config" ] || exit 1
        n=$(cat "$WARP_TEST_ROOT/devices" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$WARP_TEST_ROOT/devices"
        printf "access_token = 'token-%s-secret'\ndevice_id = 'device-%s'\nlicense_key = 'free-license'\nprivate_key = 'wg-private'\n" "$n" "$n" > "$config" ;;
      update)
        [ "${WARP_TEST_FAIL:-}" != update ] || exit 1
        grep -q '^license_key' "$config" || exit 1 ;;
      *) exit 2 ;;
    esac ;;
  warp-socks|warp-masque-check)
    case "$1" in
      version) echo "Xray ${WARP_TEST_CORE:-26.10.10} (Xray, Penetrates Everything.) test" ;;
      run)
        config=$(arg_after -config "$@") || exit 2
        case "$config" in *.json) ;; *) exit 3 ;; esac
        jq -e . "$config" >/dev/null || exit 4
        if [ "$2" = -test ]; then
          [ "${WARP_TEST_FAIL:-}" != core ] || exit 1
          exit 0
        fi
        cp "$config" "$WARP_TEST_ROOT/running-$name.json"
        exec /bin/sleep 30 ;;
    esac ;;
  curl)
    url=''; for a in "$@"; do case "$a" in http*) url=$a ;; esac; done
    case "$url" in
      *cdn-cgi/trace)
        # Настоящий запрос проходит только через уже запущенный прокси.
        i=0; while [ -e "$WARP_RUN_DIR/warp-masque-check" ] && [ ! -e "$WARP_TEST_ROOT/running-warp-masque-check.json" ] && [ "$i" -lt 60 ]; do /bin/sleep 0.05; i=$((i + 1)); done
        [ "${WARP_TEST_TRACE:-on}" = none ] || printf 'h=x\nwarp=%s\n' "${WARP_TEST_TRACE:-on}"
        exit 0 ;;
    esac
    cat > "$WARP_TEST_ROOT/curl-stdin"
    out=$(arg_after -o "$@"); body=$(arg_after -d "$@")
    printf '%s' "$body" > "$WARP_TEST_ROOT/patch-body.json"
    printf '%s' "$url" > "$WARP_TEST_ROOT/patch-url"
    key=$(printf '%s' "$body" | jq -r .key)
    mode=${WARP_TEST_API:-ok}
    [ "$mode" != network ] || exit 7
    endpoint='162.159.198.2:0'; tunnel=masque; public=$(cat "$WARP_TEST_ROOT/endpoint.pub.pem"); code=200
    case "$mode" in
      private) endpoint='10.10.0.8:0' ;;
      garbage) endpoint='1.2.3.4; reboot:0' ;;
      wireguard) tunnel=wireguard ;;
      otherkey) key='AAAA' ;;
      nopublic) public='not a key' ;;
      http500) code=500 ;;
    esac
    if [ "$mode" = nojson ]; then printf 'Not Found' > "$out"; else
    jq -n --arg key "$key" --arg tunnel "$tunnel" --arg endpoint "$endpoint" --arg public "$public" '{
      id: "device-xyz-0123456789", key: $key, key_type: "secp256r1", tunnel_type: $tunnel, warp_enabled: true,
      account: {account_type: "free", warp_plus: true, license: "LICENSE-FROM-CLOUDFLARE"},
      config: {peers: [{public_key: $public, endpoint: {v4: $endpoint, v6: "[2606:4700:103::2]:0", host: "engage.cloudflareclient.com:2408", ports: [443]}}],
               interface: {addresses: {v4: "172.16.0.2", v6: "2606:4700:110:8a36::2"}}}}' > "$out"
    fi
    printf '%s' "$code" ;;
esac
'''


@unittest.skipUnless(TOOLS, 'нужны jq и openssl')
class WarpMasqueScriptTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / 'bin').mkdir()
        (self.root / 'run').mkdir()
        for name in ('wgcf', 'curl', 'warp-socks', 'wg', 'sleep', 'iptables'):
            path = self.root / 'bin' / name
            path.write_text(FAKE)
            path.chmod(0o700)
        subprocess.run('openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl pkey -pubout -out '
                       + str(self.root / 'endpoint.pub.pem') + ' 2>/dev/null', shell=True, check=True)
        (self.root / 'pac.json').write_text('{}')
        self.dir = self.root / 'warp/masque'
        (self.root / 'warp').mkdir()

    def tearDown(self):
        subprocess.run(['pkill', '-f', str(self.root)], capture_output=True)
        self.tmp.cleanup()

    def run_script(self, *args, **env):
        environ = dict(os.environ, PATH=str(self.root / 'bin') + ':' + os.environ['PATH'], WARP_TEST_ROOT=str(self.root),
                       WARP_MASQUE_DIR=str(self.dir), WARP_PAC=str(self.root / 'pac.json'), WARP_RUN_DIR=str(self.root / 'run'))
        environ.update({key: str(value) for key, value in env.items()})
        # Ввод закрыт: скрипт не должен ждать его ни при каких обстоятельствах.
        return subprocess.run(['sh', str(SCRIPT), *args], env=environ, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)

    def calls(self, tool):
        log = self.root / 'calls'
        return [line for line in (log.read_text().splitlines() if log.exists() else []) if line.startswith(tool + ' ')]

    def device(self):
        return json.loads((self.dir / 'device.json').read_text())

    def mode(self, path):
        return stat.S_IMODE(path.stat().st_mode)

    # ---- возможности образа --------------------------------------------------

    def test_supported_needs_every_tool_and_a_core_that_knows_warp(self):
        self.assertEqual(self.run_script('supported').stdout.strip(), 'ok')
        for core, expected in (('26.10.10', 'ok'), ('26.10.11', 'ok'), ('26.11.1', 'ok'), ('27.0.0', 'ok'),
                               ('26.9.30', 'core:26.9.30'), ('26.10.9', 'core:26.10.9'), ('25.12.31', 'core:25.12.31')):
            with self.subTest(core=core):
                result = self.run_script('supported', WARP_TEST_CORE=core)
                self.assertEqual((result.stdout.strip(), result.returncode == 0), (expected, expected == 'ok'))
        (self.root / 'bin/wgcf').unlink()
        result = self.run_script('supported')
        self.assertEqual((result.stdout.strip(), result.returncode), ('missing:wgcf', 1))
        self.assertEqual(self.run_script('register').returncode, 1, 'регистрация без нужных программ не начинается')

    # ---- регистрация ---------------------------------------------------------

    def test_registration_enrolls_a_p256_key_and_keeps_only_what_the_tunnel_needs(self):
        result = self.run_script('register')
        self.assertEqual((result.returncode, result.stdout.strip()), (0, 'VPNBOT_MASQUE_REGISTERED'), result.stderr)
        self.assertEqual(self.mode(self.dir), 0o700)
        for name in ('device.json', 'key.pem', 'wgcf-account.toml', 'license.sha256'):
            self.assertEqual(self.mode(self.dir / name), 0o600, name)
        self.assertFalse((self.dir / 'response.json').exists(), 'ответ Cloudflare с ключом лицензии не сохраняется')
        self.assertNotIn('LICENSE-FROM-CLOUDFLARE', ''.join(p.read_text() for p in self.dir.iterdir() if p.is_file()))

        key = subprocess.run(['openssl', 'pkey', '-in', str(self.dir / 'key.pem'), '-noout', '-text'], capture_output=True, text=True)
        self.assertIn('prime256v1', key.stdout)
        self.assertIn('BEGIN PRIVATE KEY', (self.dir / 'key.pem').read_text(), 'ключ в PKCS #8')
        public = subprocess.run(['openssl', 'pkey', '-in', str(self.dir / 'key.pem'), '-pubout', '-outform', 'DER'], capture_output=True).stdout
        body = json.loads((self.root / 'patch-body.json').read_text())
        self.assertEqual(body, {'key': base64.b64encode(public).decode(), 'key_type': 'secp256r1', 'tunnel_type': 'masque', 'warp_enabled': True})
        self.assertEqual((self.root / 'patch-url').read_text(), 'https://api.cloudflareclient.com/v0a5641/reg/device-1')

        device = self.device()
        self.assertEqual((device['endpoint_v4'], device['address_v4'], device['warp_plus']), ('162.159.198.2:0', '172.16.0.2', True))
        self.assertEqual(device['endpoint_public_key'], (self.root / 'endpoint.pub.pem').read_text().strip())
        self.assertEqual((self.dir / 'license.sha256').read_text().strip(), hashlib.sha256(b'').hexdigest())
        self.assertTrue((self.dir / '.pending').exists(), 'регистрация ждёт подтверждения')

    def test_device_token_never_appears_in_process_arguments(self):
        self.run_script('register')
        self.assertEqual((self.root / 'curl-stdin').read_text(), 'header = "Authorization: Bearer token-1-secret"\n')
        self.assertEqual(len(self.calls('curl')), 1)
        self.assertNotIn('token-1-secret', self.calls('curl')[0])
        self.assertIn('-K -', self.calls('curl')[0])
        for header in ('CF-Client-Version: a-6.38.9-5641', '1.1.1.1/6.38.9-5641 (Android 16.0.0)', 'Accept:'):
            self.assertIn(header, self.calls('curl')[0])

    def test_license_key_is_applied_through_wgcf_and_remembered(self):
        result = self.run_script('register', WARP_LICENSE_KEY='ABCD-1234-efgh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('license_key = "ABCD-1234-efgh"', (self.dir / 'wgcf-account.toml').read_text())
        self.assertEqual(len(self.calls('wgcf update')), 1)
        self.assertNotIn('ABCD-1234-efgh', '\n'.join(self.calls('wgcf')), 'ключ не передаётся в аргументах')
        self.assertEqual(self.run_script('current', WARP_LICENSE_KEY='ABCD-1234-efgh').returncode, 0)
        self.assertEqual(self.run_script('current', WARP_LICENSE_KEY='OTHER-KEY').returncode, 1, 'сменили ключ — аккаунт устарел')
        self.assertEqual(self.run_script('current', WARP_LICENSE_KEY='').returncode, 1)
        (self.root / 'pac.json').write_text(json.dumps({'warp': 'ABCD-1234-efgh'}))
        self.assertEqual(self.run_script('current').returncode, 0, 'без переменной ключ берётся из pac.json')

    def test_license_from_pac_json_is_used_by_container_start(self):
        (self.root / 'pac.json').write_text(json.dumps({'warp': 'FROM-PAC-1'}))
        self.assertEqual(self.run_script('register').returncode, 0)
        self.assertIn('license_key = "FROM-PAC-1"', (self.dir / 'wgcf-account.toml').read_text())
        self.assertEqual(self.run_script('current').returncode, 0)

    def test_rejected_license_is_fatal_for_the_admin_and_soft_for_container_start(self):
        strict = self.run_script('register', WARP_LICENSE_KEY='BAD-KEY', WARP_LICENSE_STRICT='1', WARP_TEST_FAIL='update')
        self.assertEqual((strict.returncode, strict.stderr.strip()), (1, 'license was not applied'))
        self.assertFalse(self.dir.exists() or Path(str(self.dir) + '.new').exists(), 'после отказа ничего не осталось')
        soft = self.run_script('register', WARP_LICENSE_KEY='BAD-KEY', WARP_TEST_FAIL='update')
        self.assertEqual(soft.returncode, 0, soft.stderr)
        self.assertIn('continuing free tier', soft.stderr)
        self.assertEqual(self.run_script('current', WARP_LICENSE_KEY='BAD-KEY').returncode, 1, 'бот увидит, что ключ не применён')
        self.assertEqual(self.run_script('exists').returncode, 0)

    def test_license_key_that_is_not_a_key_is_refused_before_any_request(self):
        for bad in ("abc'; reboot; '", 'two words', 'a/b', 'ключ'):
            with self.subTest(key=bad):
                result = self.run_script('register', WARP_LICENSE_KEY=bad)
                self.assertEqual((result.returncode, result.stderr.strip()), (1, 'bad license key'))
        self.assertEqual(self.calls('wgcf register'), [])

    def test_every_failure_leaves_the_previous_account_untouched(self):
        self.assertEqual(self.run_script('register').returncode, 0)
        self.run_script('commit')
        before = {p.name: p.read_bytes() for p in self.dir.iterdir()}
        cases = [({'WARP_TEST_FAIL': 'register'}, 'registration failed'), ({'WARP_TEST_API': 'http500'}, 'enrollment rejected: HTTP 500'),
                 ({'WARP_TEST_API': 'network'}, 'enrollment request failed'), ({'WARP_TEST_API': 'nojson'}, 'enrollment answer is not a MASQUE device'),
                 ({'WARP_TEST_API': 'wireguard'}, 'enrollment answer is not a MASQUE device'), ({'WARP_TEST_API': 'otherkey'}, 'enrollment answer is not a MASQUE device'),
                 ({'WARP_TEST_API': 'nopublic'}, 'endpoint key is not a public key'), ({'WARP_TEST_API': 'private'}, 'endpoint is not a public address'),
                 ({'WARP_TEST_API': 'garbage'}, 'endpoint is not a public address')]
        for env, message in cases:
            with self.subTest(**env):
                result = self.run_script('register', **env)
                self.assertEqual((result.returncode, result.stderr.strip().splitlines()[-1]), (1, message))
                self.assertEqual({p.name: p.read_bytes() for p in self.dir.iterdir()}, before)
                self.assertFalse(Path(str(self.dir) + '.new').exists() or Path(str(self.dir) + '.old').exists())
                self.assertNotIn('VPNBOT_MASQUE_REGISTERED', result.stdout)

    def test_new_registration_is_kept_apart_until_commit_and_can_be_rolled_back(self):
        self.run_script('register')
        self.run_script('commit')
        first = (self.dir / 'wgcf-account.toml').read_text()
        self.assertFalse((self.dir / '.pending').exists())
        self.assertEqual(self.run_script('rollback').returncode, 0)
        self.assertEqual((self.dir / 'wgcf-account.toml').read_text(), first, 'откат подтверждённого аккаунта ничего не делает')

        self.run_script('register')
        self.assertNotEqual((self.dir / 'wgcf-account.toml').read_text(), first)
        self.assertEqual((Path(str(self.dir) + '.old') / 'wgcf-account.toml').read_text(), first)
        self.run_script('rollback')
        self.assertEqual((self.dir / 'wgcf-account.toml').read_text(), first, 'откат вернул прежнее устройство')
        self.assertFalse(Path(str(self.dir) + '.old').exists())

        self.run_script('register')
        second = (self.dir / 'wgcf-account.toml').read_text()
        self.run_script('commit')
        self.assertEqual(((self.dir / 'wgcf-account.toml').read_text(), Path(str(self.dir) + '.old').exists(), (self.dir / '.pending').exists()),
                         (second, False, False))

    def test_rollback_skips_a_registration_that_was_never_confirmed(self):
        self.run_script('register')
        self.run_script('commit')
        confirmed = (self.dir / 'wgcf-account.toml').read_text()
        # Бот оборвался между регистрацией и подтверждением…
        self.run_script('register')
        abandoned = (self.dir / 'wgcf-account.toml').read_text()
        # …а следующая смена ключа регистрирует ещё одно устройство и откатывается.
        self.run_script('register')
        self.assertNotIn((self.dir / 'wgcf-account.toml').read_text(), (confirmed, abandoned))
        self.assertEqual((Path(str(self.dir) + '.old') / 'wgcf-account.toml').read_text(), confirmed)
        self.run_script('rollback')
        self.assertEqual((self.dir / 'wgcf-account.toml').read_text(), confirmed, 'откат вернул подтверждённое устройство, а не брошенное')
        self.assertFalse((self.dir / '.pending').exists() or Path(str(self.dir) + '.old').exists())

    def test_rollback_of_the_very_first_registration_leaves_no_account(self):
        self.run_script('register')
        self.run_script('rollback')
        self.assertFalse(self.dir.exists())
        self.assertEqual(self.run_script('exists').returncode, 1)
        self.assertEqual(self.run_script('status').stdout.strip(), '{}')

    # ---- конфиг прокси и адрес узла -----------------------------------------

    def config(self, *args, **env):
        result = self.run_script('config', *args, **env)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_proxy_config_goes_to_warp_over_masque_and_nowhere_else(self):
        self.run_script('register')
        config = self.config('1080', 'h3')
        self.assertEqual(config['inbounds'], [{'listen': '0.0.0.0', 'port': 1080, 'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True}}])
        self.assertEqual(len(config['outbounds']), 1, 'единственный выход — туннель: запасного прямого нет')
        outbound = config['outbounds'][0]
        self.assertEqual((outbound['protocol'], outbound['settings']), ('masque', {'address': '162.159.198.2', 'port': 443, 'remoteDNS': ['1.1.1.1', '1.0.0.1']}))
        stream = outbound['streamSettings']
        self.assertEqual((stream['method'], stream['security'], stream['tlsSettings']), ('masque', 'tls', {'serverName': 'consumer-masque.cloudflareclient.com'}))
        self.assertNotIn('sockopt', stream)
        warp = stream['masqueSettings']['warp']
        self.assertEqual(warp['privateKey'], (self.dir / 'key.pem').read_text())
        self.assertEqual(warp['publicKey'], (self.root / 'endpoint.pub.pem').read_text().strip())
        self.assertEqual(warp['address'], ['172.16.0.2/32'], 'внутри туннеля только IPv4, как и в режиме WireGuard')
        self.assertNotIn('routing', config)

    def test_http2_transport_fwmark_and_listen_address(self):
        self.run_script('register')
        h2 = self.config('1081', 'h2', '51820', '127.0.0.1')
        stream = h2['outbounds'][0]['streamSettings']
        self.assertEqual(stream['tlsSettings'], {'serverName': 'consumer-masque.cloudflareclient.com', 'alpn': ['h2']})
        self.assertEqual(stream['sockopt'], {'mark': 51820})
        self.assertEqual((h2['inbounds'][0]['listen'], h2['inbounds'][0]['port']), ('127.0.0.1', 1081))
        for args in (['abc'], ['1080', 'h3', '0x10'], ['1080; id']):
            self.assertEqual(self.run_script('config', *args).returncode, 1, args)

    def test_config_needs_an_account(self):
        result = self.run_script('config', '1080')
        self.assertEqual((result.returncode, result.stdout), (1, ''))

    def test_endpoint_is_printed_only_when_it_is_a_public_ipv4(self):
        self.run_script('register')
        self.assertEqual(self.run_script('endpoint').stdout.strip(), '162.159.198.2')
        device = self.device()
        for bad in ('10.10.0.13:0', '127.0.0.1:0', '192.168.1.1:0', '172.16.0.9:0', '169.254.1.1:0', '100.64.0.1:0', '0.0.0.0:0', '224.0.0.1:0',
                    '198.18.0.1:0', '1.2.3:0', '1.2.3.4.5:0', '256.1.1.1:0', '1.2.3.4 -j ACCEPT:0', '$(id):0', 'example.org:0', '[2606:4700::1]:0', ''):
            with self.subTest(endpoint=bad):
                device['endpoint_v4'] = bad
                (self.dir / 'device.json').write_text(json.dumps(device))
                result = self.run_script('endpoint')
                self.assertEqual((result.returncode, result.stdout), (1, ''))
                self.assertEqual(self.run_script('config', '1080').returncode, 1, 'и конфиг с таким узлом не собирается')
        # Соседние с запрещёнными диапазонами адреса остаются обычными публичными.
        for good in ('162.159.198.1:0', '8.8.8.8', '172.32.0.1:443', '100.63.255.255:0', '192.169.0.1:0'):
            device['endpoint_v4'] = good
            (self.dir / 'device.json').write_text(json.dumps(device))
            self.assertEqual(self.run_script('endpoint').stdout.strip(), good.split(':')[0])

    @unittest.skipUnless(os.environ.get('VLESS_TEST_XRAY'), 'нужен VLESS_TEST_XRAY — ядро Xray 26.10.10+')
    def test_real_core_accepts_both_transports(self):
        self.run_script('register')
        for alpn in ('h3', 'h2'):
            path = self.root / ('real-' + alpn + '.json')
            path.write_text(json.dumps(self.config('1080', alpn)))
            result = subprocess.run([os.environ['VLESS_TEST_XRAY'], 'run', '-test', '-config', str(path)], capture_output=True, text=True, timeout=30)
            self.assertIn('Configuration OK', result.stdout + result.stderr, alpn)

    # ---- пробное подключение -------------------------------------------------

    def test_trial_connection_uses_its_own_process_and_cleans_up(self):
        self.run_script('register')
        result = self.run_script('check', 'h3')
        self.assertEqual(result.returncode, 0, result.stderr)
        running = json.loads((self.root / 'running-warp-masque-check.json').read_text())
        self.assertEqual((running['inbounds'][0]['listen'], running['inbounds'][0]['port']), ('127.0.0.1', 1081), 'только петля')
        self.assertNotIn('sockopt', running['outbounds'][0]['streamSettings'], 'WireGuard не поднят — метка не нужна')
        self.assertFalse((self.root / 'running-warp-socks.json').exists(), 'основной прокси не запускался')
        self.assertEqual(list((self.root / 'run').iterdir()), [], 'конфиг с ключом и ссылка убраны')
        self.assertIn('socks5h://127.0.0.1:1081', '\n'.join(self.calls('curl')))

    def test_trial_connection_bypasses_a_running_wireguard_tunnel(self):
        self.run_script('register')
        self.assertEqual(self.run_script('check', 'h2', WARP_TEST_FWMARK='0xca6c').returncode, 0)
        stream = json.loads((self.root / 'running-warp-masque-check.json').read_text())['outbounds'][0]['streamSettings']
        self.assertEqual((stream['sockopt'], stream['tlsSettings']['alpn']), ({'mark': 51820}, ['h2']))
        # Ответы узла по TCP wg-quick не помечает: при строгом rp_filter без
        # своего правила проба HTTP/2 отказывала бы при рабочем узле.
        rule = 'PREROUTING ! -i wgcf-profile -p tcp -s 162.159.198.2 --sport 443 -j MARK --set-mark 51820'
        self.assertEqual(self.calls('iptables'), ['iptables -t mangle -I ' + rule, 'iptables -t mangle -D ' + rule],
                         'правило ставится на время пробы и убирается')
        (self.root / 'calls').unlink()
        self.assertEqual(self.run_script('check', 'h3', WARP_TEST_FWMARK='0xca6c').returncode, 0)
        self.assertEqual(self.calls('iptables'), [], 'ответам UDP метку возвращает сам wg-quick')
        self.assertEqual(self.run_script('check', 'h2', WARP_TEST_FWMARK='off').returncode, 0, 'метка off — туннеля нет')
        self.assertEqual(self.calls('iptables'), [], 'без туннеля WireGuard помечать нечего')

    def test_trial_connection_fails_without_a_warp_answer(self):
        self.run_script('register')
        for trace in ('off', 'none'):
            with self.subTest(trace=trace):
                self.assertEqual(self.run_script('check', 'h3', WARP_TEST_TRACE=trace).returncode, 1)
                self.assertEqual(list((self.root / 'run').iterdir()), [])
        self.assertEqual(self.run_script('check', 'h3', WARP_TEST_FAIL='core').returncode, 1, 'конфиг, отвергнутый ядром')
        self.assertEqual(self.run_script('check', 'h3', WARP_TEST_TRACE='plus').returncode, 0, 'WARP+ тоже ответ WARP')

    def test_trial_connection_needs_an_account(self):
        self.assertEqual(self.run_script('check').returncode, 1)

    # ---- сведения для меню ---------------------------------------------------

    def test_status_has_no_secrets(self):
        self.run_script('register')
        status = json.loads(self.run_script('status').stdout)
        self.assertEqual(set(status), {'id', 'endpoint_v4', 'address_v4', 'account_type', 'warp_plus', 'registered'})
        self.assertEqual(status['id'], 'device-x', 'только начало идентификатора')
        text = self.run_script('status').stdout
        for secret in ('PRIVATE', 'token', 'BEGIN'):
            self.assertNotIn(secret, text)

    def test_unknown_command_is_an_error(self):
        result = self.run_script('reboot')
        self.assertEqual(result.returncode, 1)
        self.assertIn('usage:', result.stderr)


class WarpMasqueStaticTest(unittest.TestCase):
    def test_script_follows_the_wgcf_api_contract_pinned_in_the_image(self):
        script = SCRIPT.read_text()
        version = dict(line.split('=', 1) for line in (ROOT / '.env').read_text().splitlines() if line.startswith('WGCF_VERSION='))['WGCF_VERSION']
        self.assertIn('wgcf\n# ' + version, script.replace('взяты из wgcf\n# ', 'wgcf\n# '), 'при обновлении wgcf сверить версию API и заголовки в скрипте')

    def test_compose_mounts_the_script_read_only_and_the_image_has_its_tools(self):
        compose = (ROOT / 'docker-compose.yml').read_text()
        self.assertIn('- ./scripts/warp_masque.sh:/warp_masque.sh:ro', compose)
        dockerfile = (ROOT / 'dockerfile/wireguard.dockerfile').read_text()
        self.assertIn('        openssl \\\n', dockerfile)
        self.assertIn('command -v openssl;', dockerfile)
        self.assertIn("'./transport/internet/masque/... ./proxy/masque/...'", dockerfile, 'сборка прогоняет тесты MASQUE из ядра')


if __name__ == '__main__':
    unittest.main()
