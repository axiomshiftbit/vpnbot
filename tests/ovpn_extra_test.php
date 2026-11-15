<?php
// OpenVPN: перевыпуск сертификата, udp+tcp, выборочная маршрутизация, MSS, учёт трафика и лимит, меню и справка.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

class OvpnLabBot extends Bot
{
    public string $t_root;
    public array $t_ssh = []; public array $t_mgmt = []; public array $t_messages = []; public array $t_files = [];
    public array $t_buttons = []; public array $t_menus = []; public array $t_prompt = []; public int $t_restarts = 0;
    public bool $t_revokeOk = true; public bool $t_issueOk = true; public bool $t_busy = false; public bool $t_module = true; public $t_admin = 99;
    public function __construct(string $conf)
    {
        $this->input = ['chat' => 1, 'from' => 7, 'message_id' => 5, 'callback_id' => 'cb', 'username' => 'admin', 'callback' => '', 'message' => ''];
        $this->language = 'ru';
        require __DIR__ . '/../app/i18n.php';
        $this->i18n = $i;
        $this->t_root = sys_get_temp_dir() . '/vpnbot-ovpn-' . bin2hex(random_bytes(6));
        foreach (['pki/issued', 'pki/private', 'ccd'] as $dir) mkdir("$this->t_root/$dir", 0700, true);
        file_put_contents("$this->t_root/server.conf", $conf);
        foreach (['pki/ca.crt' => 'CA', 'pki/private/ca.key' => 'CAKEY', 'pki/ta.key' => 'TA', 'pki/crl.pem' => 'CRL',
            'pki/issued/server.crt' => 'S', 'pki/private/server.key' => 'SK'] as $file => $body) file_put_contents("$this->t_root/$file", $body);
    }
    public function __destruct() { if (is_dir($this->t_root)) exec('rm -rf ' . escapeshellarg($this->t_root)); }
    public function ovpnPaths()
    {
        $r = $this->t_root;
        return ['pki' => "$r/pki", 'issued' => "$r/pki/issued", 'priv' => "$r/pki/private", 'ta' => "$r/pki/ta.key", 'ca' => "$r/pki/ca.crt",
            'srv' => "$r/server.conf", 'ccd' => "$r/ccd", 'status' => "$r/openvpn-status.log", 'log' => "$r/openvpn.log", 'conn' => "$r/conn.log"];
    }
    public function addClient(string $name, string $cert = 'CERT'): void
    {
        file_put_contents("$this->t_root/pki/issued/$name.crt", "-----BEGIN CERTIFICATE-----\n$cert\n-----END CERTIFICATE-----\n");
        file_put_contents("$this->t_root/pki/private/$name.key", "KEY-$cert\n");
    }
    public function status(array $sessions): void
    {
        $rows = ["TITLE,OpenVPN 2.7.8", 'HEADER,CLIENT_LIST,Common Name,Real Address'];
        foreach ($sessions as $cn => [$rx, $tx, $since, $cid]) $rows[] = "CLIENT_LIST,$cn,203.0.113.5:1000,10.8.0.2,,$rx,$tx,$since,1760000000,UNDEF,$cid,0,AES-256-GCM";
        file_put_contents("$this->t_root/openvpn-status.log", implode("\n", $rows) . "\nEND\n");
    }
    public function conf(): string { return file_get_contents("$this->t_root/server.conf"); }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $this->t_busy && $name === 'ovpn-pki' ? $busy : $fn(); }
    public function ssh($cmd, $service = 'wg', $wait = true, $out = false)
    {
        $this->t_ssh[] = $cmd;
        if (str_contains($cmd, 'ovpn_migrate.sh')) {
            exec('sh ' . escapeshellarg(__DIR__ . '/../scripts/ovpn_migrate.sh') . ' ' . escapeshellarg("$this->t_root/server.conf") . ' 2>/dev/null');
            return '';
        }
        if (str_contains($cmd, 'revoke_ovpn_client.sh') && preg_match("~revoke_ovpn_client\\.sh '([^']+)'~", $cmd, $m)) {
            if (!$this->t_revokeOk) return '__VPNBOT_REVOKE_FAILED__';
            @unlink("$this->t_root/pki/issued/$m[1].crt"); @unlink("$this->t_root/pki/private/$m[1].key");
            return '__VPNBOT_REVOKED__';
        }
        if (str_contains($cmd, 'build-client-full') && preg_match("~build-client-full '([^']+)'~", $cmd, $m)) {
            if ($this->t_issueOk) $this->addClient($m[1], 'NEW');
            return '';
        }
        return str_contains($cmd, 'pgrep openvpn') ? '123' : '';
    }
    public function ovpnMgmt(array $cmds) { $this->t_mgmt[] = $cmds; return ''; }
    public function restartOvpn() { $this->t_restarts++; }
    public function getOvpnPort() { return 1194; }
    public function protocolModuleEnabled(string $key, ?array $pac = null): bool { return $this->t_module; }
    public function getDomain($a = false) { return 'vpn.example.org'; }
    public function getPacConf() { return []; }
    public function setEnvVar($key, $value) { $this->t_ssh[] = "env $key=$value"; }
    public function syncOvpnOverridePort() {}
    public function setUpstreamPortOvpn($port, $proto = null) { $this->t_ssh[] = 'upstream ' . self::ovpnUpstreamBlock((int) $port, $proto ? [$proto] : $this->ovpnListenProtos()); }
    protected function ovpnAdminChat() { return $this->t_admin; }
    public function menu($type = false, $arg = false, $return = false) { $this->t_menus[] = $type; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false, $entities = false, $forum = false) { $this->t_messages[] = [$chat, $text]; return ['ok' => true, 'result' => ['message_id' => 9]]; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->t_messages[] = [$chat, $text]; $this->t_buttons = $button ?: []; return ['ok' => true]; }
    public function sendFile($chat, $id_url_cFile, $caption = false, $to = false) { $this->t_files[] = $id_url_cFile; return ['ok' => true]; }
    public function answer($callback_id, $textNotify = false, $notify = false) { return ['ok' => true]; }
    public function stashReply($r, array $state) { $this->t_prompt = $state; }
    public function route(string $callback): void { $this->input['callback'] = $callback; $this->action(); }
    public function text(): string { return implode("\n", array_column($this->t_messages, 1)); }
}

$checks = 0;
function check(bool $condition, string $label): void { global $checks; $checks++; if (!$condition) { fwrite(STDERR, "FAIL: $label\n"); exit(1); } }
function buttonsOf(array $rows): array { $all = []; foreach ($rows as $row) foreach ($row as $button) $all[$button['callback_data']] = $button['text']; return $all; }
function block(string $conf, string $marker): ?string { return preg_match("~^#$marker\n(.*?)^#$marker$~sm", $conf, $m) ? $m[1] : null; }

// Конфиг нового сервера — ровно тот, что пишет start_ovpn.sh.
$start = file_get_contents(__DIR__ . '/../scripts/start_ovpn.sh');
check(preg_match('~cat > "\$SRV" <<EOF\n(.*?)\nEOF\n~s', $start, $m) === 1, 'server.conf template is found in start_ovpn.sh');
$fresh = strtr($m[1], ['$PORT' => '1194', '$PROTO' => 'udp4', '$PKI' => '/etc/openvpn/pki', '$NET' => '10.8.0.0', '$MASK' => '255.255.255.0']) . "\n";
// Конфиг старой установки: без новых маркеров, с повтором redirect-gateway.
$legacy = "port 1194\nproto udp4\ndev tun\nserver 10.8.0.0 255.255.255.0\npush \"redirect-gateway def1 bypass-dhcp\"\npush \"dhcp-option DNS 10.10.0.5\"\n"
    . "push \"redirect-gateway def1\"\nkeepalive 10 60\nexplicit-exit-notify 1\n#ovpn-isolation\n#ovpn-isolation\n#ovpn-winblockdns\n#ovpn-winblockdns\nstatus /etc/openvpn/openvpn-status.log 5\nstatus-version 2\nscript-security 2\nclient-connect /etc/openvpn/connect.sh\nclient-disconnect /etc/openvpn/connect.sh\n";

// --- шаблон и миграция
foreach (['ovpn-gateway', 'ovpn-routes', 'ovpn-mss', 'ovpn-dual', 'ovpn-isolation', 'ovpn-winblockdns'] as $marker) {
    check(substr_count($fresh, "#$marker\n") === 2, "fresh server.conf has the $marker block");
}
check(block($fresh, 'ovpn-gateway') === "push \"redirect-gateway def1 bypass-dhcp\"\n" && block($fresh, 'ovpn-dual') === '' && block($fresh, 'ovpn-mss') === '', 'fresh server: all traffic, one socket, default MSS');
$bot = new OvpnLabBot($fresh);
$bot->migrateOvpnServerConf();
check($bot->conf() === $fresh, 'migration leaves a fresh server.conf untouched');
$bot = new OvpnLabBot($legacy);
check($bot->isOvpnFullTunnel() && !$bot->isOvpnDual() && $bot->getOvpnMss() === 0 && $bot->getOvpnRoutes() === [], 'legacy config without markers reads as the old behaviour');
$bot->migrateOvpnServerConf();
$migrated = $bot->conf();
check(block($migrated, 'ovpn-gateway') === "push \"redirect-gateway def1 bypass-dhcp\"\n" && substr_count($migrated, 'redirect-gateway') === 1, 'migration wraps the gateway line in place and drops its duplicate');
check(strpos($migrated, '#ovpn-gateway') < strpos($migrated, 'dhcp-option DNS'), 'the gateway block stays where the line was');
$bot->migrateOvpnServerConf();
check($bot->conf() === $migrated, 'migration is idempotent');
$bot = new OvpnLabBot(str_replace(["push \"redirect-gateway def1 bypass-dhcp\"\n", "push \"redirect-gateway def1\"\n"], '', $legacy));
$bot->migrateOvpnServerConf();
check(block($bot->conf(), 'ovpn-gateway') === '' && !$bot->isOvpnFullTunnel(), 'a gateway line removed by hand is not brought back');

// --- весь трафик / выбранные сети
$bot = new OvpnLabBot($legacy);
$bot->toggleOvpnGateway();
check(block($bot->conf(), 'ovpn-gateway') === "push \"route 10.10.0.5 255.255.255.255\"\n" && !$bot->isOvpnFullTunnel(), 'split mode: no gateway push, DNS stays reachable (markers added on the fly)');
check($bot->t_restarts === 1 && str_contains($bot->text(), 'только DNS'), 'split mode without networks restarts and warns');
check(substr_count($bot->conf(), 'redirect-gateway') === 0, 'no stray gateway push survives the switch');
$bot->toggleOvpnGateway();
check($bot->isOvpnFullTunnel() && $bot->t_restarts === 2 && substr_count($bot->conf(), 'redirect-gateway') === 1, 'back to all traffic');

check(OvpnLabBot::ovpnParseRoutes("203.0.113.9/24, 198.51.100.7\n10.1.2.3/16;203.0.113.200/24") === [['203.0.113.0/24', '198.51.100.7/32', '10.1.0.0/16'], ''], 'networks are normalised and de-duplicated');
foreach (['0.0.0.0/0', '10.0.0.0/33', '999.1.1.1/24', '2001:db8::/32', 'example.org', '10.0.0.0/-1', '10.0.0/8', '10.0.0.0/8/9', "10.0.0.0/8\n\$(id)"] as $bad) {
    check(OvpnLabBot::ovpnParseRoutes($bad)[1] !== '', "rejected as a network: $bad");
}
$bot = new OvpnLabBot($fresh);
$bot->setOvpnRoutes();
check($bot->t_prompt['callback'] === 'saveOvpnRoutes' && str_contains($bot->text(), 'CIDR'), 'networks are asked with an explanation');
$bot->saveOvpnRoutes('203.0.113.9/24 198.51.100.7');
check(block($bot->conf(), 'ovpn-routes') === "push \"route 203.0.113.0 255.255.255.0\"\npush \"route 198.51.100.7 255.255.255.255\"\n", 'networks become push routes');
check($bot->getOvpnRoutes() === ['203.0.113.0/24', '198.51.100.7/32'] && $bot->t_restarts === 1, 'networks are read back and applied by a restart');
$bot->saveOvpnRoutes('198.51.100.7, 203.0.113.0/24');
check($bot->t_restarts === 2, 'a different order is a change');
$bot->saveOvpnRoutes('198.51.100.7/32 203.0.113.77/24');
check($bot->t_restarts === 2, 'the same list does not restart the server');
$before = $bot->conf();
$bot->saveOvpnRoutes('203.0.113.0/24 nonsense');
check($bot->conf() === $before && $bot->t_restarts === 2 && str_contains($bot->text(), 'nonsense'), 'a bad entry changes nothing and is named');
$bot->saveOvpnRoutes(implode(' ', array_map(static fn($n) => "10.0.$n.0/24", range(0, 40))));
check($bot->conf() === $before && str_contains($bot->text(), '40'), 'more than 40 networks are refused');
$bot->saveOvpnRoutes(implode(' ', array_map(static fn($n) => "10.0.$n.0/24", range(1, 40))));
check(count($bot->getOvpnRoutes()) === 40, 'exactly 40 networks are accepted');
$bot->saveOvpnRoutes('-');
check($bot->getOvpnRoutes() === [] && block($bot->conf(), 'ovpn-routes') === '', 'a dash clears the list');
$bot->saveOvpnRoutes('<b>10.0.0.0/8</b>');
check(!str_contains($bot->text(), '<b>10.0.0.0/8</b>'), 'echoed input is escaped');

// --- MSS
$bot = new OvpnLabBot($fresh);
$seen = [];
for ($n = 0; $n < 5; $n++) { $bot->toggleOvpnMss(); $seen[] = $bot->getOvpnMss(); }
check($seen === [1360, 1280, 1200, 0, 1360] && $bot->t_restarts === 5, 'MSS cycles through the values and back to default');
check(block($bot->conf(), 'ovpn-mss') === "mssfix 1360\n", 'MSS is one mssfix line inside its block');

// --- udp → tcp → udp+tcp → udp
$bot = new OvpnLabBot($fresh);
$bot->addClient('alice');
$states = [];
for ($n = 0; $n < 4; $n++) {
    $bot->t_ssh = []; $bot->t_files = [];
    if ($n) $bot->toggleOvpnProto();
    $conf = $bot->conf();
    $bot->sendOvpnConfigFile('alice');
    $states[] = [implode('+', $bot->ovpnListenProtos()), $bot->getOvpnProto(), (bool) preg_match('~^explicit-exit-notify 1$~m', $conf), block($conf, 'ovpn-dual'),
        implode('|', preg_grep('~^(proto|remote|server-poll-timeout) ~', explode("\n", $bot->t_files[0]->data))),
        implode(' ', preg_grep('~^(env|upstream) ~', $bot->t_ssh))];
}
check(array_column($states, 0) === ['udp', 'tcp', 'udp+tcp', 'udp'] && array_column($states, 1) === ['udp4', 'tcp4', 'udp4', 'udp4'], 'protocol button cycles udp, tcp, both');
check(array_column($states, 2) === [true, false, true, true], 'explicit-exit-notify follows the main protocol');
check(array_column($states, 3) === ['', '', "local * 1194 udp4\nlocal * 1194 tcp4\n", ''], 'second socket exists only in the udp+tcp mode');
check($states[0][4] === 'proto udp4|remote vpn.example.org 1194' && $states[1][4] === 'proto tcp4|remote vpn.example.org 1194', 'single-protocol profile is unchanged');
check($states[2][4] === 'remote vpn.example.org 1194 udp4|remote vpn.example.org 1194 tcp4|server-poll-timeout 8', 'udp+tcp profile tries UDP first and falls back to TCP');
check(str_contains($states[2][5], 'env OVPNPROTO=udp4') && substr_count($states[2][5], 'listen      1194 udp reuseport;') === 1 && substr_count($states[2][5], 'listen      1194 reuseport;') === 1, 'both ports are published in udp+tcp mode');
check(substr_count($states[1][5], 'listen') === 1 && str_contains($states[1][5], 'listen      1194 reuseport;') && str_contains($states[3][5], 'listen      1194 udp reuseport;') && substr_count($states[3][5], 'listen') === 1, 'one port is published otherwise');
check(Bot::ovpnUpstreamBlock(1194, ['udp']) === "#ovpn-port\n    server {\n        listen      1194 udp reuseport;\n        proxy_pass  openvpn;\n    }\n    #ovpn-port", 'single-protocol upstream block is byte-identical to the old one');
// explicit-exit-notify при возврате к UDP дописывается в конец — так было и раньше.
$lines = static function (string $conf): array { $rows = array_values(array_filter(explode("\n", $conf), static fn($row) => $row !== '')); sort($rows); return $rows; };
check($lines($bot->conf()) === $lines($fresh), 'a full cycle returns server.conf to the same set of lines');
foreach (['tcp4-server:203.0.113.5:34082' => '203.0.113.5', 'udp4:203.0.113.5:1194' => '203.0.113.5', '203.0.113.5:60537' => '203.0.113.5', 'tcp6-server:[2001:db8::1]:443' => '2001:db8::1', '' => ''] as $real => $ip) {
    check($bot->ovpnRealIp($real) === $ip, "client address is read from: $real");
}

// --- перевыпуск сертификата
$bot = new OvpnLabBot($fresh);
$bot->addClient('alice', 'OLD');
file_put_contents("$bot->t_root/ccd/alice", "disable\n");
$bot->renewOvpnUser('alice');
$buttons = buttonsOf($bot->t_buttons);
check(isset($buttons['/renewOvpnUser alice confirm'], $buttons['/ovpnClientMenu alice']) && !$bot->t_ssh && str_contains($bot->text(), 'перестанет работать'), 'reissue asks first and explains the consequence');
$bot->renewOvpnUser('alice', true);
$order = array_values(array_filter(array_map(static fn($c) => str_contains($c, 'revoke_ovpn_client.sh') ? 'revoke' : (str_contains($c, 'build-client-full') ? 'issue' : null), $bot->t_ssh)));
check($order === ['revoke', 'issue'], 'the old certificate is revoked before the new one is issued');
check($bot->t_mgmt === [['kill alice', 'exit']] && count($bot->t_files) === 1 && str_contains($bot->t_files[0]->data, "NEW") && !str_contains($bot->t_files[0]->data, 'OLD'), 'old session is closed and the new profile is sent');
check($bot->isOvpnUserDisabled('alice'), 'blocking survives the reissue');
$bot = new OvpnLabBot($fresh); $bot->addClient('alice', 'OLD'); $bot->t_revokeOk = false;
$bot->renewOvpnUser('alice', true);
check(!$bot->t_mgmt && !$bot->t_files && str_contains(file_get_contents("$bot->t_root/pki/issued/alice.crt"), 'OLD') && !preg_grep('~build-client-full~', $bot->t_ssh), 'failed revocation changes nothing and issues nothing');
$bot = new OvpnLabBot($fresh); $bot->addClient('alice', 'OLD'); $bot->t_issueOk = false;
$bot->renewOvpnUser('alice', true);
check($bot->t_mgmt === [['kill alice', 'exit']] && !$bot->t_files && str_contains($bot->text(), 'Добавьте клиента заново') && $bot->t_menus === ['ovpn'], 'revoked but not issued: said plainly, session closed');
$bot = new OvpnLabBot($fresh); $bot->addClient('alice'); $bot->t_busy = true;
$bot->renewOvpnUser('alice', true);
check(!$bot->t_ssh && !$bot->t_mgmt && str_contains($bot->text(), 'PKI занят'), 'busy PKI: nothing is done');
$bot = new OvpnLabBot($fresh); $bot->addClient('alice'); unlink("$bot->t_root/pki/private/ca.key");
$bot->renewOvpnUser('alice', true);
check(!preg_grep('~revoke~', $bot->t_ssh) && file_exists("$bot->t_root/pki/issued/alice.crt"), 'without the CA key nothing is revoked');
foreach (['server', 'mallory', '', "alice'; id"] as $name) {
    $bot = new OvpnLabBot($fresh); $bot->addClient('alice');
    $bot->renewOvpnUser($name, true);
    check(!$bot->t_ssh && !$bot->t_mgmt, 'reissue refuses the name: ' . json_encode($name));
}

// --- срок сертификата читается заново после перевыпуска
$make = static function (int $days): string {
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    openssl_x509_export(openssl_csr_sign(openssl_csr_new(['commonName' => 'alice'], $key), null, $key, $days), $pem);
    return $pem;
};
$bot = new OvpnLabBot($fresh);
file_put_contents("$bot->t_root/pki/issued/alice.crt", $make(10));
touch("$bot->t_root/pki/issued/alice.crt", time() - 100);
$first = $bot->ovpnCertInfo('alice');
file_put_contents("$bot->t_root/pki/issued/alice.crt", $make(3650));
$second = $bot->ovpnCertInfo('alice');
check($first && $second && $second['to'] - $first['to'] > 3000 * 86400, 'certificate dates are not served from a stale cache');
unlink("$bot->t_root/pki/issued/alice.crt");
check($bot->ovpnCertInfo('alice') === null, 'a removed certificate has no dates');

// --- учёт трафика
$bot = new OvpnLabBot($fresh);
$bot->addClient('alice'); $bot->addClient('bob');
check($bot->ovpnTrafficSync() === [] && !file_exists($bot->ovpnTrafficPath()), 'no status file: nothing is counted or written');
$bot->status(['alice' => [1000, 2000, '2026-10-10 10:00:00', 1]]);
$bot->ovpnTrafficSync();
$t = $bot->ovpnTraffic('alice');
check([$t['rx'], $t['tx']] === [1000, 2000] && $bot->ovpnTraffic('bob')['rx'] === 0, 'a live session is counted');
check($t['since'] >= time() - 2 && str_contains($bot->ovpnTrafficLine('alice'), date('Y-m-d')), 'counting starts with the first session');
check($bot->ovpnTraffic('bob')['since'] === 0 && !str_contains($bot->ovpnTrafficLine('bob'), date('Y')), 'a client that never connected has no start date');
$saved = filemtime($bot->ovpnTrafficPath());
$bot->status(['alice' => [5000, 7000, '2026-10-10 10:00:00', 1]]);
$bot->ovpnTrafficSync();
check($bot->ovpnTraffic('alice')['rx'] === 5000, 'every changed live sample is durable before disconnect');
$data = json_decode(file_get_contents($bot->ovpnTrafficPath()), true); $data['saved'] = time() - 61;
file_put_contents($bot->ovpnTrafficPath(), json_encode($data));
$bot->ovpnTrafficSync();
check($bot->ovpnTraffic('alice')['rx'] === 5000 && $bot->ovpnTraffic('alice')['tx'] === 7000, 'unchanged samples preserve the durable total');
$bot->status(['alice' => [4000, 6000, '2026-10-10 10:00:00', 1]]);
$bot->ovpnTrafficSync(static fn($users) => $users);
check($bot->ovpnTraffic('alice')['rx'] === 5000, 'a stale smaller reading never lowers the total');
$bot->status(['alice' => [300, 400, '2026-10-10 11:00:00', 2]]);
$bot->ovpnTrafficSync();
check([$bot->ovpnTraffic('alice')['rx'], $bot->ovpnTraffic('alice')['tx']] === [5300, 7400], 'a new session adds to the finished one');
$bot->status([]);
$bot->ovpnTrafficSync();
$row = json_decode(file_get_contents($bot->ovpnTrafficPath()), true)['users']['alice'];
check([$row['rx'], $row['tx'], $row['live']] === [5300, 7400, []], 'finished sessions are folded into the total at once');
$bot->status(['alice' => [300, 400, '2026-10-10 11:00:00', 2]]);
$bot->ovpnTrafficSync(static fn($users) => $users);
check($bot->ovpnTraffic('alice')['rx'] === 5600, 'the same counters after a server restart are a new session (documented approximation)');
check((fileperms($bot->ovpnTrafficPath()) & 0777) === 0600, 'the counters file is private');

// сброс при живой сессии
$bot->route('/resetOvpnTraffic alice');
$t = $bot->ovpnTraffic('alice');
check([$t['rx'], $t['tx']] === [0, 0] && $t['since'] >= time() - 2, 'reset starts from zero even with a live session');
$bot->status(['alice' => [800, 900, '2026-10-10 11:00:00', 2]]);
$bot->ovpnTrafficSync(static fn($users) => $users);
check([$bot->ovpnTraffic('alice')['rx'], $bot->ovpnTraffic('alice')['tx']] === [500, 500], 'after the reset only new bytes are counted');
$bot->status([]);
$bot->ovpnTrafficSync();
check([$bot->ovpnTraffic('alice')['rx'], $bot->ovpnTraffic('alice')['tx']] === [500, 500], 'and the same holds once that session ends');
$bot->status(['alice' => [800, 900, '2026-10-10 11:00:00', 2]]);
$bot->ovpnTrafficSync(static fn($users) => $users);

// лимит
$bot->t_messages = [];
$bot->route('/setOvpnLimit alice');
check($bot->t_prompt['callback'] === 'saveOvpnLimit' && $bot->t_prompt['args'] === ['alice'] && str_contains($bot->text(), 'гигабайт'), 'limit is asked with an explanation');
foreach (['abc', '-1', '1e9', '1.2345', ''] as $bad) {
    $bot->saveOvpnLimit($bad, 'alice');
    check($bot->ovpnTraffic('alice')['limit'] === 0, 'not a limit: ' . json_encode($bad));
}
$bot->saveOvpnLimit('0,000001', 'alice');
check($bot->ovpnTraffic('alice')['limit'] === 0, 'a limit rounded to zero bytes is no limit');
$bot->saveOvpnLimit('0.5', 'alice');
check($bot->ovpnTraffic('alice')['limit'] === 536870912 && !$bot->ovpnTraffic('alice')['limited'], 'limit is stored in bytes');
$bot->t_messages = []; $bot->t_mgmt = [];
$bot->trackOvpnTraffic();
check(!$bot->isOvpnUserDisabled('alice') && !$bot->t_mgmt, 'below the limit nothing happens');
$bot->status(['alice' => [300000800, 300000900, '2026-10-10 11:00:00', 2], 'bob' => [5, 5, '2026-10-10 12:00:00', 3]]);
$bot->trackOvpnTraffic();
check($bot->isOvpnUserDisabled('alice') && $bot->t_mgmt === [['kill alice', 'exit']] && !$bot->isOvpnUserDisabled('bob'), 'reaching the limit blocks and disconnects that client only');
check(count($bot->t_messages) === 1 && $bot->t_messages[0][0] === 99 && str_contains($bot->t_messages[0][1], 'alice') && str_contains($bot->t_messages[0][1], 'лимит'), 'the admin is told once');
$bot->trackOvpnTraffic(); $bot->trackOvpnTraffic();
check(count($bot->t_messages) === 1 && count($bot->t_mgmt) === 1, 'no repeated messages on later passes');
$bot->t_messages = [];
$bot->enableOvpnUser('alice');
check($bot->isOvpnUserDisabled('alice') && str_contains($bot->text(), 'Лимит трафика исчерпан'), 'a client over the limit cannot simply be enabled');
$bot->saveOvpnLimit('2', 'alice');
check(!$bot->ovpnTraffic('alice')['limited'] && $bot->isOvpnUserDisabled('alice'), 'raising the limit clears the flag but does not unblock by itself');
$bot->enableOvpnUser('alice');
check(!$bot->isOvpnUserDisabled('alice'), 'then the admin can enable the client');
$bot->saveOvpnLimit('0', 'alice');
check($bot->ovpnTraffic('alice')['limit'] === 0, 'zero removes the limit');
$bot->saveOvpnLimit('1', 'mallory');
check(!isset(json_decode(file_get_contents($bot->ovpnTrafficPath()), true)['users']['mallory']), 'no limit for an unknown client');
// Лимиты входят в резервную копию, счётчики нет: восстановление их не откатывает.
$bot->saveOvpnLimit('3', 'alice');
$limits = $bot->ovpnLimitsSnapshot();
check($limits === ['alice' => 3 * 1024 ** 3], 'backup keeps the limits of clients that have one');
$before = $bot->ovpnTraffic('alice');
$bot->saveOvpnLimit('0', 'alice'); $bot->saveOvpnLimit('7', 'bob');
$bot->restoreOvpnLimits($limits);
check($bot->ovpnTraffic('alice')['limit'] === 3 * 1024 ** 3 && $bot->ovpnTraffic('bob')['limit'] === 0, 'restore sets the limits from the backup and clears the others');
check($bot->ovpnTraffic('alice')['rx'] === $before['rx'] && $bot->ovpnTraffic('alice')['tx'] === $before['tx'], 'restoring limits leaves the counters as they are');
Bot::validateOvpnLimits(['alice' => 1, '123' => 5]);
foreach ([['alice' => 0], ['a b' => 5], ['alice' => '5'], 'x'] as $bad) {
    try { Bot::validateOvpnLimits($bad); check(false, 'invalid limits rejected: ' . json_encode($bad)); } catch (InvalidArgumentException) { check(true, 'invalid limits rejected'); }
}
$bot->saveOvpnLimit('0', 'alice');
// Перевыпуск на секунду убирает сертификат: проход cron в этот момент не должен стереть счётчик.
rename("$bot->t_root/pki/issued/bob.crt", "$bot->t_root/bob.crt.aside");
$bot->ovpnTrafficSync(static fn($users) => $users);
rename("$bot->t_root/bob.crt.aside", "$bot->t_root/pki/issued/bob.crt");
check($bot->ovpnTraffic('bob')['rx'] === 5, 'a certificate missing for a moment does not erase the counter');
$bot->delOvpnUser('bob', true);
check(!isset(json_decode(file_get_contents($bot->ovpnTrafficPath()), true)['users']['bob']) && !file_exists("$bot->t_root/pki/issued/bob.crt"), 'a deleted client loses its counter at once');
$bot->t_admin = null; $bot->saveOvpnLimit('0.1', 'alice'); $bot->t_messages = [];
$bot->trackOvpnTraffic();
check($bot->isOvpnUserDisabled('alice') && !$bot->t_messages, 'without a known admin chat the client is still blocked');
$bot->t_module = false; $bot->enableOvpnUser('alice'); file_put_contents("$bot->t_root/ccd/alice", ''); $bot->trackOvpnTraffic();
check(!$bot->isOvpnUserDisabled('alice'), 'a switched-off OpenVPN module is not policed');
$bot->t_module = true;
file_put_contents($bot->ovpnTrafficPath(), '{broken');
try { $bot->ovpnTrafficSync(); check(false, 'a damaged counters file is rejected'); }
catch (RuntimeException $expected) {}
check(file_get_contents($bot->ovpnTrafficPath()) === '{broken', 'a damaged counters file is never overwritten with zero');

// --- меню
$bot = new OvpnLabBot($fresh);
$long = str_repeat('u', 40);
$bot->addClient($long); $bot->addClient('alice');
$menu = $bot->ovpnMenu();
$buttons = buttonsOf($menu['data']);
foreach (['/toggleOvpnProto', '/toggleOvpnGateway', '/setOvpnRoutes', '/toggleOvpnMss', '/menuhelp ovpn 0', '/addOvpnUser', '/changePort ovpn', '/toggleOvpnIsolation',
    '/toggleOvpnWinBlockDns', '/restartOvpnMenu', '/showOvpnLog', '/showOvpnConnLog', '/refreshOvpn', '/ovpnClientMenu alice', '/menu'] as $data) {
    check(isset($buttons[$data]), "main menu button: $data");
}
check(str_contains($menu['text'], 'сервер: <code>vpn.example.org:1194/udp</code>') && str_contains($menu['text'], 'клиенты: 2') && str_contains($menu['text'], 'весь трафик через VPN: ' . $bot->i18n('on')), 'main menu text is translated');
$bot->language = 'en';
check(str_contains($bot->ovpnMenu()['text'], 'clients: 2') && str_contains($bot->ovpnMenu()['text'], 'server: <code>'), 'and has an English version');
$bot->language = 'ru';
$bot->ovpnClientMenu($long);
$buttons = buttonsOf($bot->t_buttons);
check(count($buttons) === 9 && max(array_map('strlen', array_keys($buttons))) <= 64, 'client menu fits Telegram limits with the longest name');
foreach (["/getOvpnConfig $long", "/renewOvpnUser $long", "/setOvpnLimit $long", "/resetOvpnTraffic $long", "/disableOvpnUser $long", "/kickOvpn $long", "/ovpnClientLog $long", "/delOvpnUser $long", '/menu ovpn'] as $data) {
    check(isset($buttons[$data]), "client menu button: $data");
}
check(strlen("/renewOvpnUser $long confirm") <= 64 && strlen("/delOvpnUser $long confirm") <= 64, 'confirmation buttons fit as well');
check(str_contains($bot->text(), 'трафик всего: ↓0 B ↑0 B') && !str_contains($bot->text(), '↑0 B (с '), 'client menu shows the running total, without a start date before the first session');
$bot->t_messages = [];
$bot->route("/renewOvpnUser $long");
check(isset(buttonsOf($bot->t_buttons)["/renewOvpnUser $long confirm"]), 'reissue is routed');
foreach (['/toggleOvpnGateway' => 1, '/toggleOvpnMss' => 2, '/toggleOvpnProto' => 3] as $callback => $restarts) {
    $bot->route($callback);
    check($bot->t_restarts === $restarts, "routed: $callback");
}
$bot->route('/setOvpnRoutes');
check($bot->t_prompt['callback'] === 'saveOvpnRoutes', 'routed: /setOvpnRoutes');

// --- справка и переводы
[$title, $back, $pages] = $bot->menuHelpContent('ovpn');
check($title === 'OpenVPN' && $back === '/menu ovpn' && count($pages) === 8, 'help has eight pages and returns to the menu');
check($bot->menuHelpContent('ovpn', 'alice')[1] === '/ovpnClientMenu alice' && $bot->menuHelpContent('ovpn', 'a b')[1] === '/menu ovpn', 'help returns to the client it was opened from');
foreach ($pages as $name => $body) {
    check(mb_strlen("$name\n\n$body") < 3900, "help page fits one message: $name");
    foreach (['b', 'code', 'i'] as $tag) check(substr_count($body, "<$tag>") === substr_count($body, "</$tag>"), "help markup is balanced in: $name");
}
$help = implode("\n", $pages);
foreach (['add peer', 'kick', 'history', 'log tail', 'restart', 'ovpn renew', 'ovpn gateway', 'ovpn routes', 'ovpn limit', 'ovpn traffic reset', 'ovpn traffic total', 'ovpn proto', 'inter-client', 'win dns guard', 'enable', 'disable'] as $key) {
    check(str_contains($help, $bot->i18n($key)), "help names the button as the menu does: $key");
}
$bot->language = 'en';
$enHelp = implode("\n", $bot->menuHelpContent('ovpn')[2]);
check(!preg_match('~[А-Яа-яЁё]~u', $enHelp), 'English help has no Russian text');
foreach (['add peer', 'kick', 'history', 'log tail', 'restart', 'ovpn renew', 'ovpn gateway', 'ovpn routes', 'ovpn limit', 'ovpn traffic reset', 'ovpn traffic total', 'ovpn proto', 'inter-client', 'win dns guard', 'enable', 'disable'] as $key) {
    check(stripos($enHelp, $bot->i18n($key)) !== false, "English help names the button as the menu does: $key");
}
$bot->language = 'ru';
$source = file_get_contents(__DIR__ . '/../app/bot.php') . file_get_contents(__DIR__ . '/../app/BotOvpn.php');
preg_match_all("~i18n\\('(ovpn [a-z ]+)'\\)~", $source, $used);
check(count(array_unique($used[1])) >= 30, 'translation keys are found in the code');
foreach (array_unique($used[1]) as $key) {
    foreach (['en', 'ru'] as $language) { $bot->language = $language; check($bot->i18n($key) !== $key && $bot->i18n($key) !== '', "translation $key/$language"); }
}

echo "ovpn extra: $checks checks passed\n";
