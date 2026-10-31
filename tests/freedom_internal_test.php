<?php

// finalRules прямого выхода не пускают VPN-клиента во внутреннюю сеть Docker.
//
// Аудит 2026-10-31: freedom разрешал всю 10.10.0.0/16 и полагался на гейт
// маршрутизации, а тот совпадает только по IP. При IPIfNonMatch совпавшее
// доменное правило в direct (группа узлов «напрямую», запасной direct
// упавшего узла) выигрывает до правил по IP, и клиент по имени
// 10.10.0.15.nip.io доходил до sshd service, AdGuard, dockerproxy
// (воспроизведено на тестовом сервере лабораторным ядром с боевыми правилами).
// Теперь внутрь — только DNS AdGuard и WARP-socks, остальное — запрет.

require_once __DIR__ . '/../app/bot.php';

set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});

$checks = 0;
function frCheck(bool $ok, string $label): void
{
    global $checks;
    if (!$ok) throw new RuntimeException($label);
    $checks++;
}

class FreedomBot extends Bot
{
    public string $warp = '10.10.0.13/32';
    public function __construct() {}
    public function warpSocksIp(): string { return $this->warp; }
}

$bot = new FreedomBot();
$conf = static fn(array $settings = []) => ['outbounds' => [['tag' => 'direct', 'protocol' => 'freedom'] + ($settings ? ['settings' => $settings] : []),
    ['tag' => 'block', 'protocol' => 'blackhole']]];

// ── 1. Новая установка ──────────────────────────────────────────────────────
$c = $conf();
$bot->ensureFreedomCompat($c);
$rules = $c['outbounds'][0]['settings']['finalRules'];
frCheck(count($rules) === 4, 'четыре правила');
frCheck($rules[0] === ['action' => 'allow', 'network' => 'tcp,udp', 'port' => '53', 'ip' => ['10.10.0.5/32']], 'DNS AdGuard — только порт 53');
frCheck($rules[1] === ['action' => 'allow', 'network' => 'tcp', 'port' => '1080', 'ip' => ['10.10.0.13/32']], 'WARP-socks — только TCP 1080');
frCheck($rules[2] === ['action' => 'allow', 'network' => 'udp', 'port' => '20000-29999', 'ip' => ['10.10.0.13/32']], 'WARP-socks — UDP-порты relay');
frCheck($rules[3]['action'] === 'block' && in_array('10.0.0.0/8', $rules[3]['ip'], true) && in_array('127.0.0.0/8', $rules[3]['ip'], true)
    && in_array('169.254.0.0/16', $rules[3]['ip'], true) && in_array('fc00::/7', $rules[3]['ip'], true), 'остальная внутренняя сеть, loopback, metadata и ULA — запрет');
$allowed = [];
foreach ($rules as $rule) if ($rule['action'] === 'allow') $allowed = array_merge($allowed, $rule['ip']);
frCheck(!in_array('10.10.0.0/16', $allowed, true) && $allowed === ['10.10.0.5/32', '10.10.0.13/32', '10.10.0.13/32'], 'разрешены только два адреса /32');
frCheck(!isset($c['outbounds'][1]['settings']), 'blackhole не трогается');

$bot->ensureFreedomCompat($c);
frCheck($c['outbounds'][0]['settings']['finalRules'] === $rules, 'повторный вызов ничего не меняет');

// Адрес WARP из compose (override) попадает в правила.
$bot->warp = '10.10.0.99/32';
$c2 = $conf();
$bot->ensureFreedomCompat($c2);
frCheck($c2['outbounds'][0]['settings']['finalRules'][1]['ip'] === ['10.10.0.99/32']
    && $c2['outbounds'][0]['settings']['finalRules'][2]['ip'] === ['10.10.0.99/32'], 'адрес WARP берётся из compose');
$bot->warp = '10.10.0.13/32';

// ── 2. Переход с прежних правил ─────────────────────────────────────────────
$legacy = [Bot::FREEDOM_LEGACY_INTERNAL[0], $rules[3]];
$c = $conf(['finalRules' => $legacy]);
$bot->ensureFreedomCompat($c);
frCheck($c['outbounds'][0]['settings']['finalRules'] === $rules, 'прежняя пара заменена новыми правилами');

$deny6 = ['action' => 'block', 'ip' => ['::/0'], 'blockDelay' => 0];
$c = $conf(['domainStrategy' => 'ForceIPv4', 'finalRules' => [$deny6, ...$legacy]]);
$bot->ensureFreedomCompat($c);
frCheck($c['outbounds'][0]['settings']['finalRules'] === [$deny6, ...$rules]
    && $c['outbounds'][0]['settings']['domainStrategy'] === 'ForceIPv4', 'запрет ::/0 узлов IPv6 остаётся первым');

// Тот же переход и для второго freedom с тегом direct-v6 и т. п.
$c = ['outbounds' => [['tag' => 'direct', 'protocol' => 'freedom', 'settings' => ['finalRules' => $legacy]],
    ['tag' => 'other', 'protocol' => 'freedom', 'settings' => ['finalRules' => $legacy]]]];
$bot->ensureFreedomCompat($c);
frCheck($c['outbounds'][0]['settings']['finalRules'] === $rules && $c['outbounds'][1]['settings']['finalRules'] === $rules, 'все freedom переходят');

// ── 3. Собственные правила администратора не трогаются ──────────────────────
$custom = [
    [['action' => 'allow', 'ip' => ['127.0.0.0/8']]],
    [],
    [Bot::FREEDOM_LEGACY_INTERNAL[0]],
    [Bot::FREEDOM_LEGACY_INTERNAL[0], ['action' => 'block', 'ip' => ['10.0.0.0/8']]],
    [['action' => 'block', 'ip' => ['::/0']], ['action' => 'allow', 'ip' => ['10.10.0.0/16'], 'network' => 'tcp']],
];
foreach ($custom as $n => $own) {
    $c = $conf(['finalRules' => $own]);
    $bot->ensureFreedomCompat($c);
    frCheck($c['outbounds'][0]['settings']['finalRules'] === $own, "собственные правила #$n не изменены");
}

// ── 4. Правила проверяются настоящим ядром ──────────────────────────────────
$xray = getenv('VLESS_TEST_XRAY') ?: '';
if ($xray !== '' && is_executable($xray)) {
    $dir = sys_get_temp_dir() . '/vpnbot-freedom-' . bin2hex(random_bytes(4));
    mkdir($dir, 0700);
    $c = ['log' => ['loglevel' => 'none'], 'inbounds' => [['tag' => 'in', 'listen' => '127.0.0.1', 'port' => 1, 'protocol' => 'socks']]] + $conf();
    $bot->ensureFreedomCompat($c);
    file_put_contents("$dir/config.json", json_encode($c));
    exec(escapeshellarg($xray) . ' run -test -config ' . escapeshellarg("$dir/config.json") . ' 2>&1', $out, $rc);
    unlink("$dir/config.json");
    rmdir($dir);
    frCheck($rc === 0, 'ядро принимает finalRules с network и port');
}

echo "freedom_internal_test OK ($checks проверок)\n";
