<?php

// Выдача подписки без SSH в соседние контейнеры.
//
// Замер на тестовом сервере (1 vCPU, 2026-10-31): подписка Xray — 144 мс, из них 139 мс
// SSH в ng (`cat /etc/nginx/nginx.conf`); sing-box — 516 мс: два SSH в ng
// и проба ядра в xr (253 мс). Теперь:
//  1. nginxGetTypeCert() читает /config/nginx.conf (тот же файл, что
//     смонтирован в ng), SSH — только если файла нет;
//  2. удачная проба ядра пишется в /config/xray-core-probe.json, подписка
//     берёт её не старше XRAY_PROBE_CACHE_TTL; устаревшая, испорченная или
//     неудачная запись не используется, неудачная проба файл не трогает;
//  3. subscription() и subVless() подключают кеш до первой пробы.

require_once __DIR__ . '/../app/bot.php';

set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});

$checks = 0;
function nsCheck(bool $ok, string $label): void
{
    global $checks;
    if (!$ok) throw new RuntimeException($label);
    $checks++;
}

class NoSshBot extends Bot
{
    public array $calls = [];
    public string $probeOut = "1|/usr/bin/xray-smux|reno bbr brutal|/usr/bin/xray-smux|Xray 26.10.28 (Xray, Penetrates Everything.)\nREALITY_BUILD=v0.0.0-20260908062103-8cdf7bf9a0c1+local";
    public bool $fail = false;
    public function __construct(string $root) { $this->xrayConf = "$root/xray.json"; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null')
    {
        $this->calls[] = $service;
        $this->sshFailed = $this->fail;
        if ($this->fail) return '';
        return $service === 'xr' ? $this->probeOut : "#~ssh-fallback\n";
    }
    public function realityRequireMlkemActive(?array $p = null): bool { return false; }
}

$root = sys_get_temp_dir() . '/vpnbot-nossh-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
try {
    // ── 1. nginx.conf без SSH ───────────────────────────────────────────────
    $bot = new NoSshBot($root);
    file_put_contents("$root/nginx.conf", "http {\n    #~letsencrypt\n}\n");
    nsCheck($bot->nginxGetTypeCert() === 'letsencrypt' && $bot->calls === [], 'тип сертификата читается из /config/nginx.conf без SSH');
    file_put_contents("$root/nginx.conf", "http {\n    #~\n}\n");
    nsCheck($bot->nginxGetTypeCert() === '' && $bot->calls === [], 'пустая отметка — http, тоже без SSH');
    unlink("$root/nginx.conf");
    nsCheck($bot->nginxGetTypeCert() === 'ssh-fallback' && $bot->calls === ['ng'], 'без файла — прежний SSH в ng');

    // ── 2. Кеш пробы ядра ───────────────────────────────────────────────────
    $file = "$root/xray-core-probe.json";
    $bot = new NoSshBot($root);
    $bot->xrayCoreProbe(true);
    nsCheck(!is_file($file), 'без настоящего xray.json кеш не пишется (тесты с подменой SSH)');
    file_put_contents("$root/xray.json", '{}');
    $bot = new NoSshBot($root);
    $live = $bot->xrayCoreProbe(true);
    nsCheck($live['ok'] && $live['active'] === 'fork' && $live['reality_local'] && is_file($file), 'удачная проба записана');
    $saved = json_decode(file_get_contents($file), true);
    nsCheck(abs($saved['time'] - time()) <= 2 && $saved['probe'] === $live, 'в файле время и та же проба');

    $cached = new NoSshBot($root);
    $cached->useCachedXrayCoreProbe();
    nsCheck($cached->xrayCoreProbe() === $live && $cached->calls === [], 'подписка берёт пробу из кеша без SSH');
    nsCheck($cached->realityRequiresMlkem() === false && $cached->realityAcksServerName() === false && $cached->calls === [],
        'правила REALITY считаются по кешу');
    nsCheck($cached->xrayCoreProbe(true)['ok'] && $cached->calls === ['xr'], 'свежая проба по-прежнему идёт в xr');

    // Устаревшая и «из будущего» запись не используются.
    foreach ([time() - Bot::XRAY_PROBE_CACHE_TTL - 5, time() + Bot::XRAY_PROBE_CACHE_TTL + 5] as $time) {
        file_put_contents($file, json_encode(['time' => $time, 'probe' => $live]));
        $b = new NoSshBot($root);
        $b->useCachedXrayCoreProbe();
        $b->xrayCoreProbe();
        nsCheck($b->calls === ['xr'], 'запись вне срока не используется: ' . ($time - time()));
    }

    // Испорченные записи не используются (файл в /config пишут только php и
    // service, но мусор не должен ни ронять подписку, ни подменять правило).
    $bad = [
        '{broken',
        json_encode(['time' => time()]),
        json_encode(['time' => (string) time(), 'probe' => $live]),
        json_encode(['time' => time(), 'probe' => ['ok' => false] + $live]),
        json_encode(['time' => time(), 'probe' => ['active' => 'evil'] + $live]),
        json_encode(['time' => time(), 'probe' => ['running' => 'evil'] + $live]),
        json_encode(['time' => time(), 'probe' => ['version' => 26] + $live]),
        json_encode(['time' => time(), 'probe' => array_diff_key($live, ['reality' => 1])]),
        json_encode(['time' => time(), 'probe' => 'x']),
    ];
    foreach ($bad as $n => $body) {
        file_put_contents($file, $body);
        $b = new NoSshBot($root);
        $b->useCachedXrayCoreProbe();
        $b->xrayCoreProbe();
        nsCheck($b->calls === ['xr'], "испорченная запись #$n не используется");
    }
    file_put_contents($file, json_encode(['time' => time(), 'probe' => $live + ['extra' => 'x']]));
    $b = new NoSshBot($root);
    $b->useCachedXrayCoreProbe();
    nsCheck($b->xrayCoreProbe() === $live && $b->calls === [], 'лишние поля отбрасываются');

    // Неудачная проба кеш не трогает и в него не попадает.
    file_put_contents($file, json_encode(['time' => time(), 'probe' => $live]));
    $before = file_get_contents($file);
    $down = new NoSshBot($root);
    $down->fail = true;
    nsCheck(!$down->xrayCoreProbe(true)['ok'] && file_get_contents($file) === $before, 'неудачная проба не перезаписывает кеш');
    unlink($file);
    $down->xrayCoreProbe(true);
    nsCheck(!is_file($file), 'неудачная проба не создаёт кеш');

    // Уже снятая в этом запросе проба кешем не подменяется.
    file_put_contents($file, json_encode(['time' => time(), 'probe' => ['active' => 'origin'] + $live]));
    $b = new NoSshBot($root);
    $b->xrayCoreProbe();
    $b->useCachedXrayCoreProbe();
    nsCheck($b->xrayCoreProbe()['active'] === 'fork', 'проба этого запроса важнее кеша');

    // ── 3. Точки входа подписок ─────────────────────────────────────────────
    $src = (string) file_get_contents(__DIR__ . '/../app/bot.php');
    foreach (['subscription($return = false)', 'subVless()'] as $fn) {
        $body = substr($src, strpos($src, "public function $fn"), 1500);
        nsCheck(strpos($body, '$this->useCachedXrayCoreProbe();') !== false
            && strpos($body, '$this->useCachedXrayCoreProbe();') < strpos($body, '$this->getXray()'), "$fn подключает кеш пробы в начале");
    }
    $start = (string) file_get_contents(__DIR__ . '/../scripts/start_php.sh');
    nsCheck(str_contains($start, "\nrm -f /config/xray-core-probe.json\n"), 'запуск php сбрасывает пробу прежнего образа');
} finally {
    foreach (scandir($root) ?: [] as $name) if (is_file("$root/$name")) unlink("$root/$name");
    rmdir($root);
}

echo "sub_no_ssh_test OK ($checks проверок)\n";
