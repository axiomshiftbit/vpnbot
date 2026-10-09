<?php
// Тонкие настройки Hysteria: тип обфускации, контроллер перегрузки, полоса, sniff.
// Настоящее ядро принимает эти конфигурации в сетевом стенде; здесь — логика бота.
require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

class HyTuneBot extends Bot
{
    public array $conf = ['domain' => 'vpn.example', 'hysteria_pass' => 'shared', 'language' => 'ru'];
    public array $screen = [], $commands = [];
    public string $core = 'v2.13.0';
    public bool $writeFail = false;
    public function __construct(string $root, array $strings) {
        $this->pac = "$root/pac.json"; $this->hysteriaUsersRoot = "$root/hysteria"; $this->hysteriaConf = "$root/hysteria.yaml";
        $this->i18n = $strings; $this->language = 'ru'; $this->ip = '203.0.113.10'; $this->admin = true;
        $this->input = ['chat' => 1, 'message_id' => 1, 'callback_id' => 'cb', 'callback' => '', 'message' => ''];
    }
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { $this->conf = $conf; return true; }
    public function getPorts() { return ['hy' => ['enable' => true, 'port' => 443]]; }
    public function getDomain($cdn = false) { return $this->conf['domain'] ?? ''; }
    public function getWgMsg() { return null; }
    public function protocolModuleEnabled(string $key): bool { return true; }
    public function flagName(string $name, string|array $hosts, bool $cacheOnly = true): string { return $name; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $this->commands[] = $cmd;
        if (str_contains($cmd, 'hysteria version')) return $this->core === '' ? '' : "Version:\t{$this->core}\n";
        return str_contains($cmd, 'printf managed') ? 'managed' : '';
    }
    public function writePrivateKey(string $path, string $data): bool { return !$this->writeFail && parent::writePrivateKey($path, $data); }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->screen = ['text' => $text, 'buttons' => is_array($button) ? $button : []]; }
    public function answer($callback_id, $textNotify = false, $notify = false) {}
    public function yaml(): array { return yaml_parse_file($this->hysteriaConf); }
    public function click(string $callback): void { $this->input['callback'] = $callback; $this->action(); }
    public function labels(): array { return array_map(static fn($b) => $b['text'], array_merge(...$this->screen['buttons'])); }
}

if (!extension_loaded('yaml')) { echo "hysteria_tuning_test: пропущен, нет расширения yaml\n"; exit(0); }
$root = sys_get_temp_dir() . '/vpnbot-hy-tune-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
$query = static function (string $link): array { parse_str((string) parse_url($link, PHP_URL_QUERY), $q); return $q; };
try {
    $b = new HyTuneBot($root, $i);
    copy(__DIR__ . '/../config/hysteria.yaml', $b->hysteriaConf);

    // ── значения по умолчанию не меняют прежнее поведение ───────────────────
    $check($b->restartHysteria() === true, 'конфигурация по умолчанию применяется');
    $y = $b->yaml();
    $check($y['congestion'] === ['type' => 'bbr', 'bbrProfile' => 'standard'], 'по умолчанию BBR, профиль standard');
    $check(!isset($y['obfs'], $y['bandwidth'], $y['sniff'], $y['ignoreClientBandwidth']), 'остальные настройки по умолчанию отсутствуют');
    $check(in_array('reject(10.0.0.0/8)', $y['acl']['inline'], true) && $y['auth']['password'] === 'shared', 'защитный ACL и пароль сохранены');
    $check(!isset($query($b->linkHysteria())['obfs']), 'ссылка без обфускации');

    // ── тип обфускации ──────────────────────────────────────────────────────
    $b->click('/hyTune');
    $check(!array_filter($b->labels(), static fn($l) => str_starts_with($l, 'obfs:')), 'при выключенной обфускации тип не предлагается');
    $b->click('/hyTune obfs');
    $check(!isset($b->conf['hysteria_obfs_type']), 'без обфускации тип не меняется');
    $b->conf['hysteria_obfs'] = 'obfs-secret';
    $b->restartHysteria();
    $check($b->yaml()['obfs'] === ['type' => 'salamander', 'salamander' => ['password' => 'obfs-secret']], 'по умолчанию salamander');
    $check($query($b->linkHysteria())['obfs'] === 'salamander', 'ссылка: salamander');
    foreach (['', 'v2.9.1', 'v2.8.2', 'мусор'] as $old) {
        $b->core = $old; $b->click('/hyTune obfs');
        $check($b->hyObfsType($b->conf) === 'salamander' && str_contains($b->screen['text'], '2.9.2'), "ядро «{$old}»: gecko не включается, причина названа");
    }
    $check($b->yaml()['obfs']['type'] === 'salamander', 'конфигурация старого ядра не тронута');
    foreach (['v2.9.2', 'v2.13.0', '2.20.1'] as $new) {
        $b->core = $new; $b->conf['hysteria_obfs_type'] = 'salamander'; $b->click('/hyTune obfs');
        $check($b->hyObfsType($b->conf) === 'gecko', "ядро {$new}: gecko доступна");
    }
    $check($b->yaml()['obfs'] === ['type' => 'gecko', 'gecko' => ['password' => 'obfs-secret']], 'gecko: тип и пароль в конфигурации');
    $q = $query($b->linkHysteria());
    $check($q['obfs'] === 'gecko' && $q['obfs-password'] === 'obfs-secret', 'gecko: тип и пароль в ссылке');
    $check(in_array('obfs: gecko', $b->labels(), true) && str_contains($b->hysteriaMenu()['text'], 'obfs: gecko'), 'тип виден в обоих меню');
    $b->core = ''; $b->click('/hyTune obfs');
    $check($b->hyObfsType($b->conf) === 'salamander', 'возврат к salamander не зависит от версии ядра');
    $b->conf['hysteria_obfs_type'] = '../evil'; $b->restartHysteria();
    $check($b->yaml()['obfs']['type'] === 'salamander' && $query($b->linkHysteria())['obfs'] === 'salamander', 'неизвестный тип из настроек заменяется на salamander');
    unset($b->conf['hysteria_obfs']); $b->conf['hysteria_obfs_type'] = 'gecko'; $b->restartHysteria();
    $check(!isset($b->yaml()['obfs']) && !isset($query($b->linkHysteria())['obfs']), 'выключенная обфускация убирает блок при любом типе');

    // ── контроллер перегрузки ───────────────────────────────────────────────
    $b->core = 'v2.13.0'; $seen = [];
    foreach (range(1, 4) as $_) { $b->click('/hyTune cc'); $seen[] = [$b->hyCc($b->conf), $b->yaml()['congestion']]; }
    $check($seen === [['bbr-conservative', ['type' => 'bbr', 'bbrProfile' => 'conservative']], ['bbr-aggressive', ['type' => 'bbr', 'bbrProfile' => 'aggressive']],
        ['reno', ['type' => 'reno']], ['bbr', ['type' => 'bbr', 'bbrProfile' => 'standard']]], 'кнопка обходит четыре контроллера по кругу');
    $b->conf['hysteria_cc'] = 'cubic'; $b->restartHysteria();
    $check($b->yaml()['congestion'] === ['type' => 'bbr', 'bbrProfile' => 'standard'], 'неизвестный контроллер заменяется на bbr');
    $b->conf['hysteria_cc'] = 'reno';
    $check(str_contains($b->hysteriaMenu()['text'], 'cc: <code>reno</code>'), 'главное меню показывает выбранный контроллер');

    // ── полоса: Brutal, компенсация потерь, полоса клиента ──────────────────
    $b->click('/hyTune loss');
    $check(!empty($b->conf['hysteria_no_loss_comp']) && !isset($b->yaml()['bandwidth']), 'без заданной полосы блок bandwidth не появляется');
    $b->conf['hysteria_bw_up'] = '100 mbps'; $b->conf['hysteria_bw_down'] = '200 mbps'; $b->restartHysteria();
    $check($b->yaml()['bandwidth'] === ['up' => '100 mbps', 'down' => '200 mbps', 'disableLossCompensation' => true], 'Brutal с отключённой компенсацией потерь');
    $check(str_contains($b->hysteriaMenu()['text'], 'brutal (100 mbps / 200 mbps)') && $b->yaml()['congestion'] === ['type' => 'reno'], 'Brutal в меню, запасной контроллер сохранён');
    $b->click('/hyTune loss');
    $check($b->yaml()['bandwidth'] === ['up' => '100 mbps', 'down' => '200 mbps'], 'компенсация включена обратно: ключа нет');
    $b->click('/hyTune ignorebw');
    $check($b->yaml()['ignoreClientBandwidth'] === true, 'полоса клиента игнорируется');
    $b->click('/hyTune ignorebw');
    $check(!isset($b->yaml()['ignoreClientBandwidth']), 'и снова учитывается');

    // ── sniff ───────────────────────────────────────────────────────────────
    $b->click('/hyTune sniff');
    $check($b->yaml()['sniff'] === ['enable' => true, 'timeout' => '2s'] && $b->yaml()['resolver']['udp']['addr'] === '10.10.0.5:53', 'sniff включён, резолвер — AdGuard');
    $b->click('/hyTune sniff');
    $check(!isset($b->yaml()['sniff']), 'sniff выключен');

    // ── отказ записи откатывает настройку ───────────────────────────────────
    $before = $b->conf; $yaml = file_get_contents($b->hysteriaConf); $b->writeFail = true;
    foreach (['cc', 'loss', 'ignorebw', 'sniff'] as $action) {
        $b->click("/hyTune $action");
        $check($b->conf === $before && file_get_contents($b->hysteriaConf) === $yaml && str_contains($b->screen['text'], '⚠️'), "отказ записи: «{$action}» не сохраняется и объясняется");
    }
    $b->writeFail = false;

    // ── кнопки и маршрутизация ──────────────────────────────────────────────
    $b->conf['hysteria_obfs'] = 'x'; $b->click('/hyTune');
    foreach (array_merge(...$b->screen['buttons']) as $button) $check(strlen($button['callback_data']) <= 64, 'callback укладывается в лимит Telegram');
    $check(count($b->screen['buttons']) === 6, 'пять настроек и возврат');
    $before = $b->conf;
    foreach (['/hyTune evil', '/hyTune cc extra', '/hyTune  cc', '/hyTuneX'] as $bad) { $b->screen = []; $b->click($bad); $check($b->conf === $before, "«{$bad}» ничего не меняет"); }
    $main = array_merge(...$b->hysteriaMenu()['data']);
    $check(count(array_filter($main, static fn($x) => $x['callback_data'] === '/hyTune')) === 1, 'в главном меню Hysteria есть вход в тонкие настройки');
} finally {
    foreach (glob("$root/*") as $file) is_dir($file) ? null : unlink($file);
    @rmdir("$root/hysteria"); @rmdir($root);
}
if ($failed) exit(1);
echo "hysteria_tuning_test: $count OK\n";
