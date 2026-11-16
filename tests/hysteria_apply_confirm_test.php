<?php
// MAN-01: управляемая служба Hysteria проверяет новую конфигурацию и при
// отказе продолжает работать со старой (включая прежний общий пароль).
// Бот обязан дождаться подтверждения применения именно записанного YAML,
// а смена общего пароля при отказе не должна оставаться в настройках.
require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

class HyApplyBot extends Bot
{
    public array $conf = ['domain' => 'vpn.example', 'hysteria_pass' => 'old-shared', 'language' => 'ru'];
    public string $worker = 'accept';   // accept | reject | legacy
    public array $menus = [], $sent = [];
    public ?string $applied = null;     // sha256 YAML, работающего в «службе»
    public function __construct(string $root, array $strings) {
        $this->pac = "$root/pac.json"; $this->hysteriaUsersRoot = "$root/hysteria"; $this->hysteriaConf = "$root/hysteria.yaml";
        $this->i18n = $strings; $this->language = 'ru'; $this->ip = '203.0.113.10'; $this->admin = true;
        $this->input = ['chat' => 1, 'message_id' => 1, 'callback_id' => 'cb', 'callback' => '', 'message' => '', 'from' => 1, 'username' => 'u'];
        if (property_exists($this, 'hysteriaApplyTimeout')) $this->hysteriaApplyTimeout = 2;
    }
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { $this->conf = $conf; return true; }
    public function getPorts() { return ['hy' => ['enable' => true, 'port' => 443]]; }
    public function getDomain($cdn = false) { return $this->conf['domain'] ?? ''; }
    public function protocolModuleEnabled(string $key): bool { return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        if (str_contains($cmd, 'hysteria version')) return "Version:\tv2.8.1\n";
        if (!str_contains($cmd, 'printf managed')) return '';
        // Имитация супервизора: YAML уже записан; служба принимает или отвергает его.
        $sha = hash_file('sha256', $this->hysteriaConf);
        $status = ['schema' => 1, 'time' => time() + 1, 'running' => true, 'last_success' => time(), 'revision' => 1, 'users' => 0];
        // Уже работающий файл служба принимает и в режиме отказа (тот же отпечаток).
        if ($this->worker === 'accept' || ($this->worker === 'reject' && $sha === $this->applied)) { $this->applied = $sha; $status += ['error' => '', 'config_sha256' => $sha]; }
        elseif ($this->worker === 'reject') $status += ['error' => 'configuration_rejected', 'config_sha256' => (string) $this->applied, 'checked_sha256' => $sha];
        else $status += ['error' => ''];   // прежний образ: поля config_sha256 нет
        @mkdir("{$this->hysteriaUsersRoot}/runtime", 0700, true);
        file_put_contents("{$this->hysteriaUsersRoot}/runtime/status.json", json_encode($status));
        return 'managed';
    }
    public function menu($type = false, $arg = false, $return = false) { $this->menus[] = $type; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->sent[] = $text; return []; }
    public function answer($callback_id, $textNotify = false, $notify = false) { if ($textNotify) $this->sent[] = $textNotify; }
    public function yaml(): array { return yaml_parse_file($this->hysteriaConf); }
}

if (!extension_loaded('yaml')) { echo "hysteria_apply_confirm_test: пропущен, нет расширения yaml\n"; exit(0); }
$root = sys_get_temp_dir() . '/vpnbot-hy-apply-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
try {
    $b = new HyApplyBot($root, $i);
    copy(__DIR__ . '/../config/hysteria.yaml', $b->hysteriaConf);
    $check($b->restartHysteria() === true, 'принятая службой конфигурация подтверждается');

    $b->worker = 'reject';
    $b->conf['hysteria_sni'] = 'decoy.example';   // другой YAML, который служба отвергнет
    $started = microtime(true);
    $check($b->restartHysteria() === false, 'отвергнутая службой конфигурация не считается применённой');
    $check(microtime(true) - $started < 1.5, 'явный отказ службы распознаётся без ожидания тайм-аута');

    unset($b->conf['hysteria_sni']);
    // Смена общего пароля, которую служба отвергла: настройки и YAML прежние.
    $b->sent = [];
    $b->chhypass('new-shared');
    $check(($b->conf['hysteria_pass'] ?? null) === 'old-shared', 'отвергнутый пароль не сохраняется в настройках');
    $check(($b->yaml()['auth']['password'] ?? null) === 'old-shared', 'YAML возвращён к прежнему паролю');
    $check($b->sent === ['Hysteria не приняла новый пароль: действует прежний.'], 'пользователь узнаёт, что действует прежний пароль');

    $b->worker = 'accept'; $b->sent = [];
    $b->chhypass('new-shared');
    $check(($b->conf['hysteria_pass'] ?? null) === 'new-shared' && $b->yaml()['auth']['password'] === 'new-shared', 'принятый пароль сохраняется');
    $check(!$b->sent, 'успешная смена пароля без сообщений об ошибке');

    // Служба из прежнего образа не сообщает config_sha256: прежнее поведение.
    $b->worker = 'legacy';
    $check($b->restartHysteria() === true, 'прежний образ службы: применение не блокируется');
} finally {
    exec('rm -rf ' . escapeshellarg($root));
}
echo "hysteria_apply_confirm_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
