<?php
// C-03 (сверочный аудит): удаление пользователя TeleMT и смена секрета сначала
// переписывают telemt.toml; работающий процесс держит прежние секреты до
// остановки. Отказ остановки оставлял удалённый секрет действующим без
// повторной попытки. Теперь незавершённое применение отмечено, и cron повторяет
// его, пока оно не удастся. Ядро и SSH подменены.
require_once __DIR__ . '/../app/bot.php';

class TelemtRetryBot extends Bot
{
    public array $conf = ['telemt_users' => ['alice' => 'abababababababababababababababab', 'bob' => 'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd']];
    public int $failures = 0, $applied = 0;
    public function __construct(public string $root) { $this->language = 'ru'; $this->input = ['chat' => 1, 'message_id' => 1]; require __DIR__ . '/../app/i18n.php'; $this->i18n = $i; }
    public function telemtApplyPendingPath(): string { return "$this->root/apply.pending"; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function protocolModuleEnabled(string $module): bool { return true; }
    public function getPacConf() { return $this->conf; }
    public function telemtConfUpdate(callable $fn) { return $fn($this->conf); }
    public function telemtActivityForget(string $name, bool $journalOnly = false): void {}
    public function telemtWebEnabled(array $conf): bool { return false; }
    public function telemtWebRefresh(bool $was): void {}
    public function telemtUsers($relay = '', int $page = 0) {}
    protected function applyTelemt(?string $resetQuota = null, bool $deferStart = false)
    {
        if ($this->failures > 0) { $this->failures--; throw new RuntimeException('telemt stop failed'); }
        $this->applied++;
    }
}

$root = sys_get_temp_dir() . '/vpnbot-telemt-retry-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
try {
    $b = new TelemtRetryBot($root);
    $b->failures = 2;
    try { $b->telemtDelUser('bob'); } catch (RuntimeException) {}
    $check(!isset($b->conf['telemt_users']['bob']), 'bob удалён из настроек');
    $check(is_file("$root/apply.pending"), 'незавершённое применение отмечено');
    $check(method_exists($b, 'retryTelemtApply') && in_array('retryTelemtApply', Bot::CRON_ACCESS, true), 'повтор стоит в быстрой группе cron');
    if (method_exists($b, 'retryTelemtApply')) {
        $b->retryTelemtApply();                                   // ещё один отказ: метка остаётся
        $check(is_file("$root/apply.pending") && $b->applied === 0, 'повторный отказ не снимает метку');
        $b->retryTelemtApply();                                   // удалось
        $check(!is_file("$root/apply.pending") && $b->applied === 1, 'успешный повтор применяет отзыв и снимает метку');
        $b->retryTelemtApply();
        $check($b->applied === 1, 'без метки cron ядро не трогает');
    }
} finally {
    exec('rm -rf ' . escapeshellarg($root));
}
echo "telemt_apply_retry_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
