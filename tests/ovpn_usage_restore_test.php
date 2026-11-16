<?php
// BK-02: перенос резервной копии на чистый сервер не должен обнулять
// израсходованный клиентом OpenVPN трафик и тем самым выдавать квоту заново.
// Восстановление поверх существующих счётчиков их не откатывает назад.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

class OvpnUsageBot extends Bot
{
    public string $t_root;
    public function __construct()
    {
        $this->input = ['chat' => 1, 'from' => 7, 'message_id' => 5];
        $this->language = 'ru';
        $this->t_root = sys_get_temp_dir() . '/vpnbot-ovpn-usage-' . bin2hex(random_bytes(6));
        foreach (['pki/issued', 'pki/private', 'ccd'] as $dir) mkdir("$this->t_root/$dir", 0700, true);
        file_put_contents("$this->t_root/server.conf", "port 1194\n");
    }
    public function __destruct() { if (is_dir($this->t_root)) exec('rm -rf ' . escapeshellarg($this->t_root)); }
    public function ovpnPaths()
    {
        $r = $this->t_root;
        return ['pki' => "$r/pki", 'issued' => "$r/pki/issued", 'priv' => "$r/pki/private", 'ta' => "$r/pki/ta.key", 'ca' => "$r/pki/ca.crt",
            'srv' => "$r/server.conf", 'ccd' => "$r/ccd", 'status' => "$r/openvpn-status.log", 'log' => "$r/openvpn.log", 'conn' => "$r/conn.log"];
    }
    public function addClient(string $name): void
    {
        file_put_contents("$this->t_root/pki/issued/$name.crt", "-----BEGIN CERTIFICATE-----\nC\n-----END CERTIFICATE-----\n");
        file_put_contents("$this->t_root/pki/private/$name.key", "KEY\n");
    }
    public function used(string $cn, int $rx, int $tx, int $limit): void
    {
        $this->ovpnTrafficSync(static function (array $users) use ($cn, $rx, $tx, $limit) {
            $users[$cn] = ['rx' => $rx, 'tx' => $tx, 'since' => 1700000000, 'limit' => $limit, 'live' => []];
            return $users;
        });
    }
    // Разделы OpenVPN-счётчиков полной копии и их восстановление — тем же путём, что restore.
    public function exported(): array { return json_decode(json_encode($this->ovpnBackupSections()), true); }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $f = fopen("$this->t_root/.lock.$name", 'c'); flock($f, LOCK_EX);
        try { return $fn(); } finally { flock($f, LOCK_UN); fclose($f); }
    }
    public function ssh($cmd, $service = 'wg', $wait = true, $out = false) { return ''; }
    public function ovpnMgmt(array $cmds) { return ''; }
    public function restartOvpn() {}
    public function getPacConf() { return []; }
    public function protocolModuleEnabled(string $key, ?array $pac = null): bool { return true; }
    protected function ovpnAdminChat() { return null; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false, $entities = false, $forum = false) { return ['ok' => true]; }
}
// До исправления копия содержала только лимиты: те же разделы, что пишет экспорт.
if (!method_exists(Bot::class, 'ovpnBackupSections')) {
    eval('class OvpnUsageBotCompat extends OvpnUsageBot { public function exported(): array { return ["ovpn_limits" => $this->ovpnLimitsSnapshot()]; } }');
}
$make = static fn(): OvpnUsageBot => class_exists('OvpnUsageBotCompat', false) ? new OvpnUsageBotCompat() : new OvpnUsageBot();
$restore = static function (OvpnUsageBot $bot, array $json): void {
    method_exists($bot, 'restoreOvpnBackupSections') ? $bot->restoreOvpnBackupSections($json) : $bot->restoreOvpnLimits($json['ovpn_limits']);
};

$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
$gib = 1024 ** 3;

// Сервер A: alice израсходовала 2,5 ГиБ из 3 ГиБ, bob без лимита — 1 ГиБ.
$a = $make(); $a->addClient('alice'); $a->addClient('bob');
$a->used('alice', 2 * $gib, $gib / 2, 3 * $gib);
$a->used('bob', $gib, 0, 0);
$json = $a->exported();

// Чистый сервер B: PKI уже восстановлена, своих счётчиков ещё нет.
$b = $make(); $b->addClient('alice'); $b->addClient('bob');
$restore($b, $json);
$alice = $b->ovpnTraffic('alice');
$check($alice['limit'] === 3 * $gib, 'лимит перенесён');
$check($alice['rx'] + $alice['tx'] === (int) (2.5 * $gib), 'израсходованный трафик перенесён на чистый сервер');
$check($b->ovpnTraffic('bob')['rx'] === $gib, 'расход клиента без лимита тоже перенесён');

// Сервер C: свежие локальные счётчики больше, чем в копии — не откатываются.
$c = $make(); $c->addClient('alice');
$c->used('alice', 3 * $gib, $gib, 5 * $gib);
$restore($c, $json);
$check($c->ovpnTraffic('alice')['rx'] === 3 * $gib && $c->ovpnTraffic('alice')['tx'] === $gib, 'восстановление не уменьшает больший локальный расход');
$check($c->ovpnTraffic('alice')['limit'] === 3 * $gib, 'лимит из копии применяется и поверх существующих счётчиков');

// Старая копия без раздела расхода восстанавливается как прежде.
$d = $make(); $d->addClient('alice');
$restore($d, ['ovpn_limits' => ['alice' => $gib]]);
$check($d->ovpnTraffic('alice')['limit'] === $gib && $d->ovpnTraffic('alice')['rx'] === 0, 'старая копия: лимит без расхода');

if (method_exists(Bot::class, 'validateOvpnUsage')) {
    foreach ([['alice' => ['rx' => -1, 'tx' => 0]], ['a b' => ['rx' => 1, 'tx' => 1]], ['alice' => ['rx' => '1', 'tx' => 0]], 'x'] as $bad) {
        try { Bot::validateOvpnUsage($bad); $check(false, 'неверный расход отклонён: ' . json_encode($bad)); }
        catch (InvalidArgumentException) { $check(true, 'неверный расход отклонён'); }
    }
}
echo "ovpn_usage_restore_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
