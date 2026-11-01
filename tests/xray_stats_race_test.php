<?php
require_once __DIR__ . '/../app/bot.php';

// Maintenance успел перезапустить ядро перед тем, как access получил lock.
// Снимок, снятый до lock, нельзя применять к уже свёрнутой сессии.
class StatsRaceBot extends Bot {
    public array $stats = ['session' => ['download' => 100, 'upload' => 0], 'global' => ['download' => 0, 'upload' => 0]];
    public bool $restarted = false;
    public function __construct() {}
    public function getXray() { return ['inbounds' => [['tag' => 'main', 'settings' => ['clients' => []]]]]; }
    public function getXrayStats() { return $this->stats; }
    public function setXrayStats($stats) { $this->stats = $stats; }
    public function exitNodes(?array $pac = null): array { return []; }
    public function xrayStatCounters(): ?array {
        return ['inbound>>>main>>>traffic>>>downlink' => $this->restarted ? 0 : 100];
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        if ($name === 'xray' && !$this->restarted) {
            $this->stats = self::foldSession($this->stats);
            $this->restarted = true;
        }
        return $fn();
    }
}
$bot = new StatsRaceBot();
$bot->xrayConf = tempnam(sys_get_temp_dir(), 'vpnbot-stats-');
$bot->xrayStatsUser();
unlink($bot->xrayConf . '.apply.lock');
unlink($bot->xrayConf);
$total = $bot->stats['global']['download'] + $bot->stats['session']['download'];
if ($total !== 100) throw new RuntimeException("Повторное начисление трафика: ожидается 100, получено $total");
echo "xray_stats_race_test OK\n";

// Любой restartXray(), в том числе из старого обработчика меню, держит
// xray.json.apply.lock. Сборщик обязан ждать этот же lock до чтения API.
if (function_exists('pcntl_fork')) {
    $root = sys_get_temp_dir() . '/vpnbot-stats-race-' . bin2hex(random_bytes(6));
    mkdir($root, 0700);
    $ready = "$root/ready";
    $pid = pcntl_fork();
    if ($pid === 0) {
        $lock = fopen("$root/xray.json.apply.lock", 'c'); flock($lock, LOCK_EX);
        file_put_contents($ready, '1');
        usleep(700000);
        file_put_contents("$root/restarted", '1');
        flock($lock, LOCK_UN); fclose($lock); exit(0);
    }
    try {
        for ($n = 0; $n < 200 && !is_file($ready); $n++) usleep(10000);
        if (!is_file($ready)) throw new RuntimeException('Не запустился процесс фикстуры');
        $probe = new class extends StatsRaceBot {
            public bool $queriedDuringRestart = false;
            public function xrayStatCounters(): ?array {
                $this->queriedDuringRestart = !is_file(dirname($this->xrayConf) . '/restarted');
                return [];
            }
        };
        $probe->xrayConf = "$root/xray.json";
        $probe->xrayStatsUser();
        if ($probe->queriedDuringRestart) throw new RuntimeException('Снимок API прочитан посреди перезапуска ядра');
    } finally {
        pcntl_waitpid($pid, $status);
        foreach (glob("$root/*") as $file) unlink($file);
        rmdir($root);
    }
    echo "xray_stats_apply_lock_test OK\n";
}
