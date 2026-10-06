<?php

require __DIR__ . '/../app/bot.php';

class StartupProbeBot extends Bot
{
    public array $responses = [];
    public array $probes = [];
    public function __construct() {}
    public function tcpProbe(string $host, int $port, float $timeout = 3.0): array
    {
        $this->probes[] = [$host, $port, $timeout];
        return ['ok' => array_shift($this->responses) ?? false];
    }
}

$bot = new StartupProbeBot();
$bot->responses = [false, false, true];
if (!$bot->waitForSshService('telemt', 2) || count($bot->probes) !== 3) {
    throw new RuntimeException('Delayed SSH must become ready before initialization');
}
foreach ($bot->probes as [$host, $port, $timeout]) {
    if ($host !== 'telemt' || $port !== 22 || $timeout > 1) {
        throw new RuntimeException('Startup probe must have a bounded connection timeout');
    }
}
$bot->probes = [];
$start = microtime(true);
if ($bot->waitForSshService('ipsec', 0) || count($bot->probes) !== 1 || microtime(true) - $start > .5) {
    throw new RuntimeException('Unavailable service must stop at the deadline');
}
$bot->responses = [true];
if (!$bot->waitForSshService('ng', 0)) throw new RuntimeException('Ready service must not wait');
echo "service_readiness_test OK\n";
