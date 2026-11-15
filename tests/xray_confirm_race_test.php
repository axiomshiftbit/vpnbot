<?php
require_once __DIR__ . '/../app/bot.php';

class ConfirmRaceBot extends Bot {
    public bool $locked = false;
    public int $reads = 0;
    public array $saved = [];
    public array $fixtureClients = [
        ['email' => 'alice', 'id' => '11111111-1111-4111-8111-111111111111'],
        ['email' => 'bob', 'id' => '22222222-2222-4222-8222-222222222222'],
    ];
    public function __construct() { $this->input = []; }
    public function getXray() {
        // Параллельный delxr держит xray-lock. Без него удаление и
        // переиндексация могут вклиниться между проверкой и ротацией.
        if (++$this->reads === 2 && !$this->locked) array_shift($this->fixtureClients);
        return ['inbounds' => [['settings' => ['clients' => $this->fixtureClients]]]];
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $this->locked = $name === 'xray';
        try { return $fn(); } finally { $this->locked = false; }
    }
    public function saveXray(array $c): void { $this->saved = $c; }
    public function restartXray($c, $norestart = false) { $this->saved = $c; return true; }
    protected function userXrLocked($i, $back = null) { return $this->userXr($i, $back); }
    public function userXr($i, $back = null) {}
    public function xray($page = 0) {}
}

foreach (['rotateSub', 'regenIdXr'] as $action) {
    $b = new ConfirmRaceBot();
    $b->xrConfirmClient($action, 0, $b->xrClientKey($b->fixtureClients[0]));
    $saved = $b->saved['inbounds'][0]['settings']['clients'] ?? [];
    if (count($saved) !== 2 || $saved[0]['email'] !== 'alice' || $saved[1] !== $b->fixtureClients[1]) {
        throw new RuntimeException("$action: ротация затронула другого клиента после переиндексации");
    }
}
echo "xray_confirm_race_test OK (2)\n";
