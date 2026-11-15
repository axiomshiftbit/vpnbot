<?php
// Настоящий flock в изолированном /logs; стек ловит повторный и обратный захват.
require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';
class CoreLockOrderFixture extends Bot {
    public array $held = [];
    public function __construct(array $strings) { $this->language = 'ru'; $this->i18n = $strings; $this->input = ['chat' => 1, 'message_id' => 1, 'callback_id' => 'synthetic']; }
    public function getPacConf() { return self::PAC_DEFAULTS + ['xray_core' => 'origin']; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        if (in_array($name, $this->held, true) || ($name === 'xray' && in_array('pac', $this->held, true))) throw new RuntimeException('lock order');
        $this->held[] = $name;
        try { return parent::withLock($name, $fn, 2, $busy); }
        finally { array_pop($this->held); }
    }
    public function xrayCoreProbe(bool $fresh = false): array { return ['ok' => true, 'fork' => false, 'active' => 'origin', 'running' => 'origin']; }
    public function brutalAvailable(): bool { return false; }
    public function smuxFrameReady(): bool { return true; }
    public function smuxHalfCloseReady(): bool { return true; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { return []; }
}
$b = new CoreLockOrderFixture($i);
$b->healSmuxHalfClose($b->getPacConf());
if ($b->repairXrayCore() !== false) throw new RuntimeException('origin needs no repair');
$b->smuxToggle('synthetic-invalid');
$b->withWireguardLock(function () use ($b) {
    if ($b->getInstanceWG() !== 'wg1') throw new RuntimeException('instance not pinned');
    $b->withWireguardLock(static fn() => true, 'wg1');
    try { $b->withWireguardLock(static fn() => true, 'wg'); }
    catch (LogicException $expected) { return; }
    throw new RuntimeException('cross-instance nesting accepted');
}, 'wg1');
if ($b->held !== [] || $b->getInstanceWG() !== 'wg') throw new RuntimeException('lock state leaked');
echo "core_lock_order_test: PASS\n";
