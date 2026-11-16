<?php
// MAN-02 (аудит A): копия Mieru с периодической квотой обязана содержать
// историю периода (native_metrics). Без неё восстановление начинало период
// заново, и пользователь получал квоту повторно. Данные синтетические.
require_once __DIR__ . '/managed_protocol_fixture.php';
require_once __DIR__ . '/../app/bot.php';

$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
$root = sys_get_temp_dir() . '/vpnbot-mieru-rolling-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
$accepts = static function (ManagedProtocol $m, array $snapshot): bool {
    try { $m->validateSnapshot($snapshot); return true; } catch (InvalidArgumentException) { return false; }
};
try {
    $mieru = new ManagedProtocol('mieru', $root);
    $mieru->configure(['host' => 'vpn.example.com'], true);
    $id = managedProtocolFixtureUser($mieru, 'Периодическая квота');
    $mieru->user($id, ['rolling_quota' => ['days' => 30, 'megabytes' => 10240]]);
    $state = $mieru->read(); unset($state['config'], $state['restore_usage']);
    $usage = ['users' => [$id => ['upload' => 5, 'download' => 7, 'reset' => $state['users'][$id]['reset']]]];

    $check(!$accepts($mieru, ['state' => $state, 'usage' => $usage]), 'периодическая квота без истории периода — отказ');
    $check(!$accepts($mieru, ['state' => $state, 'usage' => $usage + ['native_metrics' => '']]), 'пустая история периода — отказ');
    $check($accepts($mieru, ['state' => $state, 'usage' => $usage + ['native_metrics' => base64_encode("\x0a\x02\x08\x01")]]), 'история периода есть — копия принимается');

    // Без периодической квоты история периода не обязательна (прежние копии).
    $mieru->user($id, ['rolling_quota' => null]);
    $plain = $mieru->read(); unset($plain['config'], $plain['restore_usage']);
    if (empty($plain['users'][$id]['rolling_quota'])) {
        $check($accepts($mieru, ['state' => $plain, 'usage' => $usage]), 'без периодической квоты история не требуется');
    }
} finally {
    exec('rm -rf ' . escapeshellarg($root));
}
echo "mieru_rolling_backup_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
