<?php
// The node renews its certificate itself (daily timer, 30 days before expiry).
// When that keeps failing (DNS moved, TCP/80 filtered upstream, CA limits),
// the main bot is the only place an administrator would learn about it before
// the node stops serving TLS: the periodic status check must warn, once a day.
require __DIR__ . '/managed_nodes_test.php';

class CertExpiryFixture extends ManagedFixtureBot {
    public array $alerts = [];
    public function notifyAdmins(string $text): void { $this->alerts[] = $text; }
}

$fixture = static function (?int $expires): CertExpiryFixture {
    $b = new CertExpiryFixture();
    $b->pacState['managed_nodes']['aabbccdd']['job'] = null;
    $b->remoteStatus['pending'] = null;
    $b->remoteStatus['certificate'] = $expires === null ? [] : ['expires' => $expires, 'fingerprint' => str_repeat('e', 64)];
    return $b;
};
$poll = static function (CertExpiryFixture $b): void {
    $b->pacState['managed_nodes']['aabbccdd']['status_attempt'] = 0;
    // The throttle is a private property of the Bot trait: reset it in Bot scope.
    Closure::bind(function () { $this->managedNodeCronAt = 0; }, $b, Bot::class)();
    $b->checkManagedNodes();
};

$b = $fixture(time() + 5 * 86400);
$poll($b);
$check(count($b->alerts) === 1, 'certificate expiring in 5 days alerts the administrators');
$check(str_contains($b->alerts[0] ?? '', 'node') && str_contains($b->alerts[0] ?? '', date('Y-m-d', time() + 5 * 86400)),
    'alert names the node and the expiry date');
$poll($b);
$check(count($b->alerts) === 1, 'no repeated alert within a day');
$b->pacState['managed_nodes']['aabbccdd']['cert_alert'] = time() - 86401;
$poll($b);
$check(count($b->alerts) === 2, 'alert repeats daily while the certificate is still expiring');

$b->remoteStatus['certificate']['expires'] = time() + 80 * 86400;
$poll($b);
$check(count($b->alerts) === 2 && !isset($b->pacState['managed_nodes']['aabbccdd']['cert_alert']), 'renewed certificate clears the alert state');

foreach ([['healthy', time() + 40 * 86400], ['no certificate', null]] as [$label, $expires]) {
    $b = $fixture($expires);
    $poll($b);
    $check($b->alerts === [], "no alert: $label");
}
$b = $fixture(time() - 3600);
$poll($b);
$check(count($b->alerts) === 1 && str_contains($b->alerts[0], '❌'), 'expired certificate is reported as expired');

echo "PASS managed node certificate expiry alerts ($checks checks)\n";
