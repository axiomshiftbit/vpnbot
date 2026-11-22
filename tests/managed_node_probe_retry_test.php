<?php
require __DIR__ . '/managed_nodes_test.php';
class ResumeFixtureBot extends ManagedFixtureBot {
    public int $attempts = 0;
    public function exitProbe(string $id, bool $full = true): array {
        $this->events[] = 'probe';
        return ['ok' => ++$this->attempts > 1];
    }
}
$bot = new ResumeFixtureBot();
$bot->managedNodePoll('aabbccdd');
if ($bot->attempts !== 2 || $bot->pacState['managed_nodes']['aabbccdd']['job'] !== null || !in_array('confirm', $bot->events)) {
    throw new RuntimeException('FAIL a failed stale session must be retried before node rollback');
}
echo "PASS stale session gets one verified retry\n";

class WarpProbeFixtureBot extends ManagedFixtureBot {
    public string $result = 'https=ok udp=ok';
    public array $observed = [];
    protected function exitStatusWrite(string $id, array $status): void { $this->observed = $status; }
    protected function sshInputCommand(string $cmd, string $input, string $service): string {
        if (!preg_match('~^python3 /node_warp_probe\.py [0-9]+ --details$~D', $cmd) || $service !== 'xr'
            || !preg_match('~^[0-9a-f]{64}\n$~D', $input)) throw new RuntimeException('Invalid private probe transport');
        $this->sshFailed = false;
        return $this->result;
    }
}
foreach (['ok','incomplete','https','udp','missing-profile'] as $case) {
    $bot = new WarpProbeFixtureBot();
    $bot->remoteStatus['options']['warp_mode'] = 'masque';
    if ($case !== 'missing-profile') $bot->profile['warp_uuid'] = '44444444-4444-4444-8444-444444444444';
    if ($case === 'incomplete') $bot->result = '';
    if ($case === 'https') $bot->result = 'https=tls udp=ok';
    if ($case === 'udp') $bot->result = 'https=ok udp=timeout';
    $bot->managedNodePoll('aabbccdd');
    $pending = $bot->pacState['managed_nodes']['aabbccdd']['job'];
    if ($case === 'udp' && ($bot->observed['warp_health']['udp'] ?? '') !== 'timeout') throw new RuntimeException('Missing UDP timeout');
    if ($case === 'ok' ? ($pending !== null || !in_array('confirm', $bot->events, true))
        : (($pending['phase'] ?? '') !== 'wait_rollback' || isset($bot->pacState['exits']['aabbccdd']['managed_profile'])
            || in_array('confirm', $bot->events, true))) throw new RuntimeException('Wrong WARP confirmation: '.$case);
}
echo "PASS WARP requires trace, UDP and matching controller profile\n";
