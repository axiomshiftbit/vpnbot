<?php
// Real JSON files/flock/atomic writers; controller failures are injected at
// the SSH boundary. This is not a native Cloak authentication test.
require_once __DIR__ . '/../app/bot.php';
class CloakRevokeBot extends Bot {
    public string $fault = '';
    public array $runtime = ['owner', 'victim'], $events = [];
    public function __construct(public string $root) { $this->pac = "$root/pac.json"; $this->language = 'ru'; }
    public function getCloakConfig() { return json_decode(file_get_contents("$this->root/ckserver.json"), true, 512, JSON_THROW_ON_ERROR); }
    public function getCloakUsers(): array { return json_decode(file_get_contents("$this->root/ckusers.json"), true, 512, JSON_THROW_ON_ERROR); }
    public function setCloakConfig(array $c) {
        $this->events[] = 'config';
        if ($this->fault === 'config' || !$this->writePrivateKey("$this->root/ckserver.json", json_encode($c))) throw new RuntimeException('synthetic configuration write failure');
    }
    public function setCloakUsers(array $users): void {
        $this->events[] = 'users';
        if ($this->fault === 'users' || !$this->writePrivateKey("$this->root/ckusers.json", json_encode($users))) throw new RuntimeException('synthetic user write failure');
    }
    public function controlContainerService(string $container, string $service, string $action): bool {
        $this->events[] = $action;
        if ($this->fault === 'stop' || ($action === 'restart' && $this->fault === 'restart')) return false;
        $this->runtime = $action === 'stop' ? [] : $this->getCloakConfig()['BypassUID'];
        return true;
    }
    public function menuCkUsers() {}
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { return ''; }
}
$root = sys_get_temp_dir() . '/cloak-revoke-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
$checks = 0; $failed = [];
$check = function ($ok, $name) use (&$checks, &$failed) { $checks++; if (!$ok) $failed[] = $name; };
try {
    foreach (['stop','config','users','restart','success'] as $fault) {
        $b = new CloakRevokeBot($root);
        $b->setCloakConfig(['Enabled' => 1, 'UID' => 'owner', 'BypassUID' => ['owner', 'victim']]);
        $b->setCloakUsers([['uid' => 'owner', 'name' => 'owner'], ['uid' => 'victim', 'name' => 'victim']]);
        $before = [file_get_contents("$root/ckserver.json"), file_get_contents("$root/ckusers.json")];
        $b->events = []; $b->fault = $fault; $error = false;
        try { $b->delCloakUser(substr(sha1('victim'),0,12)); } catch (RuntimeException $e) { $error = true; }
        $check($error === ($fault !== 'success'), "$fault: truthful failure");
        $check(($b->events[0] ?? '') === 'stop', "$fault: stop precedes writes");
        if ($fault === 'stop') {
            $check($before === [file_get_contents("$root/ckserver.json"), file_get_contents("$root/ckusers.json")] && in_array('victim', $b->runtime, true), 'failed stop preserves retryable pair');
        } else {
            $check(!in_array('victim', $b->runtime, true), "$fault: old runtime access revoked");
            if ($fault === 'config') $check(file_get_contents("$root/ckusers.json") === $before[1], 'first write failure retains user for retry');
            if ($fault === 'users') $check(!in_array('victim', $b->getCloakConfig()['BypassUID'], true), 'second write failure retains revocation in server config');
        }
        $b->fault = ''; $b->delCloakUser(substr(sha1('victim'),0,12));
        $check(!in_array('victim', $b->runtime, true) && !in_array('victim', $b->getCloakConfig()['BypassUID'], true), "$fault: retry cannot preserve revoked UID");
    }
    echo json_encode(['checks' => $checks, 'failures' => $failed]), "\n";
} finally {
    foreach (glob("$root/*") as $file) unlink($file); rmdir($root);
}
exit($failed ? 1 : 0);
