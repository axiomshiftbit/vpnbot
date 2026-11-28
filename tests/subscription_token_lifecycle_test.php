<?php
require_once __DIR__ . '/../app/bot.php';

class TokenLifecycleFixture extends Bot
{
    public array $state;
    public array $pacState = [];
    public bool $failSave = false;
    public function __construct() {
        $this->input = [];
        $this->state = ['inbounds' => [['settings' => ['clients' => [
            ['id' => '00000000-0000-4000-8000-000000000001', 'email' => 'alpha'],
            ['id' => '00000000-0000-4000-8000-000000000002', 'email' => 'beta', 'subtoken' => 'beta-before'],
        ]]]]];
    }
    public function getXray() { return $this->state; }
    public function saveXray(array $config): void {
        if ($this->failSave) throw new RuntimeException('fixture save failed');
        $this->state = $config;
    }
    public function getPacConf() { return $this->pacState; }
    public function pacConfUpdate(callable $fn) { return $fn($this->pacState); }
    public function withLock(string $name, callable $fn, int $timeout=0, $busy=null) { return $fn(); }
    protected function userXrLocked($i) {}
    public function xray($page=0) {}
    public function clients(): array { return $this->state['inbounds'][0]['settings']['clients']; }
    public function lookup($id) { return $this->findClientBySid($this->state,$id,!empty($this->pacState['subtoken_strict'])); }
}

$check = static function ($ok, $label) { if (!$ok) throw new RuntimeException($label); };
$b = new TokenLifecycleFixture();
[$alpha,$beta]=$b->clients();
$check($b->lookup($alpha['id'])===0 && $b->lookup($beta['subtoken'])===1,'legacy and issued links work before strict mode');
$b->failSave=true;
try { $b->switchSubtokenStrict(); } catch (RuntimeException $e) {}
$check(empty($b->pacState['subtoken_strict']) && $b->lookup($alpha['id'])===0,'failed backfill keeps existing links usable');
$b->failSave=false;
$b->switchSubtokenStrict();
[$a,$b1]=$b->clients();
$check(!empty($b->pacState['subtoken_strict']) && $b->lookup($alpha['id'])===null && $b->lookup($beta['id'])===null,'strict mode rejects both VPN identities');
$check(strlen($a['subtoken'])===32 && $b->lookup($a['subtoken'])===0 && $b->lookup($b1['subtoken'])===1,'strict mode backfills only the missing locator');
$b->rotateSubToken(0);
[$fresh,$unchanged]=$b->clients();
$check($b->lookup($a['subtoken'])===null && $b->lookup($fresh['subtoken'])===0 && $unchanged===$b1,'individual rotation revokes only one link');
$b->rotateAllSubTokens();
[$one,$two]=$b->clients();
$check($b->lookup($fresh['subtoken'])===null && $b->lookup($unchanged['subtoken'])===null && $b->lookup($one['subtoken'])===0 && $b->lookup($two['subtoken'])===1,'global rotation revokes both prior links');
$check($one['id']===$alpha['id'] && $two['id']===$beta['id'] && $one['subtoken']!==$two['subtoken'],'rotation preserves credentials and keeps accounts separate');
$b->switchSubtokenStrict();
$check($b->lookup($alpha['id'])===0 && $b->lookup($a['subtoken'])===null,'compatibility mode restores UUID addressing without reviving rotated tokens');
echo "subscription_token_lifecycle_test OK\n";
