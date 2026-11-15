<?php
require_once __DIR__ . '/../app/bot.php';
class TelemtIdentityFixture extends Bot {
    public array $conf = [];
    public int $restarts = 0, $forgotten = 0;
    public bool $replaceBeforeLock = false;
    public function __construct() {
        $this->key = 'fixture'; $this->language = 'ru';
        $this->input = ['chat'=>1,'message_id'=>1,'callback_id'=>1,'callback'=>'','message'=>''];
        $this->conf = ['telemt_users'=>['audit'=>str_repeat('a',32),'other'=>str_repeat('c',32)]];
    }
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { $this->conf = $conf; return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        if ($name === 'telemt' && $this->replaceBeforeLock) {
            $this->replaceBeforeLock = false;
            $this->conf['telemt_users']['audit'] = str_repeat('b',32);
        }
        return $fn();
    }
    public function getWgMsg() { return null; }
    public function restartTelemt() { $this->restarts++; return true; }
    public function telemtUsers($relay = '', int $page = 0) {}
    public function telemtUserCard(string $name, string $relay = '', int $page = 0): void {}
    public function telemtActivityForget(string $name, bool $journalOnly = false): void { $this->forgotten++; }
    public function telemtWebRefresh(bool $was): void {}
    public function click(string $callback): void { $this->input['callback'] = $callback; $this->action(); }
}
$failed = 0; $checks = 0;
$check = static function(bool $ok, string $label) use (&$failed, &$checks) {
    $checks++; if (!$ok) { $failed++; echo "FAIL: $label\n"; }
};
foreach (['toggle','regen-confirm','delete-confirm'] as $action) {
    foreach (['rotated','recreated','before-lock'] as $case) {
        $b = new TelemtIdentityFixture();
        $button = $b->telemtUserCallback('audit',999999,str_repeat('r',200),$action);
        $check(strlen($button)<=64, "$action callback length");
        if ($case === 'recreated') unset($b->conf['telemt_users']['audit']);
        if ($case === 'before-lock') $b->replaceBeforeLock = true;
        else $b->conf['telemt_users']['audit'] = str_repeat('b',32);
        $expected = $b->conf; $expected['telemt_users']['audit'] = str_repeat('b',32);
        $b->click($button);
        $check($b->conf === $expected && $b->restarts === 0 && $b->forgotten === 0, "$action $case rejects old identity");
    }
    $b = new TelemtIdentityFixture();
    $before = $b->conf;
    $b->click($b->telemtUserCallback('audit',0,'',$action));
    $check($b->conf !== $before && $b->conf['telemt_users']['other'] === $before['telemt_users']['other'] && $b->restarts === 1, "$action current identity applies");
    $b = new TelemtIdentityFixture(); $before = $b->conf;
    $b->click('/tuc '.substr(hash('sha256','audit'),0,12).' 0 direct '.$action);
    $check($b->conf === $before && $b->restarts === 0, "$action old name-only key rejected");
}
foreach (['/telemtToggleUser audit 0','/telemtDelUser audit 0','/telemtRegen audit 0','/tu t audit 0 relay','/tu d audit 0 relay','/tu r audit 0 relay'] as $button) {
    $b = new TelemtIdentityFixture(); $before = $b->conf; $b->click($button);
    $check($b->conf === $before && $b->restarts === 0 && $b->forgotten === 0, 'legacy unbound button only refreshes');
}
echo "telemt_identity_test: $checks checks, $failed failed\n";
exit($failed ? 1 : 0);
