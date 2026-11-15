<?php
require_once __DIR__ . '/../app/bot.php';
class TrojanLifecycleBot extends Bot
{
    public array $config = ['inbounds' => [['settings' => ['clients' => [[
        'id' => '11111111-2222-4333-8444-555555555555', 'email' => 'test', 'password' => 'original-password',
    ]]]]]];
    public function __construct() {}
    public function getXray() { return $this->config; }
    public function restartXray($c = false, $norestart = false) { if (is_array($c)) $this->config = $c; return true; }
    protected function userXrLocked($i) { return $this->userXr($i); }
    public function userXr($i) {}
    public function xray($page = 0) {}
}
$b = new TrojanLifecycleBot();
$b->switchXr(0, 1);
$disabled = $b->getXray()['inbounds'][0]['settings']['clients'][0];
$b->setXrPwd('new-password', 0);
$changed = $b->getXray()['inbounds'][0]['settings']['clients'][0];
if ($changed['password'] !== $disabled['password'] || $changed['off_pwd'] !== 'new-password' || $changed['off'] !== $disabled['off']) {
    throw new RuntimeException('Смена пароля выключенного Trojan не должна активировать новые реквизиты');
}
$b->switchXr(0, 1);
$enabled = $b->getXray()['inbounds'][0]['settings']['clients'][0];
if ($enabled['password'] !== 'new-password' || isset($enabled['off_pwd'], $enabled['off'])) throw new RuntimeException('Включение должно применить новый пароль');
$b->setXrPwd('active-password', 0);
if ($b->getXray()['inbounds'][0]['settings']['clients'][0]['password'] !== 'active-password') throw new RuntimeException('Пароль активного пользователя не применён');
$before = $b->getXray();
$b->setXrPwd('stale', 99);
if ($b->getXray() !== $before) throw new RuntimeException('Старый callback не должен создавать пользователя');
echo "trojan_user_lifecycle_test OK\n";
