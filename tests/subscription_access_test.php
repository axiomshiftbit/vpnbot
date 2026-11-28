<?php

require_once __DIR__ . '/../app/bot.php';

class SubscriptionPageFixture extends Bot
{
    public array $settings = ['hwid_limit_enabled' => true, 'hwid_device_count' => 1, 'subtoken_strict' => true];
    public array $account = ['id' => 'page-credential', 'email' => 'test', 'subtoken' => 'page-locator'];
    public bool $storageAvailable = true;
    public int $reads = 0;

    public function getXray() { return ['inbounds' => [['settings' => ['clients' => [$this->account]]]]]; }
    public function getPacConf() { return $this->settings; }
    public function getXrayStats() { $this->reads++; return []; }
    public function subDomain(array $pac): string { return 'vpn.example.test'; }
    public function nginxGetTypeCert() { return 'letsencrypt'; }
    public function getHashBot($notset = false) { return 'testhash'; }
    public function subRateLimit($sid, $scope = '') {}
    public function recordSubClient(array $client): void {}
    public function getHwidDevicesByUser($uid) { return []; }
    public function hwidRegister(string $uid, string $hwid, int $limit, array $info): bool {
        if (!$this->storageAvailable) throw new RuntimeException('fixture storage offline');
        return true;
    }
    public function linkXray($i, $s = false) { throw new LogicException('profile'); }
    public function subNotFound($reason = 'Subscription not found or disabled.') { throw new LogicException('rejected'); }
}

$bot = (new ReflectionClass(SubscriptionPageFixture::class))->newInstanceWithoutConstructor();
$failures = [];
$check = static function (bool $ok, string $label) use (&$failures) { if (!$ok) $failures[] = $label; };
$view = static function () use ($bot) {
    $_GET = ['id' => 'page-locator'];
    ob_start();
    try { $bot->sub(); return ob_get_contents(); }
    catch (LogicException $e) { return $e->getMessage(); }
    finally { ob_end_clean(); }
};

$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0';
$bot->account['time'] = time() - 60;
$check($view() === 'rejected', 'expired account cannot open preview');
$check($bot->reads === 0, 'expired preview avoids reading usage');
unset($bot->account['time']);
$preview = $view();
$check(str_contains($preview, 'import://Happ') && !str_contains($preview, 'page-credential'), 'browser without HWID receives import links without connection profiles');
$_SERVER['HTTP_X_HWID'] = 'device-one';
$check($view() === 'profile', 'registered device reaches the personal template');
$bot->storageAvailable = false;
$check(!$bot->processHwidRequest($bot->account) && http_response_code() === 503, 'HWID storage failure prevents profile delivery');
$bot->settings['hwid_limit_enabled'] = false;
unset($_SERVER['HTTP_X_HWID']);
$check($view() === 'profile', 'ordinary account can still open the personal template');

$legacy = new class extends Bot {
    public bool $failWrite = false;
    public function __construct() { $this->hwid = tempnam(sys_get_temp_dir(), 'sub-hwid-'); }
    public function store(): ?PDO { return null; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function setHwidStorage(array $storage) { return $this->failWrite ? false : parent::setHwidStorage($storage); }
};
try {
    file_put_contents($legacy->hwid, '{incomplete');
    $rejected = false;
    try { $legacy->hwidRegister('fixture', 'device-one', 1, []); } catch (Throwable $e) { $rejected = true; }
    $check($rejected && file_get_contents($legacy->hwid) === '{incomplete', 'legacy HWID corruption preserves state and rejects registration');
    file_put_contents($legacy->hwid, '{}');
    $legacy->failWrite = true;
    $rejected = false;
    try { $legacy->hwidRegister('fixture', 'device-one', 1, []); } catch (Throwable $e) { $rejected = true; }
    $check($rejected && file_get_contents($legacy->hwid) === '{}', 'legacy HWID write failure cannot approve a new device');
} finally { unlink($legacy->hwid); }

foreach (['192.0.2.10', '198.51.100.10', '203.0.113.10', '224.0.0.1', '[2001:db8::1]', '[ff02::1]'] as $reserved) {
    $check($bot->safeExtUrlIps("https://$reserved/") === [], 'external fetch accepts only public unicast destinations (' . $reserved . ')');
}
$check($bot->safeExtUrlIps('https://1.1.1.1/') === ['1.1.1.1'], 'public address remains eligible');
if ($failures) { echo implode("\n", $failures), "\n"; exit(1); }
echo "subscription_access_test OK\n";
