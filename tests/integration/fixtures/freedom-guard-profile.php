<?php
require_once __DIR__ . '/../../../app/bot.php';
class FreedomGuardProfile extends Bot
{
    public function __construct() {}
    public function warpSocksIp(): string { return '10.10.0.13/32'; }
}
$value = ['outbounds' => [['tag' => 'direct', 'protocol' => 'freedom']]];
(new FreedomGuardProfile())->ensureFreedomCompat($value);
echo json_encode($value['outbounds'][0]['settings']['finalRules'], JSON_THROW_ON_ERROR);
