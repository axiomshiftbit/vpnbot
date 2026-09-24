<?php

require __DIR__ . '/timezone.php';

require __DIR__ . '/bot.php';
require __DIR__ . '/config.php';
require __DIR__ . '/i18n.php';

if ($c['debug']) {
    require __DIR__ . '/debug.php';
}

$bot = new Bot($c['key'], $i);

// После старого updater конфиги ещё пусты, но ожидается их восстановление.
// Такой запуск не должен назначать nip.io поверх сохранённого домена.
$initialSetup = !is_file($bot->update)
    && !is_file(dirname($bot->update) . '/state-restored')
    && $bot->getPacConf() == Bot::PAC_DEFAULTS;
if (!$bot->selfUpdate()) {
    exit(1);
}
$bot->ssPswdCheck();
$bot->restartTelemt();
if (!empty($bot->selfupdate)) {
    $bot->offWarp();
}
$bot->dontshowcron = 1;
$bot->sslip($initialSetup);
$bot->adguardSync();
$bot->cloakNginx();
$bot->syncDeny();
$bot->cleanDocker();
$bot->dnsttStart();
$bot->restartHysteria();
$bot->restartTt();
$c = $bot->getPacConf();
$bot->setUpstreamDomain($c['transport'] != 'Reality' ? 't' : $c['reality']['domain']);
$bot->setUpstreamDomainNaive($c['domain']);
$bot->setUpstreamDomainOcserv($c['domain']);
$bot->syncOcservCamouflage();
$bot->syncManagedUpstreams();
$bot->xrayUpdateRules();
