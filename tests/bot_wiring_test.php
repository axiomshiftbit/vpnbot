<?php
// Связность бота: каждый шаг cron и каждый обработчик кнопки, названные в коде, существуют.
// Опечатка в имени метода иначе видна только в рабочем боте: шаг cron молча
// падает каждые десять секунд, а кнопка не отвечает.
require_once __DIR__ . '/../app/bot.php';

$checks = 0;
function check(bool $condition, string $label): void { global $checks; $checks++; if (!$condition) { fwrite(STDERR, "FAIL: $label\n"); exit(1); } }

$source = file_get_contents(__DIR__ . '/../app/bot.php');
$class = new ReflectionClass(Bot::class);

// --- шаги cron
$cron = substr($source, strpos($source, 'public function cron()'), 3000);
check(preg_match('~\$steps = \[(.*?)\];~s', $cron, $m) === 1, 'the list of cron steps is found');
preg_match_all("~^\s*'([A-Za-z0-9_]+)',\s*$~m", $m[1], $steps);
check(count($steps[1]) >= 25 && count($steps[1]) === count(array_unique($steps[1])), 'cron steps are listed once each');
foreach ($steps[1] as $step) {
    check($class->hasMethod($step) && $class->getMethod($step)->isPublic() && $class->getMethod($step)->getNumberOfRequiredParameters() === 0,
        "cron step is a public method without required arguments: $step");
}
check(in_array('trackOvpnTraffic', $steps[1], true), 'OpenVPN traffic accounting runs from cron');

// --- обработчики кнопок и сообщений
$start = strpos($source, 'public function action()');
$end = strpos($source, "\n    public function ", $start + 30);
$action = substr($source, $start, $end - $start);
preg_match_all('~case preg_match\(.*?\):\s*(?:(?://[^\n]*|\s)*)\$this->([A-Za-z0-9_]+)\(~s', $action, $handlers);
$names = array_unique($handlers[1]);
check(count($names) >= 300, 'handlers are found in the router (' . count($names) . ')');
foreach ($names as $name) {
    check($class->hasMethod($name), "routed handler exists: $name");
}
foreach (['renewOvpnUser', 'resetOvpnTraffic', 'setOvpnLimit', 'toggleOvpnGateway', 'setOvpnRoutes', 'toggleOvpnMss', 'sendL2tpProfile', 'sendIkev2Profile', 'xdriveMenu'] as $name) {
    check(in_array($name, $names, true), "recent feature is routed: $name");
}

// --- обработчики ответов на запрос ввода: имя метода хранится строкой
preg_match_all("~'callback'\s*=>\s*'([A-Za-z0-9_]+)'~", $source . file_get_contents(__DIR__ . '/../app/BotOvpn.php') . file_get_contents(__DIR__ . '/../app/BotXdrive.php'), $replies);
$replyNames = array_unique($replies[1]);
check(count($replyNames) >= 40, 'reply handlers are found (' . count($replyNames) . ')');
foreach ($replyNames as $name) {
    check($class->hasMethod($name), "reply handler exists: $name");
}

// --- данные каждой кнопки с постоянным текстом укладываются в предел Telegram
preg_match_all("~'callback_data'\s*=>\s*'([^'\$]+)'~", $source, $static);
foreach (array_unique($static[1]) as $data) {
    check(strlen($data) <= 64, "button data fits 64 bytes: $data");
}

echo "bot wiring: $checks checks passed\n";
