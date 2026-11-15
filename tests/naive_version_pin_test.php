<?php
require_once __DIR__ . '/../app/bot.php';

class NaivePinBot extends Bot
{
    public array $writes = [];
    public array $messages = [];
    public function __construct() { $this->language = 'ru'; $this->input = ['chat' => 1, 'message_id' => 1]; }
    public function setEnvVar($key, $value) { $this->writes[$key] = $value; }
    public function menu($type = false, $arg = false, $return = false) {}
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->messages[] = $text; }
}

$pins = [];
foreach (file(__DIR__ . '/../.env', FILE_IGNORE_NEW_LINES) as $line) {
    if (preg_match('~^(CADDY_VERSION|FORWARDPROXY_VERSION)=(.+)$~D', $line, $m)) $pins[$m[1]] = $m[2];
}
$saved = array_map('getenv', array_combine(array_keys($pins), array_keys($pins)));
$failed = [];
try {
    $b = new NaivePinBot();
    $b->chCaddyVersion($pins['CADDY_VERSION']);
    if ($b->writes !== $pins) $failed[] = 'выбор текущей версии сохраняет проверенную ревизию forwardproxy';
    if (getenv('FORWARDPROXY_VERSION') !== $pins['FORWARDPROXY_VERSION']) $failed[] = 'меню немедленно видит правильную ревизию';
    foreach (['v2.11.7', 'v2.11.9'] as $version) {
        $b->writes = [];
        $b->chCaddyVersion($version);
        if ($b->writes !== ['CADDY_VERSION'=>$version, 'FORWARDPROXY_VERSION'=>'v2.11.7-naive2']) {
            $failed[] = 'старая и security-пара сохраняют закреплённый forwardproxy';
        }
    }
    $b->writes = [];
    $b->chCaddyVersion('v99.99.99');
    if ($b->writes || !$b->messages) $failed[] = 'непроверенная пара отклоняется до записи';
    if (getenv('FORWARDPROXY_VERSION') !== $pins['FORWARDPROXY_VERSION']) $failed[] = 'отказ сохраняет прежний пин процесса';
} finally {
    foreach ($saved as $key => $value) putenv($value === false ? $key : "$key=$value");
}
foreach ($failed as $name) echo "FAIL $name\n";
echo 'naive_version_pin_test ' . ($failed ? 'FAILED' : 'OK') . "\n";
exit($failed ? 1 : 0);
