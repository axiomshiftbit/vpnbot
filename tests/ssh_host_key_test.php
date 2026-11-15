<?php
// Бот выполняет команду в контейнере только после проверки ключа узла.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });
class HostKeyBot extends Bot { public function __construct() {} }

$failures = [];
$check = static function (bool $ok, string $name) use (&$failures): void { if (!$ok) $failures[] = $name; };
$blob = static fn(string $key): string => "\0\0\0\x0bssh-ed25519\0\0\0\x20" . $key;
$line = static fn(string $key, string $comment = 'xr'): string => 'ssh-ed25519 ' . base64_encode($blob($key)) . ($comment === '' ? '' : " $comment") . "\n";
$print = static fn(string $key): string => sha1($blob($key), true);
$own = random_bytes(32); $other = random_bytes(32); $third = random_bytes(32);

// Разбор строки открытого ключа.
$check(Bot::sshHostKeyFingerprint($line($own)) === $print($own), 'отпечаток совпадает с SHA-1 записи ключа');
$check(Bot::sshHostKeyFingerprint($line($own, '')) === $print($own), 'ключ без комментария');
$check(Bot::sshHostKeyFingerprint(trim($line($own))) === $print($own), 'ключ без перевода строки');
$check(Bot::sshHostKeyFingerprint($line($own)) !== Bot::sshHostKeyFingerprint($line($other)), 'разные ключи — разные отпечатки');
foreach ([
    'пустой файл' => '',
    'ключ RSA' => 'ssh-rsa ' . base64_encode("\0\0\0\x07ssh-rsa" . random_bytes(260)) . " xr\n",
    'обрезанный ключ' => 'ssh-ed25519 ' . base64_encode(substr($blob($own), 0, 40)) . "\n",
    'лишние байты' => 'ssh-ed25519 ' . base64_encode($blob($own) . 'x') . "\n",
    'чужой алгоритм в записи' => 'ssh-ed25519 ' . base64_encode("\0\0\0\x0bssh-ed25518\0\0\0\x20" . $own) . "\n",
    'не base64' => "ssh-ed25519 !!!! xr\n",
    'закрытый ключ вместо открытого' => "-----BEGIN OPENSSH PRIVATE KEY-----\n",
    'ключ не в начале файла' => "# comment\n" . $line($own),
] as $name => $text) {
    $check(Bot::sshHostKeyFingerprint($text) === null, "не принимается: $name");
}

$root = sys_get_temp_dir() . '/vpnbot-hostkey-' . bin2hex(random_bytes(6));
mkdir("$root/hosts/xr", 0700, true); mkdir("$root/hosts/wg", 0700, true); mkdir("$root/dnstt", 0700, true);
$bot = new HostKeyBot();
$bot->sshHostKeys = "$root/hosts"; $bot->dnsttHostKey = "$root/dnstt/ssh_host_ed25519_key.pub";
// До первой выдачи ключей (обновление: новый код, старые контейнеры) каталога нет.
$legacy = new HostKeyBot(); $legacy->sshHostKeys = "$root/absent"; $legacy->dnsttHostKey = "$root/absent.pub";
$check($legacy->sshHostKeyTrusted('xr', $print($third)), 'до выдачи ключей бот работает как раньше');
$check(!$legacy->sshHostKeyTrusted('../xr', $print($third)), 'и до выдачи имя сервиса проверяется');
$check(!$legacy->sshHostKeyTrusted('xr', ''), 'и до выдачи нужен отпечаток');
try {
    file_put_contents("$root/hosts/xr/ssh_host_ed25519_key.pub", $line($own));
    file_put_contents("$root/hosts/wg/ssh_host_ed25519_key.pub", $line($other, 'wg'));
    $check($bot->sshHostKeyTrusted('xr', $print($own)), 'свой ключ сервиса принимается');
    $check(!$bot->sshHostKeyTrusted('xr', $print($other)), 'ключ другого сервиса не принимается');
    $check(!$bot->sshHostKeyTrusted('wg', $print($own)), 'сервис не может выдать себя за соседа');
    $check(!$bot->sshHostKeyTrusted('xr', $print($third)), 'случайный ключ не принимается');
    $check(!$bot->sshHostKeyTrusted('oc', $print($own)), 'сервис без известного ключа не принимается');
    $check(!$bot->sshHostKeyTrusted('xr', ''), 'пустой отпечаток не принимается');
    $check(!$bot->sshHostKeyTrusted('xr', bin2hex($print($own))), 'отпечаток не того вида не принимается');
    foreach (['', '../xr', 'xr/../wg', 'XR', 'xr ', "xr\n", 'hosts/xr'] as $name) {
        $check(!$bot->sshHostKeyTrusted($name, $print($own)), 'недопустимое имя сервиса: ' . json_encode($name));
    }
    file_put_contents("$root/hosts/xr/ssh_host_ed25519_key.pub", '');
    $check(!$bot->sshHostKeyTrusted('xr', sha1('', true)), 'пустой файл ключа не даёт доступа');
    // Обычный сервис не получает запасного пути через настройки dnstt.
    file_put_contents($bot->dnsttHostKey, $line($third, 'dnstt'));
    $check(!$bot->sshHostKeyTrusted('xr', $print($third)), 'ключ dnstt не подходит другому сервису');

    // dnstt: ключ из настроек принимается и запоминается.
    $pin = "$root/hosts/dnstt/ssh_host_ed25519_key.pub";
    $check(!$bot->sshHostKeyTrusted('dnstt', $print($own)), 'dnstt: чужой ключ не принимается');
    $check(!is_file($pin), 'dnstt: отказ ничего не запоминает');
    $check($bot->sshHostKeyTrusted('dnstt', $print($third)), 'dnstt: текущий ключ из настроек принимается');
    $check(is_file($pin) && file_get_contents($pin) === $line($third, 'dnstt'), 'dnstt: принятый ключ запомнен');
    // Замена ключа: до перезагрузки sshd отдаёт прежний, после — новый.
    file_put_contents($bot->dnsttHostKey, $line($other, 'dnstt'));
    $check($bot->sshHostKeyTrusted('dnstt', $print($third)), 'dnstt: прежний ключ годится до перезагрузки');
    $check(file_get_contents($pin) === $line($third, 'dnstt'), 'dnstt: запомненный ключ не меняется прежним');
    $check($bot->sshHostKeyTrusted('dnstt', $print($other)), 'dnstt: новый ключ годится после перезагрузки');
    $check(file_get_contents($pin) === $line($other, 'dnstt'), 'dnstt: запомнен новый ключ');
    $check(!$bot->sshHostKeyTrusted('dnstt', $print($third)), 'dnstt: после смены прежний ключ больше не годится');
    $check(!$bot->sshHostKeyTrusted('dnstt', $print($own)), 'dnstt: посторонний ключ не годится никогда');
    // Две замены подряд, как при восстановлении из копии: ключ заменили вне
    // бота, бот перезагрузил sshd (и запомнил ключ), затем вернули прежний.
    file_put_contents($bot->dnsttHostKey, $line($third, 'dnstt'));
    $check($bot->sshHostKeyTrusted('dnstt', $print($other)), 'dnstt: вторая замена — до перезагрузки годится запомненный');
    $bot->sshHostKeyRememberDnstt();   // успешная перезагрузка: sshd отдаёт $third
    file_put_contents($bot->dnsttHostKey, $line($own, 'dnstt'));
    $check($bot->sshHostKeyTrusted('dnstt', $print($third)), 'dnstt: после перезагрузки и новой замены sshd узнаётся');
    $check(!$bot->sshHostKeyTrusted('dnstt', $print($other)), 'dnstt: ключ до перезагрузки больше не годится');
    $bot->sshHostKeyRememberDnstt();   // вторая перезагрузка: sshd отдаёт $own
    $check($bot->sshHostKeyTrusted('dnstt', $print($own)) && !$bot->sshHostKeyTrusted('dnstt', $print($third)), 'dnstt: после второй перезагрузки действует только последний ключ');
    // Негодный файл настроек запомненный ключ не затирает.
    file_put_contents($bot->dnsttHostKey, 'garbage');
    $bot->sshHostKeyRememberDnstt();
    $check($bot->sshHostKeyTrusted('dnstt', $print($own)), 'dnstt: негодный файл не затирает запомненный ключ');
    unlink($bot->dnsttHostKey);
    $check($bot->sshHostKeyTrusted('dnstt', $print($own)), 'dnstt: без файла настроек действует запомненный ключ');
    // Перезагрузка — место, где ключ запоминается; без этого две замены подряд блокируют бота.
    $start = substr($source = file_get_contents(__DIR__ . '/../app/bot.php'), strpos($source, 'public function dnsttStart()'), 2800);
    $check(strpos($start, "start_dnstt.sh --reload") < strpos($start, '$this->sshHostKeyRememberDnstt();'), 'dnstt: ключ запоминается после успешной перезагрузки');
} finally {
    exec('rm -rf ' . escapeshellarg($root));
}

// Порядок в Bot::ssh(): ключ узла сверяется до входа и до команды.
$source = file_get_contents(__DIR__ . '/../app/bot.php');
$body = substr($source, strpos($source, 'public function ssh($cmd'), 4000);
$connect = strpos($body, "ssh2_connect(\$service, 22, ['hostkey' => 'ssh-ed25519'])");
$verify = strpos($body, '$this->sshHostKeyTrusted(');
$auth = strpos($body, 'ssh2_auth_pubkey_file(');
$exec = strpos($body, 'ssh2_exec(');
$check($connect !== false && $verify !== false && $auth !== false && $exec !== false, 'все шаги подключения на месте');
$check($connect < $verify && $verify < $auth && $auth < $exec, 'проверка ключа узла стоит между подключением и входом');
$check(substr_count($source, 'ssh2_connect(') === 1, 'другого подключения по SSH в боте нет');

foreach ($failures as $failure) echo "FAIL: $failure\n";
if ($failures) exit(1);
echo "ssh_host_key_test OK\n";
