<?php
require_once __DIR__ . '/../app/bot.php';

class WarpLifecycleBot extends Bot
{
    public array $commands = [];
    public string $fail = '';
    public bool $transportFailure = false;
    public bool $failWrite = false;
    public bool $concurrentEdit = false;
    public function __construct(public string $root) {
        $this->pac = "$root/pac.json";
        $this->input = ['chat' => 1, 'message_id' => 1];
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        $f = fopen("$this->root/$name.lock", 'c'); flock($f, LOCK_EX);
        try { return $fn(); } finally { flock($f, LOCK_UN); fclose($f); }
    }
    public function setPacConf(array $conf) { return !$this->failWrite && parent::setPacConf($conf); }
    public function warpClientDir($email) { return "$this->root/warp/clients/" . sha1($email); }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $this->commands[] = $cmd;
        $this->sshFailed = $this->transportFailure;
        if ($this->transportFailure) return '';
        if ($this->concurrentEdit) {
            $this->concurrentEdit = false;
            $this->withLock('pac', function () {
                $p = $this->getPacConf(); $p['parallel'] = 'saved'; $this->setPacConf($p);
            });
        }
        $cmd = str_replace(['/etc/warp', '/warp_fixup.sh'],
            ["$this->root/warp", realpath(__DIR__ . '/../scripts/warp_fixup.sh')], $cmd);
        $env = getenv(); $env['PATH'] = "$this->root/bin:" . $env['PATH'];
        $env['WARP_TEST_ROOT'] = $this->root; $env['WARP_TEST_FAIL'] = $this->fail;
        $env['WGCF_CONF'] = "$this->root/warp/wgcf-profile.conf";
        $p = proc_open(['sh', '-c', $cmd], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'a']], $pipes, null, $env);
        fclose($pipes[0]); $out = stream_get_contents($pipes[1]); fclose($pipes[1]); proc_close($p);
        return $out;
    }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { return []; }
    public function sendDraft($chat, $draft_id, $text = '', $mode = 'HTML') {}
    public function warp() {}
}

$root = sys_get_temp_dir() . '/vpnbot-warp-lifecycle-' . bin2hex(random_bytes(6));
mkdir($root, 0700); mkdir("$root/bin"); mkdir("$root/warp");
$fake = <<<'SH'
#!/bin/sh
name=${0##*/}
printf '%s %s\n' "$name" "$1" >> "$WARP_TEST_ROOT/calls"
case "$name:$1" in
  pkill:*) exit 0;;
  wg:show) test -f "$WARP_TEST_ROOT/up"; exit $?;;
  wg-quick:down) rm -f "$WARP_TEST_ROOT/up"; exit 0;;
  wg-quick:up)
    if [ "$WARP_TEST_FAIL" = up ] && ! grep -q ORIGINAL "$WARP_TEST_ROOT/warp/wgcf-profile.conf"; then exit 1; fi
    touch "$WARP_TEST_ROOT/up"; exit 0;;
  wgcf:*)
    if [ "$WARP_TEST_FAIL" = "$1" ]; then echo failed >&2; exit 1; fi
    case "$1" in
      register) sleep 0.2; test ! -s wgcf-account.toml || exit 1; printf 'license_key = "FREE"\naccount = "NEW"\n' > wgcf-account.toml;;
      update) test -s wgcf-account.toml || exit 1;;
      generate)
        test -s wgcf-account.toml || exit 1
        printf '[Interface]\nPrivateKey = NEW\nAddress = 172.16.0.2/32\n[Peer]\nPublicKey = PEER\nEndpoint = engage.cloudflareclient.com:2408\nAllowedIPs = 0.0.0.0/0\n' > wgcf-profile.conf;;
    esac;;
esac
SH;
foreach (['wgcf', 'wg-quick', 'wg', 'pkill'] as $name) { file_put_contents("$root/bin/$name", $fake); chmod("$root/bin/$name", 0700); }
$failures = []; $checks = 0;
$check = function ($ok, $name) use (&$failures, &$checks) { $checks++; if (!$ok) $failures[] = $name; };
$remove = function ($path) use (&$remove) {
    if (is_dir($path)) { foreach (array_diff(scandir($path), ['.', '..']) as $f) $remove("$path/$f"); rmdir($path); }
    elseif (file_exists($path)) unlink($path);
};
$reset = function (bool $off = true) use ($root, $remove) {
    $remove("$root/warp"); mkdir("$root/warp");
    foreach (['up', 'calls'] as $f) @unlink("$root/$f");
    $b = new WarpLifecycleBot($root);
    $b->setPacConf(['warp' => 'OLD-LICENSE', 'domain' => 'example.test'] + ($off ? ['warpoff' => 1] : []));
    file_put_contents("$root/warp/wgcf-account.toml", 'ORIGINAL ACCOUNT');
    file_put_contents("$root/warp/wgcf-profile.conf", 'ORIGINAL PROFILE');
    if (!$off) touch("$root/up");
    return $b;
};
try {
    foreach ([true, false] as $off) {
        foreach (['register', 'update', 'generate', 'up'] as $fail) {
            if ($off && $fail === 'up') continue;
            $b = $reset($off); $b->fail = $fail; $b->addWarpPlus('NEW-LICENSE');
            $check($b->getPacConf()['warp'] === 'OLD-LICENSE', "$fail: прежняя лицензия сохранена");
            $check(!empty($b->getPacConf()['warpoff']) === $off, "$fail: прежний переключатель сохранён");
            $check(is_file("$root/up") === !$off, "$fail: восстановлено прежнее состояние туннеля");
            $check(file_get_contents("$root/warp/wgcf-account.toml") === 'ORIGINAL ACCOUNT'
                && file_get_contents("$root/warp/wgcf-profile.conf") === 'ORIGINAL PROFILE', "$fail: оба файла восстановлены");
        }
        foreach (['NEW-LICENSE', ''] as $key) {
            $b = $reset($off); $b->concurrentEdit = true; $b->addWarpPlus($key);
            $check(($b->getPacConf()['warp'] ?? '') === $key, 'Успешная смена free/plus');
            $check(is_file("$root/up") === !$off && !empty($b->getPacConf()['warpoff']) === $off, 'Смена ключа сохраняет off/on');
            $check(($b->getPacConf()['parallel'] ?? '') === 'saved', 'Сохранено параллельное изменение pac');
        }
    }
    $b = $reset(); $b->addWarpPlus('invalid key');
    $check(!$b->commands, 'Некорректный ключ отклонён до изменения сервера');
    $b = $reset(); $b->transportFailure = true; $b->offWarp();
    $check(!empty($b->getPacConf()['warpoff']), 'Ошибка SSH не включает переключатель');
    $b = $reset(); $b->failWrite = true;
    try { $b->offWarp(); } catch (RuntimeException $e) {}
    $check(!is_file("$root/up"), 'Ошибка записи настроек не оставляет включённый туннель');
    $b = $reset(); $dir = $b->warpClientDir('incomplete'); mkdir($dir, 0700, true);
    file_put_contents("$dir/wgcf-account.toml", 'EXISTING ACCOUNT');
    $check(is_array($b->warpClientProfile('incomplete')), 'Неполный аккаунт восстанавливается без повторной регистрации');
    $check(file_get_contents("$dir/wgcf-account.toml") === 'EXISTING ACCOUNT', 'Восстановление сохраняет зарегистрированный аккаунт');
    $b = $reset(); $b->fail = 'generate';
    $check($b->warpClientProfile('retry') === false, 'Ошибка генерации не выдаёт профиль');
    $check(is_file($b->warpClientDir('retry') . '/wgcf-account.toml'), 'Ошибка генерации сохраняет аккаунт для повтора');
    $b = new WarpLifecycleBot($root);
    $check(is_array($b->warpClientProfile('retry')), 'Повтор генерации использует сохранённый аккаунт');
    $b = $reset(); $b->fail = 'update';
    $check($b->warpClientProfile('plus-failure') === false, 'Ошибка применения WARP+ не выдаёт free-профиль молча');
    $profile = "[Interface]\nPrivateKey = KEY\nAddress = 172.16.0.2/32\n[Peer]\nPublicKey = PEER\nEndpoint = ENDPOINT\n";
    foreach (['missing-port', ':2408', 'host:0', 'host:65536', 'host:abc', '[not-ipv6]:2408'] as $endpoint) {
        $check($b->parseWarpProfile(str_replace('ENDPOINT', $endpoint, $profile)) === false, "Повреждённый endpoint отклонён: $endpoint");
    }
    $check(is_array($b->parseWarpProfile(str_replace('ENDPOINT', '[2606:4700::1]:2408', $profile))), 'IPv6 endpoint разобран');
    $b = $reset(); $b->setPacConf([]); $dir = $b->warpClientDir('free-retry'); mkdir($dir, 0700, true);
    file_put_contents("$dir/wgcf-account.toml", 'EXISTING ACCOUNT');
    $check(is_array($b->warpClientProfile('free-retry')), 'Неполный бесплатный аккаунт восстанавливается без регистрации');
    if (function_exists('pcntl_fork')) {
        $b = $reset();
        $pid = pcntl_fork();
        if ($pid === 0) exit(is_array($b->warpClientProfile('concurrent')) ? 0 : 1);
        $ok = is_array($b->warpClientProfile('concurrent'));
        pcntl_waitpid($pid, $status);
        $check($ok && pcntl_wexitstatus($status) === 0, 'Параллельные запросы получают один готовый профиль');
        $check(substr_count(file_get_contents("$root/calls"), 'wgcf register') === 1, 'На клиента регистрируется ровно одно устройство');
        $b = $reset();
        $pid = pcntl_fork();
        if ($pid === 0) exit(is_array($b->warpClientProfile('delete-race')) ? 0 : 1);
        $deadline = microtime(true) + 3;
        while (!str_contains((string) @file_get_contents("$root/calls"), 'wgcf register') && microtime(true) < $deadline) usleep(10000);
        $b->deleteWarpClient('delete-race'); pcntl_waitpid($pid, $status);
        $check(pcntl_wexitstatus($status) === 0 && !is_dir($b->warpClientDir('delete-race')),
            'Удаление ждёт генерацию и не оставляет заново созданный профиль');
    }
} finally { $remove($root); }
foreach ($failures as $failure) echo "FAIL: $failure\n";
echo 'warp_lifecycle: ' . ($checks - count($failures)) . "/$checks\n";
exit($failures ? 1 : 0);
