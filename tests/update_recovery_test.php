<?php

require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';

function recoveryAssert(bool $ok, string $message): void
{
    if (!$ok) throw new RuntimeException($message);
}
function recoveryRun(array $args, string $cwd, bool $success = true): string
{
    $p = proc_open($args, [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $cwd);
    $out = stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    $code = proc_close($p);
    recoveryAssert(($code === 0) === $success, 'Неожиданный результат ' . $args[0] . ': ' . $err);
    return $out;
}
function recoveryRemove(string $path): void
{
    if (is_dir($path) && !is_link($path)) {
        foreach (scandir($path) as $name) if ($name !== '.' && $name !== '..') recoveryRemove("$path/$name");
        rmdir($path);
    } else unlink($path);
}

class RecoveryBot extends Bot
{
    public bool $importOk = true;
    public bool $throws = false;
    public int $imports = 0;
    public array $calls = [];
    public function __construct(string $dir, array $translations)
    {
        $this->update = "$dir/json";
        $this->pac = "$dir/pac.json";
        $this->i18n = $translations;
        $this->language = 'ru';
        file_put_contents($this->pac, '{}');
    }
    public function importFile($file = false)
    {
        $this->imports++;
        if ($this->throws) throw new RuntimeException('synthetic restore failure');
        if (!$this->importOk) return false;
        return $this->setPacConf(json_decode(file_get_contents($file), true)['pac']);
    }
    public function request($method, $data, $json_header = 0)
    {
        $this->calls[] = [$method, $data];
        return ['ok' => true, 'result' => ['message_id' => 1]];
    }
    public function migrateDohClientIds(): bool { return true; }
}

class CancelUpdateBot extends RecoveryBot
{
    public bool $queued = false;
    public function pinBackup($file = false) { return false; }
    public function queueUpdateCommand(string $command, array $draft): bool
    {
        $this->queued = true;
        return true;
    }
}

$tmp = sys_get_temp_dir() . '/vpnbot-recovery-' . bin2hex(random_bytes(6));
mkdir($tmp, 0700);
try {
    mkdir("$tmp/cancel", 0700);
    $cancel = new CancelUpdateBot("$tmp/cancel", $i);
    $cancel->input = ['from' => 1, 'chat' => 1, 'message_id' => 1];
    $cancel->applyupdatebot();
    recoveryAssert(!$cancel->queued && $cancel->calls[0][1]['text'] === $cancel->i18n('update worker busy'), 'Без службы обновления команда не ставится и об этом сообщается');
    file_put_contents("$tmp/cancel/update_pid", '1');
    file_put_contents("$tmp/cancel/pipe", '1');
    $cancel->calls = [];
    $cancel->applyupdatebot();
    recoveryAssert(!$cancel->queued && $cancel->calls[0][1]['text'] === $cancel->i18n('update worker busy'), 'Невзятая прошлая команда не перекрывается новой');
    file_put_contents("$tmp/cancel/pipe", '');
    $cancel->calls = [];
    $cancel->applyupdatebot();
    recoveryAssert(!$cancel->queued, 'Отказ резервной копии не запускает обновление');
    recoveryAssert(count($cancel->calls) === 1 && $cancel->calls[0][0] === 'sendMessage', 'Отмена сообщается пользователю');

    foreach (['legacy', 'preserved', 'invalid', 'failure', 'exception'] as $case) {
        mkdir("$tmp/$case", 0700);
        $b = new RecoveryBot("$tmp/$case", $i);
        $snapshot = $case === 'invalid' ? 'broken' : json_encode(['pac' => ['domain' => 'saved.example', 'hash' => 'saved']]);
        file_put_contents($b->update, $snapshot);
        file_put_contents("$tmp/$case/reload_message", '1:');
        if ($case === 'preserved') {
            file_put_contents("$tmp/$case/state-restored", '');
            $b->setPacConf(['domain' => 'live.example', 'hash' => 'live']);
        }
        $b->importOk = $case !== 'failure';
        $b->throws = $case === 'exception';
        $ok = in_array($case, ['legacy', 'preserved'], true);
        recoveryAssert($b->selfUpdate() === $ok, "$case: исход восстановления");
        if ($ok) {
            recoveryAssert(!is_file($b->update) && file_get_contents($b->update . '.last') === $snapshot, 'Последняя резервная копия сохранена');
            recoveryAssert((fileperms($b->update . '.last') & 0777) === 0600, 'Резервная копия закрыта');
            recoveryAssert($b->getPacConf()['domain'] === ($case === 'legacy' ? 'saved.example' : 'live.example'), 'Домен сохранён');
            recoveryAssert($b->imports === ($case === 'legacy' ? 1 : 0), 'Точное состояние не заменяется повторным импортом');
        } else {
            recoveryAssert(file_get_contents($b->update) === $snapshot, 'Ошибка не удаляет снимок');
            recoveryAssert(!is_file($b->update . '.last'), 'Ошибка не объявлена успешным восстановлением');
        }
    }

    // Настоящий Git и настоящий helper, только синтетические рабочие данные.
    $repo = "$tmp/checkout";
    mkdir($repo, 0700);
    foreach (['config', 'certs', 'update', 'app'] as $dir) mkdir("$repo/$dir", 0700);
    file_put_contents("$repo/.gitignore", "update/*\ncerts/*\napp/config.php\n");
    file_put_contents("$repo/config/pac.json", '{}');
    file_put_contents("$repo/config/static.conf", 'template-v1');
    file_put_contents("$repo/config/deleted.conf", 'remove-me');
    file_put_contents("$repo/.env", "CUSTOM=default\n");
    recoveryRun(['git', 'init', '-q', '-b', 'dev'], $repo);
    recoveryRun(['git', 'config', 'user.name', 'axiomshiftbit'], $repo);
    recoveryRun(['git', 'config', 'user.email', '227203165+axiomshiftbit@users.noreply.github.com'], $repo);
    recoveryRun(['git', 'add', '.gitignore', '.env', 'config'], $repo);
    recoveryRun(['git', 'commit', '-qm', 'Synthetic update fixture'], $repo);
    $files = ['config/pac.json' => '{"domain":"saved.example","clients":["synthetic-client"]}',
        'config/new data.json' => 'generated runtime', 'certs/cert_private' => 'synthetic-private-data',
        'app/config.php' => '<?php $c = ["key" => "synthetic"];', '.env' => "CUSTOM=installation\n"];
    foreach ($files as $path => $value) file_put_contents("$repo/$path", $value);
    chmod("$repo/certs/cert_private", 0600);
    unlink("$repo/config/deleted.conf");
    $helper = __DIR__ . '/../scripts/preserve_update_state.sh';
    recoveryRun(['bash', $helper, 'save', $repo], $repo);
    recoveryRun(['bash', $helper, 'save', $repo], $repo, false);
    recoveryAssert((fileperms("$repo/update/runtime-state") & 0777) === 0700, 'Снимок вне Git закрыт');
    recoveryRun(['git', 'restore', '--source=HEAD', '--worktree', '.'], $repo);
    recoveryRun(['git', 'clean', '-fd', '-e', '/update/'], $repo);
    file_put_contents("$repo/config/static.conf", 'template-v2');
    file_put_contents("$repo/config/new-template.conf", 'new-template');
    recoveryRun(['bash', $helper, 'restore', $repo], $repo);
    foreach ($files as $path => $value) recoveryAssert(file_get_contents("$repo/$path") === $value, "$path: данные пережили Git");
    recoveryAssert(file_get_contents("$repo/config/static.conf") === 'template-v2', 'Неизменённые шаблоны обновляются');
    recoveryAssert(is_file("$repo/config/new-template.conf"), 'Новые шаблоны не удалены');
    recoveryAssert(!is_file("$repo/config/deleted.conf"), 'Намеренное удаление сохранено');
    recoveryAssert((fileperms("$repo/certs/cert_private") & 0777) === 0600, 'Права секрета сохранены');
    recoveryAssert(is_file("$repo/update/state-restored") && is_dir("$repo/update/runtime-state.last"), 'Результат восстановления и последний снимок сохранены');

    // Исполняем сам service.php в отдельном PHP-процессе, подменяя только Bot.
    $boot = "$tmp/boot";
    mkdir($boot, 0700);
    copy(__DIR__ . '/../app/service.php', "$boot/service.php");
    file_put_contents("$boot/timezone.php", '<?php');
    file_put_contents("$boot/config.php", '<?php $c = ["key" => "synthetic", "debug" => false];');
    file_put_contents("$boot/i18n.php", '<?php $i = [];');
    file_put_contents("$boot/bot.php", <<<'PHP'
<?php
class Bot {
    public const PAC_DEFAULTS = ['transport' => 'Websocket', 'domain' => ''];
    public string $update = __DIR__ . '/json';
    public bool $selfupdate = false;
    public int $dontshowcron = 0;
    public int $sshStartupWait = 0;
    public function __construct(...$args) {}
    public function getPacConf() { return self::PAC_DEFAULTS; }
    public function selfUpdate() { return !is_file(__DIR__ . '/fail'); }
    public function sslip($initial) { echo json_encode(['initialSetup' => $initial]); }
    public function __call($method, $args) {}
}
PHP);
    recoveryAssert(json_decode(recoveryRun(['php', 'service.php'], $boot), true)['initialSetup'] === true, 'Чистая установка настраивается автоматически');
    file_put_contents("$boot/json", 'synthetic snapshot');
    recoveryAssert(json_decode(recoveryRun(['php', 'service.php'], $boot), true)['initialSetup'] === false, 'Обновление не превращается в первый запуск');
    file_put_contents("$boot/fail", '');
    recoveryAssert(recoveryRun(['php', 'service.php'], $boot, false) === '', 'Сбой восстановления останавливает автоконфигурацию');

    // Исполняем PHP-часть настоящего entrypoint: после отказа service.php
    // ни cron, ни обработчик IP-лимитов запускаться не должны.
    $entrypoint = strstr(file_get_contents(__DIR__ . '/../scripts/start_service.sh'), 'php service.php');
    recoveryAssert(is_string($entrypoint), 'Найден запуск PHP в entrypoint');
    mkdir("$boot/bin", 0700);
    file_put_contents("$boot/bin/php", <<<'SH'
#!/bin/sh
echo "$1" >> calls
if [ "$1" = service.php ] && [ -f fail ]; then exit 1; fi
exit 0
SH);
    chmod("$boot/bin/php", 0700);
    $command = ['env', 'PATH=' . "$boot/bin:" . getenv('PATH'), 'sh', '-c', $entrypoint];
    recoveryRun($command, $boot, false);
    recoveryAssert(file_get_contents("$boot/calls") === "service.php\n", 'Ошибка восстановления блокирует фоновые задачи');
    unlink("$boot/fail");
    unlink("$boot/calls");
    recoveryRun($command, $boot);
    $calls = file("$boot/calls", FILE_IGNORE_NEW_LINES);
    sort($calls);
    recoveryAssert($calls === ['cron.php', 'iplimit.php', 'service.php'], 'Успешный старт запускает фоновые задачи');
} finally {
    recoveryRemove($tmp);
}
echo "update_recovery_test OK\n";
