<?php
// make restore / restore-check (app/restore.php, BackupCli): тот же путь
// восстановления, что у файла из Telegram, ход — в stdout, отказы — в stderr
// с кодом 1, неверные аргументы — код 2. --check ничего не применяет.
require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/../app/BackupCli.php';
require __DIR__ . '/../app/i18n.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

$checks = 0;
function check(bool $condition, string $label): void { global $checks; $checks++; if (!$condition) { fwrite(STDERR, "FAIL: $label\n"); exit(1); } }

const SECRET = 'SYNTHETIC_SECRET_DO_NOT_PRINT';

class CliBot extends BackupCli
{
    public bool $failProtocols = false;
    public int $applied = 0;
    public function __construct(public string $root, array $translations, string $language = 'ru')
    {
        $this->i18n = $translations; $this->language = $language; Lang::$en = $language === 'en';
        $this->key = '1234567890:' . SECRET; $this->update = "$root/update.json"; $this->pac = "$root/pac.json";
        $this->cliOut = fopen('php://memory', 'w+'); $this->cliErr = fopen('php://memory', 'w+');
    }
    public function request($method, $data, $json_header = 0) { throw new LogicException("CLI не обращается к Telegram: $method"); }
    public function getWgMsg() { return null; }
    public function importManagedProtocols(array $data, bool $syncUpstreams = true): void { if ($this->failProtocols) throw new RuntimeException(SECRET); $this->applied++; }
    public function syncManagedUpstreams(): void {}
    public function cloakNginx() {}
    public function menu($type = false, $arg = false, $return = false) { throw new LogicException('CLI не показывает меню'); }
    public function getPacConf() { return ['language' => $this->language, 'limitpage' => 5]; }
    public function run(array $args, string $stdin): array
    {
        $in = fopen('php://memory', 'w+'); fwrite($in, $stdin); rewind($in);
        $code = $this->cli($args, $in);
        rewind($this->cliOut); rewind($this->cliErr);
        return [$code, stream_get_contents($this->cliOut), stream_get_contents($this->cliErr)];
    }
}

$root = sys_get_temp_dir() . '/vpnbot-backup-cli-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
ini_set('error_log', "$root/errors.log");
$leftovers = static fn() => glob(sys_get_temp_dir() . '/vpnbot-restore-*') ?: [];
$before = $leftovers();
try {
    $good = json_encode(['managed_protocols' => ['modules' => [], 'protocols' => []]]);

    // Неверные аргументы: подсказка и код 2, ввод не читается.
    foreach ([['--force'], ['backup.json'], ['--check', '--check']] as $args) {
        [$code, $out, $err] = (new CliBot($root, $i))->run($args, $good);
        check($code === 2 && $out === '' && str_contains($err, 'make restore FILE='), 'аргументы ' . implode(' ', $args));
    }
    [$code, , $err] = (new CliBot($root, $i, 'en'))->run(['-h'], '');
    check($code === 2 && !preg_match('~[а-яё]~iu', $err), 'подсказка на английском');

    // Не копия бота: код 1, понятная причина, ничего не применено.
    foreach (['' => 'пусто', 'broken' => 'не JSON', '[]' => 'пустой массив', '{"other":1}' => 'чужой JSON',
        '{"pac":"x"}' => 'неверный раздел', '{"wg":{"clients":[]}}' => 'неполный WireGuard',
        str_repeat(' ', Bot::BACKUP_MAX_BYTES) . '{"pac":{}}' => 'больше предела'] as $stdin => $label) {
        $b = new CliBot($root, $i);
        [$code, $out, $err] = $b->run([], (string) $stdin);
        check($code === 1 && $b->applied === 0 && str_contains($err, 'Восстановление прервано') && str_contains($err, 'JSON'), "$label: отказ");
    }

    // --check: разделы перечислены, ничего не применено.
    $b = new CliBot($root, $i);
    [$code, $out, $err] = $b->run(['--check'], json_encode(['pac' => [], 'xray' => [], 'unknown' => 1]));
    check($code === 0 && $err === '' && trim($out) === 'Разделы копии: pac, xray' && $b->applied === 0, '--check');

    // Восстановление: ход построчно, без повторов, итог, код 0, временный файл удалён.
    $b = new CliBot($root, $i);
    [$code, $out, $err] = $b->run([], $good);
    $lines = explode("\n", trim($out));
    check($code === 0 && $err === '' && $b->applied === 1, 'восстановление: код 0');
    check($lines[0] === 'Разделы копии: managed_protocols' && end($lines) === '✅ Восстановление завершено.', 'восстановление: разделы и итог');
    check(count($lines) === count(array_unique($lines)), 'восстановление: строки не повторяются');
    check($leftovers() === $before, 'временный файл удалён');

    // Отказ применения: код 1, этап назван, текст исключения не печатается.
    $b = new CliBot($root, $i); $b->failProtocols = true;
    [$code, $out, $err] = $b->run([], $good);
    check($code === 1 && str_contains($err, 'Восстановление прервано') && !str_contains($out . $err, SECRET), 'отказ применения');
    check(!str_contains((string) file_get_contents("$root/errors.log"), SECRET), 'журнал без текста исключения');
    check($leftovers() === $before, 'временный файл удалён и после отказа');

    // Чужая операция бэкапа держит блокировку: восстановление не начинается.
    $lock = fopen("$root/.backup.lock", 'c'); flock($lock, LOCK_EX);
    $b = new CliBot($root, $i);
    [$code, , $err] = $b->run([], $good);
    check($code === 1 && $b->applied === 0 && $err !== '', 'занятая блокировка');
    flock($lock, LOCK_UN); fclose($lock);

    // update() получает весь список этапов — печатаются только новые строки.
    $b = new CliBot($root, $i);
    $b->update(0, 0, 'a'); $b->update(0, 0, "a\nb"); $b->update(0, 0, "a\nb\n<b>c &amp; d</b>"); $b->send(0, '<code>e</code>');
    rewind($b->cliOut);
    check(stream_get_contents($b->cliOut) === "a\nb\nc & d\ne\n", 'вывод хода');

    // Копия старого формата на новой установке (только TeleMT) возвращает набор по умолчанию.
    $b = new CliBot($root, $i); $b->protocolModulesFile = "$root/protocol-services.json";
    $fresh = array_map(static fn($k) => $k === 'telemt', array_combine(array_keys(ProtocolModules::DEFAULTS), array_keys(ProtocolModules::DEFAULTS)));
    file_put_contents($b->protocolModulesFile, json_encode($fresh));
    $b->restoreLegacyModules(['dnstt' => []]);
    check(json_decode(file_get_contents($b->protocolModulesFile), true) === $fresh, 'частичная копия не трогает модули');
    $b->restoreLegacyModules(['pac' => [], 'managed_protocols' => ['modules' => [], 'protocols' => []]]);
    check(json_decode(file_get_contents($b->protocolModulesFile), true) === $fresh, 'новый формат переключает модули сам');
    $b->restoreLegacyModules(['pac' => [], 'wg' => []]);
    check((new ProtocolModules($b->protocolModulesFile))->read() === ProtocolModules::DEFAULTS, 'полная копия старого формата — набор по умолчанию');
    $b->protocolModulesFile = "$root/missing/protocol-services.json";
    $b->restoreLegacyModules(['pac' => []]);
    check(!file_exists($b->protocolModulesFile), 'без файла (уже по умолчанию) ничего не пишется');
    check(str_contains(file_get_contents(__DIR__ . '/../app/bot.php'), '$this->restoreLegacyModules($json)'), 'restoreBackup вызывает restoreLegacyModules');

    // Список разделов один для меню и CLI.
    $src = file_get_contents(__DIR__ . '/../app/bot.php');
    check(str_contains($src, 'array_intersect(array_keys($json), self::BACKUP_SECTIONS)'), 'restoreBackup использует BACKUP_SECTIONS');
    $restore = file_get_contents(__DIR__ . '/../app/restore.php');
    check(str_contains($restore, "PHP_SAPI !== 'cli'") && !str_contains($restore, 'debug.php'), 'restore.php только для CLI, без debug.php (он читает stdin)');
    $make = file_get_contents(__DIR__ . '/../makefile');
    check(str_contains($make, 'exec -T php php /app/restore.php <') && str_contains($make, 'exec -T php php /app/restore.php --check <'), 'make restore / restore-check');
} finally {
    exec('rm -rf ' . escapeshellarg($root));
}
echo "backup_cli_test: $checks checks OK\n";
