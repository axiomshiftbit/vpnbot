<?php
require_once __DIR__ . '/../app/bot.php';

// Реальные методы меню/очистки; подменены только каталог и Telegram API.
class LogMenuTestBot extends Bot
{
    public string $dir;
    public array $buttons = [];
    public array $files = [];
    public array $answers = [];
    public array $pacFake = [];
    protected function logDirectory(): string { return $this->dir; }
    public function getPacConf() { return $this->pacFake; }
    public function setPacConf(array $conf) { $this->pacFake = $conf; return true; }
    public function i18n(string $menu): string { return $menu; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->buttons = $button; }
    public function sendFile($chat, $id_url_cFile, $caption = false, $to = false) { $this->files[] = $id_url_cFile->getFilename(); }
    public function answer($callback_id, $textNotify = false, $notify = false) { $this->answers[] = $textNotify; }
}
$checks = 0;
function logCheck(bool $ok, string $message): void {
    global $checks;
    $checks++;
    if (!$ok) throw new RuntimeException($message);
}
$root = sys_get_temp_dir() . '/vpnbot-logs-' . bin2hex(random_bytes(6));
mkdir($root);
$b = (new ReflectionClass(LogMenuTestBot::class))->newInstanceWithoutConstructor();
$b->dir = "$root/logs";
$b->protocolRoot = "$root/protocols";
$b->hysteriaUsersRoot = "$root/hysteria";
$b->input = ['chat' => 1, 'message_id' => 2, 'callback_id' => 'test'];
try {
    logCheck($b->logFiles() === [], 'Отсутствующий каталог безопасен');
    mkdir($b->dir);
    $protected = ['xray_core' => '3', 'menu_status.json' => '{}', 'menu_versions.json' => '{}', 'sub_ratelimit.json' => '{"requests":9}', '.lock.telemt' => 'lock'];
    foreach ($protected as $name => $data) file_put_contents("$b->dir/$name", $data);
    mkdir("$b->dir/geodata");
    file_put_contents("$root/outside", 'keep');
    symlink("$root/outside", "$b->dir/linked");
    foreach (['wireguard', 'wireguard1', 'warp', 'shadowsocks', 'shadowsocks_proxy', 'telemt'] as $name) file_put_contents("$b->dir/$name", "$name test log\n");
    foreach (['anytls', 'mieru', 'tuic', 'shadowtls', 'masque'] as $protocol) {
        mkdir("$b->protocolRoot/$protocol/runtime", 0777, true);
        foreach (['core.log', 'core.previous.log'] as $name) file_put_contents("$b->protocolRoot/$protocol/runtime/$name", "$protocol $name\n");
        file_put_contents("$b->protocolRoot/$protocol/runtime/status.json", '{"phase":"running"}');
        file_put_contents("$b->protocolRoot/$protocol/runtime/usage.json", '{"bytes":99}');
    }
    mkdir("$b->hysteriaUsersRoot/runtime", 0700, true);
    file_put_contents("$b->hysteriaUsersRoot/runtime/core.log", "hysteria native log\n");
    file_put_contents("$b->hysteriaUsersRoot/runtime/usage.json", '{"bytes":123}');
    logCheck(count($b->logFiles()) === 17, 'Доступны плоские журналы, пять протоколов и нативный журнал Hysteria');
    foreach ($protected as $name => $data) logCheck(!in_array($name, $b->logFiles(), true), "Служебный файл $name скрыт");
    $b->getLog('anytls.core.previous.log');
    logCheck($b->files === ["$b->protocolRoot/anytls/runtime/core.previous.log"], 'Кнопка отдаёт нужный журнал');
    foreach (['../outside', 'linked', 'xray_core', 'anytls.status.json'] as $name) { $b->getLog($name); $b->clearLog($name); $b->delLog($name); }
    logCheck(count($b->files) === 1, 'Обход пути, ссылка и служебные файлы не отправлены');
    $b->getLog('hysteria.core.log');
    logCheck(end($b->files) === "$b->hysteriaUsersRoot/runtime/core.log", 'Нативный журнал Hysteria доступен из меню');
    $writer = fopen("$b->dir/telemt", 'ab');
    $inode = fileinode("$b->dir/telemt");
    $b->clearLog('telemt');
    fwrite($writer, "after clear\n"); fflush($writer);
    logCheck(file_get_contents("$b->dir/telemt") === "after clear\n", 'Работающий демон продолжает писать после очистки');
    $b->delLog('telemt');
    fwrite($writer, "after legacy delete\n"); fclose($writer);
    logCheck(fileinode("$b->dir/telemt") === $inode && file_get_contents("$b->dir/telemt") === "after legacy delete\n", 'Старая кнопка удаления не теряет inode демона');
    $b->cleanLog();
    foreach ($b->logFiles() as $name) {
        $before = count($b->files); $b->getLog($name);
        logCheck(count($b->files) === $before && end($b->answers) === 'log empty', "Пустой $name не отправляется в Telegram");
    }
    foreach ($protected as $name => $data) logCheck(file_get_contents("$b->dir/$name") === $data, "$name не стёрт общей очисткой");
    logCheck(file_get_contents("$root/outside") === 'keep', 'Цель симлинка не изменена');
    logCheck(file_get_contents("$b->protocolRoot/anytls/runtime/usage.json") === '{"bytes":99}', 'Расход протокола не сброшен');
    logCheck(file_get_contents("$b->hysteriaUsersRoot/runtime/usage.json") === '{"bytes":123}', 'Очистка Hysteria не сбрасывает расход');
    rename($b->hysteriaUsersRoot, "$root/hysteria-moved");
    symlink("$root/hysteria-moved", $b->hysteriaUsersRoot);
    logCheck(!in_array('hysteria.core.log', $b->logFiles(), true), 'Симлинк каталога Hysteria отфильтрован');
    unlink("$b->protocolRoot/tuic/runtime/core.log");
    symlink("$root/outside", "$b->protocolRoot/tuic/runtime/core.log");
    logCheck(!in_array('tuic.core.log', $b->logFiles(), true), 'Симлинк в журнале протокола отфильтрован');
    rename("$b->protocolRoot/masque", "$root/moved");
    symlink("$root/moved", "$b->protocolRoot/masque");
    logCheck(!in_array('masque.core.log', $b->logFiles(), true), 'Симлинк в каталоге протокола отфильтрован');
    for ($i = 0; $i < 50; $i++) file_put_contents("$b->dir/extra_$i", 'log');
    $seen = [];
    foreach (range(0, 3) as $page) {
        $b->logs($page); $buttons = array_merge(...$b->buttons);
        logCheck(count($buttons) < 100, 'Клавиатура помещается в лимит Telegram');
        foreach ($buttons as $button) {
            logCheck(strlen($button['callback_data']) <= 64, 'Callback не длиннее 64 байт');
            if (str_starts_with($button['callback_data'], '/getLog ')) $seen[] = substr($button['callback_data'], 8);
        }
    }
    logCheck($seen === $b->logFiles(), 'Пагинация показывает каждый журнал ровно один раз');
    foreach (['wrong', 'now', '/1 day', 'now/1 day/extra', 'now/1 day'] as $schedule) { $b->pacFake = ['autocleanlogs' => $schedule]; $b->logs(999); }
    $b->logs(-10);
    $b->input = [];
    $b->buttons = [];
    $b->pacFake = ['autocleanlogs' => date('Y-m-d') . '/1 hour'];
    $b->checkLogs();
    logCheck($b->buttons === [], 'Плановая очистка не пытается обновить сообщение Telegram');
    logCheck(!empty($b->pacFake['last_clean_logs_time']), 'Плановая очистка сохраняет время выполнения');
    echo "logs_test OK: $checks checks\n";
} finally {
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $file) { if ($file->isDir() && !$file->isLink()) rmdir($file->getPathname()); else unlink($file->getPathname()); }
    rmdir($root);
}
