<?php
require_once __DIR__ . '/../app/bot.php';

set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return true;
});
$root = sys_get_temp_dir() . '/vpnbot-hysteria-' . bin2hex(random_bytes(8));
mkdir($root, 0700);
$check = static function (bool $ok, string $message) { if (!$ok) throw new RuntimeException($message); };
$children = [];
try {
    $store = new HysteriaUsers($root);
    $id = $store->add('Иван & <тест>');
    $user = $store->read()['users'][$id];
    $check((fileperms($root . '/users.json') & 0777) === 0600, 'Реквизиты созданы с 0600');
    $before = file_get_contents($root . '/users.json');
    foreach (['Иван & <тест>', '', "плохое\nимя", str_repeat('я', 61)] as $name) {
        try { $store->add($name); throw new RuntimeException('Принято неверное имя'); }
        catch (InvalidArgumentException $e) {}
        $check(file_get_contents($root . '/users.json') === $before, 'Ошибочный ввод сохранил исходный файл');
    }
    $store->edit($id, 'toggle');
    $store->edit($id, 'name', 'Новое имя');
    $check(!$store->read()['users'][$id]['enabled'], 'Переименование не включает доступ');
    $check($store->read()['users'][$id]['password'] === $user['password'], 'Переименование сохраняет реквизиты');
    $store->edit($id, 'rotate');
    $check($store->read()['users'][$id]['password'] !== $user['password'], 'Ротация меняет реквизиты');
    $store->edit($id, 'quota', 123456);
    $store->edit($id, 'expires', time() + 60);
    mkdir($root . '/runtime', 0700);
    $user = $store->read()['users'][$id];
    ManagedProtocol::writeJson($root . '/runtime/usage.json', ['time' => time(), 'users' => [$id => ['reset' => $user['reset'], 'upload' => 123, 'download' => 456]]]);
    $snapshot = $store->snapshot();
    $bad = $snapshot;
    $bad['usage']['users'][$id]['upload'] = -1;
    $before = file_get_contents($root . '/users.json');
    try { $store->restore($bad); throw new RuntimeException('Повреждённый бэкап принят'); }
    catch (InvalidArgumentException $e) {}
    $check(file_get_contents($root . '/users.json') === $before, 'Неверный бэкап ничего не записал');
    $store->edit($id, 'delete');
    $store->restore($snapshot);
    $check($store->read()['users'][$id] === $user, 'Бэкап возвращает точные реквизиты, срок, off и квоту');
    $check($store->read()['restore_usage']['users'][$id]['download'] === 456, 'Бэкап передаёт расход контроллеру');
    $store->edit($id, 'reset');
    $check($store->read()['users'][$id]['reset'] !== $user['reset'], 'Сброс создаёт новый период');
    try { $store->snapshot(); throw new RuntimeException('Неприменённый сброс попал в бэкап'); }
    catch (RuntimeException $e) { $check(str_contains($e->getMessage(), 'Дождитесь'), 'Снимок ждёт счётчики нового периода'); }
    $empty = ['state' => ['schema' => 1, 'protocol' => 'hysteria2', 'revision' => 0, 'users' => []], 'usage' => ['users' => []]];
    $store->restore($empty);
    $raw = json_decode(file_get_contents($root . '/users.json'));
    $check(is_object($raw->users) && is_object($raw->restore_usage->users), 'Пустые карты совместимы с Python');
    $numeric = '1234567890123456';
    $store->change(static function (&$state) use ($numeric, $user) { $state['users'][$numeric] = $user; });
    $check(isset($store->read()['users'][$numeric]), 'Hex ID из одних цифр переживает PHP JSON');
    if (function_exists('pcntl_fork')) {
        for ($n = 0; $n < 8; $n++) {
            $pid = pcntl_fork();
            if ($pid === 0) { $store->add('Конкурент ' . $n); exit; }
            $check($pid > 0, 'fork'); $children[] = $pid;
        }
        foreach ($children as $pid) { pcntl_waitpid($pid, $status); $check(pcntl_wexitstatus($status) === 0, 'Параллельное создание'); }
        $children = [];
        $check(count($store->read()['users']) === 9, 'Одновременные записи не теряют пользователей');
    }
    echo "hysteria_users_test: OK\n";
} finally {
    foreach ($children as $pid) pcntl_waitpid($pid, $status);
    $remove = static function ($path) use (&$remove) {
        if (is_dir($path)) { foreach (scandir($path) as $file) if ($file !== '.' && $file !== '..') $remove("$path/$file"); rmdir($path); }
        else unlink($path);
    }; $remove($root);
}
