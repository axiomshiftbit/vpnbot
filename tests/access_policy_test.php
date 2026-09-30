<?php
require_once __DIR__ . '/../app/bot.php';

function policyCheck(bool $ok, string $name): void { if (!$ok) throw new RuntimeException($name); }
$ts = static fn($s) => AccessPolicy::date($s);
$anchor = $ts('2028-01-31 23:30');
policyCheck(AccessPolicy::next('month', $anchor, $anchor) === $ts('2028-02-29 23:30'), 'Високосный февраль');
policyCheck(AccessPolicy::next('month', $anchor, $ts('2028-02-29 23:30')) === $ts('2028-03-31 23:30'), 'Март сохраняет 31 число');
policyCheck(AccessPolicy::next('month', $anchor, $ts('2030-04-01 00:00')) === $ts('2030-04-30 23:30'), 'Простой на несколько лет');
policyCheck(AccessPolicy::next('week', $anchor, $anchor + 604800) === $anchor + 1209600, 'Ровно на границе недели');
policyCheck(AccessPolicy::next('day', $anchor, $anchor - 1) === $anchor, 'До первого сброса');
try { AccessPolicy::validate(['quota_schedule' => ['period' => []]]); throw new LogicException('Битое расписание принято'); } catch (InvalidArgumentException $e) {}
try { AccessPolicy::validate(['alerts' => ['percent' => 101, 'days' => 3]]); throw new LogicException('Битый порог принят'); } catch (InvalidArgumentException $e) {}
foreach (['2026-02-30 00:00', '2026-01-01 24:00', 'now', '2026-01-01 00:00Z'] as $bad) {
    try { AccessPolicy::date($bad); throw new LogicException('Дата принята'); } catch (InvalidArgumentException $e) {}
}
$user = ['name' => 'Test', 'enabled' => false, 'expires' => $anchor - 1, 'quota' => 100,
    'reset' => str_repeat('a', 16), 'quota_schedule' => ['period' => 'month', 'anchor' => $anchor, 'next' => $anchor],
    'alerts' => ['percent' => 80, 'days' => 3]];
$state = ['users' => ['abcd' => $user]];
policyCheck(AccessPolicy::resetDue($state, $anchor) === ['abcd'], 'Сброс наступил');
policyCheck(!$state['users']['abcd']['enabled'] && $state['users']['abcd']['expires'] === $anchor - 1, 'Сброс не включает и не продлевает доступ');
policyCheck($state['users']['abcd']['reset'] !== $user['reset'], 'Новый период счётчика');
policyCheck(AccessPolicy::resetDue($state, $anchor) === [], 'Повторный тик идемпотентен');
$user['enabled'] = true; $row = ['reset' => $user['reset'], 'upload' => 30, 'download' => 50];
$events = AccessPolicy::events($user, $row, $anchor);
policyCheck(count($events) === 2, 'Оба предупреждения на границе');
policyCheck(!isset(AccessPolicy::events($user, null, $anchor)['quota']), 'Нет предупреждения по неизвестному расходу');
policyCheck(AccessPolicy::bytes($user, ['reset' => $user['reset'], 'upload' => PHP_INT_MAX, 'download' => 1]) === null, 'Повреждённый расход не переполняет целое число');
$state = ['users' => ['abcd' => $user + ['xray_source' => str_repeat('b', 32)]]];
policyCheck(AccessPolicy::resetDue($state, $anchor) === [], 'Общий расход связанных пользователей не обнуляется');
$user['reset'] = str_repeat('c', 16); $row['reset'] = $user['reset'];
policyCheck(AccessPolicy::events($user, $row, $anchor)['quota'] !== $events['quota'], 'Новый период допускает новое предупреждение');

class PolicyCronBot extends Bot
{
    public array $sent = []; public bool $failSend = false;
    public function __construct(string $root) {
        $this->hysteriaUsersRoot = "$root/hy"; $this->protocolRoot = "$root/protocols";
        $this->protocolModulesFile = "$root/protocol-services.json";
    }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function accessAlertAdmins(): array { return [100, 200]; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) {
        $this->sent[] = [$chat, $text]; return $this->failSend ? [] : ['result' => ['message_id' => 1]];
    }
}
$root = sys_get_temp_dir() . '/vpnbot-policy-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
try {
    $bot = new PolicyCronBot($root); $store = $bot->hysteriaUsersStore(); $id = $store->add('<Test>');
    $now = time();
    $store->change(static function (&$s) use ($id, $now) {
        $s['users'][$id]['alerts'] = ['percent' => 80, 'days' => 3];
        $s['users'][$id]['quota'] = 100; $s['users'][$id]['expires'] = $now + 86400;
    });
    mkdir($store->root . '/runtime', 0700);
    $row = ['reset' => $store->read()['users'][$id]['reset'], 'upload' => 30, 'download' => 50];
    ManagedProtocol::writeJson($store->root . '/runtime/usage.json', ['users' => [$id => $row]]);
    ManagedProtocol::writeJson($store->root . '/runtime/status.json', ['time' => $now, 'stats_time' => $now, 'running' => true]);
    $bot->failSend = true; $bot->checkAccessPolicies($now);
    policyCheck(count($bot->sent) === 4, 'Попытка уведомить обоих администраторов');
    $bot->failSend = false; $bot->checkAccessPolicies($now); $bot->checkAccessPolicies($now);
    policyCheck(count($bot->sent) === 8, 'Ошибка отправки повторяется, успех не дублируется');
    policyCheck(str_contains($bot->sent[0][1], '&lt;Test&gt;'), 'Имя экранировано');
    $revision = $store->read()['revision']; $bot->checkAccessPolicies($now);
    policyCheck($store->read()['revision'] === $revision, 'Пустой тик не меняет ревизию');
    $snapshot = $store->snapshot(); $store->restore($snapshot);
    policyCheck($store->read()['users'][$id]['alerts'] === ['percent' => 80, 'days' => 3], 'Backup сохраняет политику');
    $store->edit($id, 'delete'); $bot->checkAccessPolicies($now);
    policyCheck(ManagedProtocol::readJson("$root/access-alerts.json") === [], 'Удаление пользователя убирает маркеры');
} finally {
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $f) $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
    rmdir($root);
}
echo "access_policy_test OK\n";
