<?php
require_once __DIR__ . '/../app/bot.php';
function batchCheck(bool $ok, string $label): void { if (!$ok) throw new RuntimeException($label); }
$now = time(); $id = str_repeat('a', 16); $second = str_repeat('b', 16);
$users = [$id => ['name' => 'Первый', 'enabled' => false, 'expires' => $now - 100, 'quota' => 100, 'reset' => str_repeat('c', 16)],
    $second => ['name' => 'Общий', 'enabled' => true, 'expires' => null, 'quota' => null, 'reset' => str_repeat('d', 16), 'xray_source' => str_repeat('e', 32)]];
$plan = AccessBatch::preview($users, [$id, $second], 'extend', 2, $now);
batchCheck($plan['rows'][0]['after']['expires'] === $now + 172800 && $plan['rows'][1]['skip'] !== '', 'Просмотр продления и пропуск связанного доступа');
$changed = $users; $changed[$id]['name'] = 'Переименован'; $before = $changed;
try { AccessBatch::apply($changed, $plan, $now); throw new LogicException('Изменившийся пользователь принят'); } catch (InvalidArgumentException $e) {}
batchCheck($changed === $before, 'Устаревшее подтверждение не меняет ни одного пользователя');
batchCheck(AccessBatch::apply($users, $plan, $now) === 1 && !$users[$id]['enabled'], 'Продление сохраняет ручное отключение');
$plan = AccessBatch::preview($users, [$id], 'reset', null, $now); $old = $users[$id]['reset'];
AccessBatch::apply($users, $plan, $now);
batchCheck($users[$id]['reset'] !== $old && !$users[$id]['enabled'], 'Сброс не включает доступ');
try { AccessBatch::apply($users, $plan, $now); throw new LogicException('Повтор принят'); } catch (InvalidArgumentException $e) {}
batchCheck(AccessBatch::value('quota', '0,5') === 536870912 && AccessBatch::value('quota', '0') === null, 'Разбор квоты');
try { AccessBatch::apply($users, $plan, $now + 601); throw new LogicException('Истёкший просмотр принят'); } catch (InvalidArgumentException $e) {}
foreach (['-1', '1e3', '1000001', 'NaN'] as $bad) {
    try { AccessBatch::value('quota', $bad); throw new LogicException('Неверная квота принята'); } catch (InvalidArgumentException $e) {}
}
$group = [];
for ($n = 0; $n < 21; $n++) $group[sprintf('%016x', $n)] = $users[$id];
$selected = array_map('strval', array_slice(array_keys($group), 0, 20));
$groupPlan = AccessBatch::preview($group, $selected, 'quota', 4096, $now);
batchCheck(AccessBatch::apply($group, $groupPlan, $now) === 20, 'Одна операция меняет 20 выбранных пользователей');
batchCheck($group[sprintf('%016x', 20)]['quota'] === 100, 'Невыбранный 21-й пользователь сохранён');
try { AccessBatch::preview($group, array_keys($group), 'reset', null, $now); throw new LogicException('Принят 21 пользователь'); } catch (InvalidArgumentException $e) {}

class AccessBatchBot extends Bot
{
    public array $buttons = []; public array $messages = [];
    public function __construct(string $root) { $this->admin = true; $this->hysteriaUsersRoot = $root; $this->input = ['chat' => 1, 'from' => 1, 'message_id' => 1]; }
    protected function sessionApply(callable $fn) { $fn(); }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->messages[] = $text; $this->buttons = $button; }
    public function protocolError(string $message, string $back, string $retry = ''): void { $this->messages[] = $message; }
    public function i18n(string $menu): string { return $menu; }
}
$root = sys_get_temp_dir() . '/vpnbot-batch-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
try {
    $_SESSION = []; $bot = new AccessBatchBot($root); $store = $bot->hysteriaUsersStore(); $uid = $store->add('Алиса <&>');
    $bot->accessBatchStart('hy'); $token = $_SESSION['access_batch'][1]['token'];
    $bot->accessBatch($token, 'pick', $uid); $bot->accessBatchReply('1', $token, 'quota');
    $oldConfirmation = $_SESSION['access_batch'][1]['confirm'];
    batchCheck($store->read()['users'][$uid]['quota'] === null, 'Preview не изменяет данные');
    batchCheck(str_contains(end($bot->messages), 'Алиса &lt;&amp;&gt;'), 'Экранирование имени');
    $bot->accessBatchReply('2', $token, 'quota'); $confirmation = $_SESSION['access_batch'][1]['confirm'];
    $bot->accessBatch($token, 'apply', $oldConfirmation);
    batchCheck($store->read()['users'][$uid]['quota'] === null && isset($_SESSION['access_batch'][1]), 'Старое окно не подтверждает новый план');
    $bot->input['chat'] = 2; $bot->accessBatch($token, 'apply', $confirmation);
    batchCheck($store->read()['users'][$uid]['quota'] === null, 'Другой чат не применяет план');
    $bot->input['chat'] = 1; $bot->admin = false; $bot->accessBatch($token, 'apply', $confirmation);
    batchCheck($store->read()['users'][$uid]['quota'] === null, 'Неадминистратор не применяет план');
    $bot->admin = true; $bot->accessBatch($token, 'apply', $confirmation);
    batchCheck($store->read()['users'][$uid]['quota'] === 2147483648 && !isset($_SESSION['access_batch'][1]), 'Подтверждён ровно показанный план');
    $revision = $store->read()['revision']; $bot->accessBatch($token, 'apply', $confirmation);
    batchCheck($store->read()['revision'] === $revision, 'Повтор callback не применяется');
} finally {
    foreach (glob($root . '/*') as $f) unlink($f); rmdir($root);
}
echo "access_batch_test OK\n";
