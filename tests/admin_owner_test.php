<?php

// Состав администраторов меняет только владелец — первый в $c['admin'].
// Bot читает config.php из своего каталога, поэтому класс копируется во
// временный каталог со своим конфигом: настоящая установка не затрагивается.
$dir = sys_get_temp_dir() . '/vpnbot-owner-' . bin2hex(random_bytes(6));
mkdir($dir, 0700);
foreach (glob(__DIR__ . '/../app/*.php') as $file) {
    if (basename($file) !== 'config.php') copy($file, $dir . '/' . basename($file));
}
$config = "$dir/config.php";
$setAdmins = static function (array $admins) use ($config) {
    file_put_contents($config, "<?php\n\n\$c = " . var_export(['key' => 'k', 'admin' => $admins], true) . ";\n");
};
$admins = static function () use ($config) {
    require $config;
    return $c['admin'];
};
$setAdmins([100, 200, 300]);
require "$dir/bot.php";

class AdminOwnerBot extends Bot
{
    public array $log = [];
    public function __construct() {}
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    { $this->log[] = "send:$text"; return ['result' => ['message_id' => 1]]; }
    public function answer($callback_id, $textNotify = false, $notify = false) { $this->log[] = "answer:$textNotify"; }
    public function menu($type = false, $arg = false, $return = false) { $this->log[] = "menu:$type"; }
    public function stashReply($r, array $state) { $this->log[] = 'stash:' . $state['callback']; }
    public function session() {}
}

$failed = 0;
$check = static function (bool $ok, string $what) use (&$failed) {
    if (!$ok) { $failed++; echo "FAIL: $what\n"; }
};
$as = static function ($from, bool $callback = true, bool $panel = false): AdminOwnerBot {
    $bot = new AdminOwnerBot();
    $bot->input = ['from' => $from, 'chat' => $from, 'message_id' => 7, 'username' => 'u'] + ($callback ? ['callback_id' => 'cb'] : []);
    if ($panel) $bot->transport = new stdClass();
    return $bot;
};

try {
    // ── не владелец: ничего не меняет ни одним из трёх входов ────────────────
    foreach ([200, '200', 300, 555, 0, null, '', -100, '100abc', [100], 100.9] as $who) {
        $label = var_export($who, true);
        foreach ([['delAdmin', 100], ['delAdmin', 300], ['delAdmin', 200], ['addAdmin', '999']] as [$method, $arg]) {
            $bot = $as($who, $method === 'delAdmin');
            $bot->$method($arg);
            $check($admins() === [100, 200, 300], "$label: $method($arg) не меняет список");
        }
        $bot = $as($who);
        $bot->enterAdmin();
        $check(!in_array('stash:addAdmin', $bot->log, true), "$label: приглашение ввести id не выдаётся");
        $check(in_array('answer:only the owner can manage admins', $bot->log, true), "$label: отказ объяснён");
        $check($bot->isOwner() === false, "$label: не владелец");
    }

    // ── список администраторов в настройках: видят все, первым — владелец ────
    $lines = $as(200)->adminListLines();
    $check(count($lines) === 4, 'заголовок и три ID');
    $check((bool) preg_match('~^<code>100</code> — (владелец|owner)$~u', $lines[1]), 'первый — владелец: ' . $lines[1]);
    $check((bool) preg_match('~^<code>200</code> — (вы|you)$~u', $lines[2]), 'текущий администратор отмечен: ' . $lines[2]);
    $check($lines[3] === '<code>300</code>', 'остальные без пометок');
    $check((bool) preg_match('~— (владелец, вы|owner, you)$~u', $as(100)->adminListLines()[1]), 'владелец видит себя');
    $check(!preg_grep('~— (вы|you)~u', $as(100, true, true)->adminListLines()), 'в панели «вы» не ставится: личность не подтверждена');
    $setAdmins([]);
    $empty = $as(100)->adminListLines();
    $check(count($empty) === 2 && !str_contains($empty[1], '<id>'), 'пустой список объяснён, без сырого < > для HTML');
    $setAdmins([100, '200; <b>', 300]);
    $check(count($as(100)->adminListLines()) === 3, 'нечисловой ID в config.php не выводится');
    $setAdmins([100, 200, 300]);

    $bot = $as(100, true, true);
    $bot->delAdmin(200); $bot->addAdmin('999'); $bot->enterAdmin();
    $check($admins() === [100, 200, 300] && !in_array('stash:addAdmin', $bot->log, true), 'панель не меняет состав даже от имени владельца');

    // ── владелец ────────────────────────────────────────────────────────────
    $bot = $as('100');
    $check($bot->isOwner(), 'id владельца строкой из Telegram распознаётся');
    $bot->enterAdmin();
    $check(in_array('stash:addAdmin', $bot->log, true), 'владелец получает приглашение');
    $bot = $as(100, false);
    $bot->addAdmin(' 999 ');
    $check($admins() === [100, 200, 300, 999], 'владелец добавляет администратора');
    foreach (['0', '-5', 'abc', '', '999', '100'] as $bad) {
        $as(100, false)->addAdmin($bad);
        $check($admins() === [100, 200, 300, 999], "addAdmin('$bad') не меняет список");
    }
    $as(100)->delAdmin(200);
    $check($admins() === [100, 300, 999], 'владелец удаляет администратора, порядок сохранён');
    $bot = $as(100);
    $bot->delAdmin(100);
    $check($admins() === [100, 300, 999] && in_array('answer:нельзя удалить владельца', $bot->log, true), 'владелец себя не удаляет');
    $as(100)->delAdmin(12345);
    $check($admins() === [100, 300, 999], 'неизвестный id ничего не удаляет');

    // Удалённый администратор теряет права сразу; новый владельцем не становится.
    $check($as(200)->isOwner() === false && $as(999)->isOwner() === false && $as(300)->isOwner() === false, 'владелец один');

    // ── прежние форматы конфига ─────────────────────────────────────────────
    $setAdmins(['100', '200']);
    $check($as(100)->isOwner() && !$as(200)->isOwner(), 'id строками: владелец — первый');
    $as(200)->delAdmin(100);
    $check($admins() === ['100', '200'], 'второй администратор не удаляет владельца (строковые id)');
    $setAdmins([100]);
    $bot = $as(100);
    $bot->delAdmin(100);
    $check($admins() === [100] && in_array('answer:нельзя удалить последнего администратора', $bot->log, true), 'последний администратор не удаляется');
    $setAdmins([]);
    $check($as(100)->isOwner() === false, 'пустой список: владельца нет');
    $as(100, false)->addAdmin('100');
    $check($admins() === [], 'ничейный бот не присваивается через addAdmin');

    // ── настоящий путь нажатия кнопки: input() → auth() → action() ─────────
    $press = static function (int $from, string $data) {
        $bot = new AdminOwnerBot();
        $bot->input(['callback_query' => ['id' => 'cb', 'data' => $data, 'from' => ['id' => $from, 'username' => 'u'],
            'message' => ['message_id' => 7, 'text' => 'menu', 'chat' => ['id' => $from]]]]);
        return $bot;
    };
    $setAdmins([100, 200, 300]);
    foreach ([200, 300, 555] as $who) {
        $press($who, '/deladmin 100'); $press($who, '/deladmin 200'); $press($who, '/deladmin 300');
        $bot = $press($who, '/addadmin');
        $check($admins() === [100, 200, 300] && !in_array('stash:addAdmin', $bot->log, true), "кнопки от $who не меняют состав");
    }
    $bot = $press(100, '/addadmin');
    $check(in_array('stash:addAdmin', $bot->log, true), 'кнопка владельца выдаёт приглашение');
    $press(100, '/deladmin 100');
    $press(100, '/deladmin 300');
    $check($admins() === [100, 200], 'кнопка владельца удаляет администратора, но не владельца');

    // ── меню: кнопки только владельцу, без кнопки удаления себя ─────────────
    $src = file_get_contents(__DIR__ . '/../app/bot.php');
    $block = substr($src, strpos($src, 'Состав администраторов видит и меняет только владелец'), 1200);
    $check(strpos($block, 'if ($this->isOwner())') < strpos($block, '/addadmin') && strpos($block, '/addadmin') < strpos($block, '/deladmin'),
        'кнопки добавления и удаления стоят под проверкой владельца');
    $check(str_contains($block, 'array_slice(array_values((array) $c[\'admin\']), 1)'), 'кнопки удаления владельца нет');
    $check(substr_count($src, '"/addadmin"') === 1 && substr_count($src, '"/deladmin ') === 1, 'других кнопок управления администраторами нет');
} finally {
    foreach (glob("$dir/*") as $file) unlink($file);
    rmdir($dir);
}
if ($failed) exit(1);
echo "admin_owner_test OK\n";
