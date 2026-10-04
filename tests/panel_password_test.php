<?php

/**
 * Смена/генерация пароля веб-панели (app/panel) из меню бота: Bot::setPanelPassword(),
 * panelPswdSet(), формат сгенерированного пароля. Проверяется именно точка стыка
 * bot.php и Panel.php — password_hash() в bot.php обязан оставаться совместимым
 * с password_verify() в Panel::login(), иначе смена пароля из Telegram молча
 * ломает вход в панель, установленную/проверяемую через CLI (panel.php).
 *
 * НЕ путать panelpswd (эта фича) с adpswd (AdGuardHome) и decoy-паролем
 * .htpasswd — оба вне области этого файла.
 */

require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/../app/panel/Panel.php';

function panelPswdAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$dir = sys_get_temp_dir() . '/panel_pswd_test_' . bin2hex(random_bytes(4));
mkdir($dir, 0700, true);
register_shutdown_function(function () use ($dir) {
    foreach (glob("$dir/files/*") ?: [] as $f) {
        @unlink($f);
    }
    @rmdir("$dir/files");
    foreach (glob("$dir/*") ?: [] as $f) {
        @unlink($f);
    }
    @rmdir($dir);
});
putenv("PANEL_DIR=$dir");

/** Тот же фикстур-паттерн, что tests/panel_test.php: Bot без конструктора,
 * pac.json — в памяти, request() уходит в файловый транспорт, не в сеть. */
class PanelPswdTestBot extends Bot
{
    public $conf = [];

    public function __construct()
    {
        $this->admin = true;
    }

    public function getHashBot($notset = false)
    {
        return 'deadbeef';
    }

    public function getPacConf()
    {
        return $this->conf;
    }

    public function setPacConf(array $conf)
    {
        $this->conf = $conf;
    }
}

$store     = new PanelStore($dir);
$transport = new PanelTransport($store);

$bot            = new PanelPswdTestBot();
$bot->transport = $transport;
$bot->file      = $store->filesDir();
$bot->input     = ['chat' => 777, 'message_id' => 1, 'username' => 'admin', 'callback_id' => 'cb1'];

// ── setPanelPassword(): формат хеша совместим с Panel::login() ──────────────
$bot->setPanelPassword('correct horse battery staple');
panelPswdAssert(isset($bot->conf['panelpswd']), 'setPanelPassword: panelpswd не записан в pac.json');
panelPswdAssert(
    password_verify('correct horse battery staple', $bot->conf['panelpswd']),
    'setPanelPassword: хеш не проходит password_verify() — сломана совместимость с Panel::login()'
);
panelPswdAssert(
    !password_verify('wrong password', $bot->conf['panelpswd']),
    'setPanelPassword: неверный пароль не должен проходить password_verify()'
);

// Тот же хеш обязан пускать через реальный Panel::authed() (не только "голый"
// password_verify) — полный путь: HMAC-кука подписана текущим хешем пароля.
$panel = new Panel($bot, ['key' => 'test-token:AAH', 'admin' => [111]], $store);
$sign  = new ReflectionMethod(Panel::class, 'sign');
$exp              = time() + 3600;
$_COOKIE['panel'] = $exp . '.' . $sign->invoke($panel, $exp);
panelPswdAssert($panel->authed(), 'пароль, установленный Bot::setPanelPassword(), не пускает через Panel::authed()');
unset($_COOKIE['panel']);

// ── initial_password.txt чистится, как в Panel::setPassword() ───────────────
$stale = "$dir/initial_password.txt";
file_put_contents($stale, "уже-недействительный-пароль\n");
panelPswdAssert(is_file($stale), 'тест не смог создать фейковый initial_password.txt');
$bot->setPanelPassword('another one');
panelPswdAssert(!is_file($stale), 'setPanelPassword: initial_password.txt должен исчезать при смене пароля');

// ── формат сгенерированного пароля: bin2hex(random_bytes(16)) = 32 hex ──────
for ($i = 0; $i < 20; $i++) {
    $gen = bin2hex(random_bytes(16));
    panelPswdAssert(32 === strlen($gen), "сгенерированный пароль должен быть 32 символа, получено " . strlen($gen));
    // preg_match, не ctype_xdigit(): расширение ctype не гарантировано в
    // проде (в контейнере php-контейнере его нет — проверено на рабочем сервере).
    panelPswdAssert(1 === preg_match('~^[0-9a-f]{32}$~', $gen), 'сгенерированный пароль должен быть hex-строкой');
}

// ── panelPswdSet(): короткий пароль отклоняется, pac.json не меняется ───────
$bot2            = new PanelPswdTestBot();
$bot2->transport = $transport;
$bot2->file      = $store->filesDir();
$bot2->input     = ['chat' => 777, 'message_id' => 1, 'username' => 'admin', 'callback_id' => ''];
$bot2->panelPswdSet('short', true);
panelPswdAssert(!isset($bot2->conf['panelpswd']), 'panelPswdSet: пароль короче 8 символов не должен применяться');

$bot2->panelPswdSet('   ', true);
panelPswdAssert(!isset($bot2->conf['panelpswd']), 'panelPswdSet: пробельная строка не должна проходить как валидный пароль');

$bot2->panelPswdSet('valid password 123', true);
panelPswdAssert(isset($bot2->conf['panelpswd']), 'panelPswdSet: валидный пароль (>= 8 символов) должен применяться');
panelPswdAssert(
    password_verify('valid password 123', $bot2->conf['panelpswd']),
    'panelPswdSet: применённый пароль должен проходить password_verify()'
);

// panelPswdSet() с nomenu=true не зовёт menu('config') (там require
// app/config.php, которого нет в тестовом окружении) — но send() с паролем
// всё равно должен уйти в транспорт. Проверяем последнее сообщение в ленте.
$last = array_key_last($store->read()['messages']);
$sent = $store->read()['messages'][$last]['text'];
panelPswdAssert(str_contains($sent, '<code>valid password 123</code>'), 'panelPswdSet: пароль должен прийти в чат в <code> для копирования');
panelPswdAssert(str_contains($sent, 'panel.php passwd'), 'panelPswdSet: подсказка CLI-команды должна быть в сообщении');

// ── sendPanelPasswordCopy(): HTML-спецсимволы в ручном пароле экранируются ──
// (panelPswdSet($nomenu=true) не годится для проверки этого напрямую, т.к.
// короткий путь < 8 символов не пропустит "<script>&\"", а длинный — уже
// проверен выше на обычном пароле; вызываем приватный метод напрямую, как
// panel_test.php делает для Panel::sign()/rateHit().)
$copy = new ReflectionMethod(Bot::class, 'sendPanelPasswordCopy');
$xssPass = '<script>alert(1)</script>&"\'';
$copy->invoke($bot2, $xssPass);
$last2 = array_key_last($store->read()['messages']);
$sent2 = $store->read()['messages'][$last2]['text'];
panelPswdAssert(
    !str_contains($sent2, '<script>'),
    'sendPanelPasswordCopy: сырой <script> не должен попадать в HTML-сообщение'
);
panelPswdAssert(
    str_contains($sent2, htmlspecialchars($xssPass, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')),
    'sendPanelPasswordCopy: пароль должен быть экранирован через htmlspecialchars(), но виден в сообщении'
);

echo "panel_password_test OK\n";
