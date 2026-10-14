<?php
require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/../app/i18n.php';
require_once __DIR__ . '/../app/panel/Panel.php';

$checks = 0;
function vaultCheck(bool $ok, string $label): void {
    global $checks;
    if (!$ok) throw new RuntimeException($label);
    $checks++;
}
class VaultDisplayTransport {
    public array $calls = [];
    public function call($method, $data, $json = 0) {
        $this->calls[] = [$method, $data];
        return ['ok' => true, 'result' => ['message_id' => count($this->calls)]];
    }
}
class VaultDisplayBot extends Bot {
    public array $conf = [];
    public bool $writable = true;
    public function __construct(array $i) {
        $this->admin = true; $this->i18n = $i; $this->language = 'ru'; $this->key = 'fixture:bot-token';
        $this->input = ['chat' => 1, 'message_id' => 1, 'message' => '', 'reply' => false];
        $this->transport = new VaultDisplayTransport();
    }
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $c) { if (!$this->writable) return false; $this->conf = $c; return true; }
    public function getHashBot($notset = false) { return 'fixture'; }
    public function getWgMsg() { return null; }
    public function menu($type = false, $arg = false, $return = false) {}
}
$dir = sys_get_temp_dir() . '/vpnbot-panel-display-' . bin2hex(random_bytes(6)); mkdir($dir, 0700);
$oldDirectory = getenv('PANEL_DIR'); putenv("PANEL_DIR=$dir");
ob_start();
try {
    $bot = new VaultDisplayBot($i); $plain = 'Fixture < & > password';
    $bot->setPanelPassword($plain); $hash = $bot->conf['panelpswd'];
    vaultCheck(password_verify($plain, $hash), 'Вход использует прежний формат хеша');
    vaultCheck(PanelPasswordVault::reveal($dir, $hash, $bot->key) === $plain, 'Расшифровка текущего пароля');
    $encoded = file_get_contents("$dir/password-display.json");
    vaultCheck(!str_contains($encoded, $plain) && !str_contains(json_encode($bot->conf), $plain), 'Открытый пароль не хранится в pac.json или копии');
    vaultCheck(!file_exists("$dir/password-display.key"), 'Ключ не лежит файлом рядом с шифротекстом');
    vaultCheck(PanelPasswordVault::reveal($dir, $hash, 'other:bot-token') === null, 'Без токена этого бота копия не раскрывается');
    vaultCheck(PanelPasswordVault::reveal($dir, $hash, '') === null && !PanelPasswordVault::remember($dir, $plain, $hash, ''), 'Пустой токен не даёт ключа');
    foreach (['password-display.json', 'password-display.lock'] as $file) {
        vaultCheck((fileperms("$dir/$file") & 0777) === 0600, 'Закрытые права файла');
    }
    $bot->input['callback'] = '/panelShowPswd'; $bot->action();
    [, $data] = end($bot->transport->calls);
    vaultCheck(str_contains($data['text'], '<span class="tg-spoiler">Fixture &lt; &amp; &gt; password</span>'), 'Реальный callback отдаёт экранированный спойлер');
    vaultCheck(!str_contains($data['text'], $hash), 'Хеш не выдаётся вместо пароля');
    $calls = count($bot->transport->calls); $bot->admin = false;
    foreach (['/panelShowPswd', '/panelPswd', '/panelGenPswd'] as $callback) {
        $bot->input['callback'] = $callback; $bot->action();
    }
    $bot->panelPswdSet('unauthorized fixture', true);
    vaultCheck(count($bot->transport->calls) === $calls && $bot->conf['panelpswd'] === $hash, 'Чужие callback и ForceReply не показывают и не меняют пароль');
    $bot->admin = true;
    $records = json_decode($encoded, true); $id = array_key_first($records); $binary = base64_decode(substr($records[$id], 3));
    $binary[strlen($binary)-1] = chr(ord($binary[strlen($binary)-1]) ^ 1);
    $records[$id] = 'v2:' . base64_encode($binary); file_put_contents("$dir/password-display.json", json_encode($records));
    vaultCheck(PanelPasswordVault::reveal($dir, $hash, $bot->key) === null, 'Изменённый шифротекст не проходит GCM');
    file_put_contents("$dir/password-display.json", $encoded);
    vaultCheck(PanelPasswordVault::reveal($dir, password_hash('different fixture', PASSWORD_DEFAULT), $bot->key) === null, 'Копия привязана к действующему хешу');
    chmod("$dir/password-display.json", 0644); clearstatcache();
    vaultCheck(PanelPasswordVault::reveal($dir, $hash, $bot->key) === null, 'Открытые права копии отвергаются');
    chmod("$dir/password-display.json", 0600); clearstatcache();

    // Прежний формат: запись без префикса, ключ файлом рядом. Просмотр
    // переписывает её ключом из токена и удаляет файл ключа.
    $legacyKey = random_bytes(32); $nonce = random_bytes(12); $tag = '';
    $ct = openssl_encrypt($plain, 'aes-256-gcm', $legacyKey, OPENSSL_RAW_DATA, $nonce, $tag, $hash);
    $stale = password_hash('older fixture', PASSWORD_DEFAULT);
    file_put_contents("$dir/password-display.json", json_encode([hash('sha256', $stale) => base64_encode(random_bytes(40)), hash('sha256', $hash) => base64_encode($nonce . $tag . $ct)]));
    file_put_contents("$dir/password-display.key", $legacyKey); chmod("$dir/password-display.key", 0600);
    vaultCheck(PanelPasswordVault::reveal($dir, $hash, $bot->key) === $plain, 'Запись прежнего формата читается');
    $migrated = json_decode(file_get_contents("$dir/password-display.json"), true);
    vaultCheck(!file_exists("$dir/password-display.key") && count($migrated) === 1 && str_starts_with(reset($migrated), 'v2:'), 'Миграция: ключ удалён, остались только новые записи');
    vaultCheck(PanelPasswordVault::reveal($dir, $hash, $bot->key) === $plain, 'После миграции копия читается ключом из токена');
    $bot->writable = false;
    try { $bot->setPanelPassword('write failure fixture'); throw new LogicException('write succeeded'); }
    catch (RuntimeException $e) {}
    vaultCheck($bot->conf['panelpswd'] === $hash && PanelPasswordVault::reveal($dir, $hash, $bot->key) === $plain, 'Отказ записи pac сохраняет старый пароль и просмотр');
    $bot->writable = true;
    foreach (['short', str_repeat('a', 73)] as $invalid) {
        try { $bot->setPanelPassword($invalid); throw new LogicException('bad length'); }
        catch (InvalidArgumentException $e) {}
    }
    vaultCheck($bot->conf['panelpswd'] === $hash, 'Длина пароля не допускает усечение bcrypt');
    unlink("$dir/password-display.json");
    $bot->input['callback'] = '/panelShowPswd'; $bot->action(); [, $data] = end($bot->transport->calls);
    vaultCheck(str_contains($data['text'], 'только хеш') && !str_contains($data['text'], $plain), 'Старый пароль не выдумывается из хеша');
    file_put_contents("$dir/initial_password.txt", "stale fixture\n"); chmod("$dir/initial_password.txt", 0600);
    vaultCheck(PanelPasswordVault::reveal($dir, $hash, $bot->key) === null, 'Устаревший bootstrap пароль не выдаётся');
    file_put_contents("$dir/initial_password.txt", $plain . "\n");
    vaultCheck(PanelPasswordVault::reveal($dir, $hash, $bot->key) === $plain, 'Действующий bootstrap пароль мигрирует');
    vaultCheck(!file_exists("$dir/initial_password.txt"), 'Перенесённый в копию стартовый пароль удаляется');
    unlink("$dir/password-display.json");
    file_put_contents("$dir/initial_password.txt", $plain . "\n"); chmod("$dir/initial_password.txt", 0600);
    $panel = new Panel($bot, ['key' => $bot->key, 'admin' => [1]], new PanelStore($dir));
    $_SERVER['REMOTE_ADDR'] = '127.0.0.1'; $_POST = ['password' => $plain];
    $login = new ReflectionMethod(Panel::class, 'login'); $login->invoke($panel);
    vaultCheck(PanelPasswordVault::reveal($dir, $hash, $bot->key) === $plain, 'Успешный настоящий вход восстанавливает копию для просмотра');
    vaultCheck(!file_exists("$dir/initial_password.txt"), 'Стартовый пароль в открытом виде удаляется после входа');
    $bot->writable = false;
    try { $panel->setPassword('CLI write failure fixture'); throw new LogicException('write succeeded'); }
    catch (RuntimeException $e) {}
    vaultCheck($bot->conf['panelpswd'] === $hash && PanelPasswordVault::reveal($dir, $hash, $bot->key) === $plain, 'CLI сообщает об отказе записи и сохраняет прежний просмотр');
    $bot->writable = true;
    $panel->setPassword('CLI replacement fixture');
    vaultCheck(PanelPasswordVault::reveal($dir, $bot->conf['panelpswd'], $bot->key) === 'CLI replacement fixture', 'Смена через Panel/CLI обновляет копию');
    $bot->panelPswdSet('generated view fixture', true); [, $data] = end($bot->transport->calls);
    vaultCheck(str_contains($data['text'], 'tg-spoiler'), 'Новый пароль тоже скрыт спойлером');
} finally {
    ob_end_clean(); putenv($oldDirectory === false ? 'PANEL_DIR' : 'PANEL_DIR=' . $oldDirectory);
    $remove = static function($path) use (&$remove) {
        if (is_dir($path)) { foreach (scandir($path) as $f) if ($f !== '.' && $f !== '..') $remove("$path/$f"); rmdir($path); }
        else unlink($path);
    };
    $remove($dir);
}
echo "panel_password_display_test: OK ($checks проверок)\n";
