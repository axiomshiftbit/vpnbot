<?php
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($n, $s, $f, $l) { if (error_reporting() & $n) throw new ErrorException($s, 0, $n, $f, $l); return true; });
class GroupBot extends Bot {
    public array $groupPac = [], $x = [], $screens = [], $notified = [];
    public function __construct() {
        $this->language = 'ru'; $this->input = ['chat' => 1, 'message_id' => 1];
        require __DIR__ . '/../app/i18n.php'; $this->i18n = $i;
    }
    public function getPacConf() { return $this->groupPac; }
    public function setPacConf(array $p) { $this->groupPac = $p; return true; }
    public function getXray() { return $this->x; }
    public function restartXray($c, $norestart = false) { $this->ensureExitNodes($c); $this->x = $c; return true; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) { return $fn(); }
    public function update($chat, $message_id, $text, $data = false, $reply = false, $mode = 'HTML') { $this->screens[] = [$text, $data]; }
    public function exitStatus(): array { return []; }
    public function notifyAdmins(string $text): void { $this->notified[] = $text; }
    public function getXrayStats() { return []; }
    protected function exitIpv6Network(): array { return []; }
    protected function exitIpv6Attached(): bool { return false; }
}
$count = 0;
$check = static function ($value, $message) use (&$count) { ++$count; if (!$value) throw new RuntimeException($message); };
$bot = new GroupBot();
$base = ['inbounds' => [['tag' => 'vless', 'port' => 19001, 'protocol' => 'vless', 'settings' => ['decryption' => 'none', 'clients' => [
    ['id' => '11111111-1111-4111-8111-111111111111', 'email' => 'alice', 'exit' => ['cccccccc']]]]]],
    'outbounds' => [['tag' => 'direct', 'protocol' => 'freedom'], ['tag' => 'block', 'protocol' => 'blackhole']], 'routing' => ['rules' => []]];
$link = 'vless://11111111-1111-4111-8111-111111111111@node.example.test:443?security=tls&sni=node.example.test&type=ws&path=%2Fnode&encryption=none';
$pac = ['exits' => ['aaaaaaaa' => ['link' => $link, 'name' => 'A'], 'bbbbbbbb' => ['link' => $link, 'name' => 'B'],
    'cccccccc' => ['kind' => 'group', 'name' => 'A + B', 'members' => ['aaaaaaaa', 'bbbbbbbb'], 'fallback' => 'block', 'routes' => ['domain:youtube.com' => 1]]]];
$render = static function ($p) use ($bot, $base) { $c = $base; $bot->ensureExitNodes($c, $p); return $c; };
$rule = static function ($c, $suffix = 'domain') { foreach ($c['routing']['rules'] as $r) if (($r['ruleTag'] ?? '') === 'vpnbot:exit:cccccccc:' . $suffix) return $r; return []; };
$c = $render($pac);
$check($rule($c)['balancerTag'] === 'vpnbot-exit-cccccccc', 'Группа имеет собственный маршрут');
$check($c['routing']['balancers'][0]['strategy']['type'] === 'leastPing', 'Выбор по задержке');
$check($c['routing']['balancers'][0]['fallbackTag'] === 'block', 'Группа по умолчанию строгая');
$check($c['burstObservatory']['subjectSelector'] === ['vpnbot-exit-aaaaaaaa', 'vpnbot-exit-bbbbbbbb'], 'Пробы только реальных членов, не группы/blackhole');
$check($rule($c)['user'] === ['alice'], 'Назначения группы не назначают пользователя отдельным узлам');
$again = $c; $bot->ensureExitNodes($again, $pac); $check($again === $c, 'Идемпотентная пересборка группы');
$manual = $pac; $manual['exits']['cccccccc']['choice'] = 'bbbbbbbb';
$m = $render($manual);
$check($rule($m)['outboundTag'] === 'vpnbot-exit-bbbbbbbb', 'Ручной выбор члена');
$check($m['outbounds'] === $c['outbounds'] && $m['inbounds'] === $c['inbounds'] && $m['burstObservatory'] === $c['burstObservatory'], 'Ручной выбор меняет только routing для горячего применения');
foreach (['disabled', 'deleted', 'broken', 'nonmember'] as $scenario) {
    $p = $manual;
    if ($scenario === 'disabled') $p['exits']['bbbbbbbb']['enabled'] = 0;
    if ($scenario === 'deleted') unset($p['exits']['bbbbbbbb']);
    if ($scenario === 'broken') $p['exits']['bbbbbbbb']['link'] = 'invalid';
    if ($scenario === 'nonmember') $p['exits']['cccccccc']['members'] = ['aaaaaaaa'];
    $check($rule($render($p))['outboundTag'] === 'block', 'Отказ ручного выбора закрыт: ' . $scenario);
}
$p = $pac; $p['exits']['cccccccc']['members'] = [];
$check($rule($render($p))['outboundTag'] === 'block', 'Пустая строгая группа закрыта');
$p['exits']['cccccccc']['fallback'] = 'direct';
$check($rule($render($p))['outboundTag'] === 'direct', 'Явно разрешённый fallback пустой группы');
$check($rule($render($p), 'probe')['outboundTag'] === 'block', 'Проверка не считает прямой fallback живым узлом');
$p = $pac; $p['exits']['cccccccc']['choice'] = 'direct';
$check($rule($render($p))['outboundTag'] === 'block', 'Импорт direct не обходит строгий режим');
$p['exits']['cccccccc']['fallback'] = 'direct';
$check($rule($render($p))['outboundTag'] === 'direct', 'Явный ручной прямой выход');
$p = $pac; $p['exits']['bbbbbbbb'] = ['kind' => 'group', 'members' => ['cccccccc']];
$circular = $render($p);
$check($circular['routing']['balancers'][0]['selector'] === ['vpnbot-exit-aaaaaaaa'], 'Вложенные группы и циклы не становятся выходами');
$bot->groupPac = $pac; $bot->x = $c;
foreach (['ru', 'en'] as $language) {
    $bot->language = $language; $bot->exitNodeMenu('cccccccc'); $bot->exitGroupMenu('cccccccc');
    foreach (array_slice($bot->screens, -2) as [$text, $rows]) {
        $check(!str_contains($text, 'link cannot be parsed') && !str_contains($text, 'ссылка не разбирается'), 'Группа не показывает ошибку ссылки');
        foreach ($rows as $row) foreach ($row as $button) $check(strlen($button['callback_data'] ?? '') <= 64, 'Лимит callback Telegram');
    }
}
$bot->exitGroupChoice('cccccccc', 'direct');
$check(($bot->groupPac['exits']['cccccccc']['choice'] ?? 'auto') === 'auto', 'Старая кнопка direct не снимает строгий режим');
$bot->exitGroupChoice('cccccccc', 'bbbbbbbb'); $bot->exitGroupMember('cccccccc', 'bbbbbbbb');
$check($rule($bot->x)['outboundTag'] === 'block', 'Удаление выбранного члена закрывает маршрут');
$bot->language = 'ru';
$bot->groupPac['exits']['cccccccc']['fallback'] = 'direct';
$bot->exitNodeMenu('cccccccc');
$check(str_contains(end($bot->screens)[0], 'При отказе: блокировать'), 'Карточка ручного выбора не обещает прямой fallback');
class FailedGroupBot extends GroupBot {
    public function exitStatus(): array { return ['cccccccc' => ['ok' => true]]; }
    public function exitProbe(string $id, bool $full = true): array { return ['ok' => false]; }
    public function exitRefreshRulesets(string $id, bool $force = false): bool { return false; }
}
$failed = new FailedGroupBot();
$failed->groupPac = ['exits' => ['cccccccc' => ['kind' => 'group', 'fallback' => 'direct', 'choice' => 'bbbbbbbb']]];
$failed->checkExitNodes();
$check(count($failed->notified) === 1 && str_contains($failed->notified[0], 'блокируются'), 'Уведомление ручной группы не обещает прямой fallback');
if ($binary = getenv('VLESS_TEST_XRAY')) {
    foreach ([$c, $m, $circular] as $fixture) {
        $directory = sys_get_temp_dir() . '/xray-group-' . bin2hex(random_bytes(8));
        mkdir($directory, 0700); $path = $directory . '/config.json';
        try {
            file_put_contents($path, json_encode($fixture)); chmod($path, 0600);
            exec(escapeshellarg($binary) . ' run -test -format json -config ' . escapeshellarg($path) . ' >/dev/null 2>&1', $output, $status);
            $check($status === 0, 'Настоящее ядро принимает конфигурацию группы');
        } finally { unlink($path); rmdir($directory); }
    }
}
echo "exit_groups_test: $count OK\n";
