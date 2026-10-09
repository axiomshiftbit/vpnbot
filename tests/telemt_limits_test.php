<?php
require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';
set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return true;
});

class TelemtLimitsBot extends Bot
{
    public array $conf = [], $screen = [], $prompt = [], $locks = [], $calls = [], $apiFixture = [];
    public string $root, $toml = '';
    public bool $image = true, $stateEnabled = true, $failReady = false, $failWrite = false;
    public int $starts = 0;
    public function __construct(string $root, array $strings) {
        $this->root = $root; $this->i18n = $strings; $this->language = 'ru'; $this->admin = true;
        $this->ip = '203.0.113.10'; $this->key = 'fixture'; $this->protocolModulesFile = "$root/modules.json";
        $this->conf = ['telemt_users' => ['alice' => str_repeat('ab',16), 'bob' => str_repeat('cd',16)], 'telemt_web' => 0];
        $this->input = ['chat' => 1, 'message_id' => 2, 'callback_id' => 3, 'callback' => '', 'message' => ''];
    }
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { $this->conf = $conf; return true; }
    public function getWgMsg() { return null; }
    public function getPorts() { return ['telemt' => ['port' => 8443, 'enable' => true]]; }
    public function telemtQuotaPath(): string { return "$this->root/quota.json"; }
    public function telemtWriteServiceState(bool $enabled): void { $this->stateEnabled = $enabled; }
    public function telemtWriteToml(string $toml): void {
        if ($this->failWrite) { $this->failWrite = false; throw new RuntimeException('fixture write'); }
        $this->toml = $toml;
    }
    public function telemtWebRefresh(bool $was): void {}
    public function telemtUsers($relay = '', int $page = 0) { $this->screen = ['text'=>'users','buttons'=>[]]; }
    public function telemtApiFetch(array $paths): array { return $this->apiFixture; }
    public function withLock(string $name, callable $fn, int $timeout = 0, $busy = null) {
        if (in_array($name, $this->locks, true)) throw new RuntimeException('recursive lock: ' . $name);
        $this->locks[] = $name;
        try { return $fn(); } finally { array_pop($this->locks); }
    }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') {
        $this->calls[] = $cmd; $this->sshFailed = false;
        if (str_starts_with($cmd, 'telemt run')) { $this->starts++; return ''; }
        if (!$this->image) return '';
        if (str_contains($cmd, 'telemt_state.py ready') && $this->failReady) { $this->failReady = false; return ''; }
        if (preg_match("~telemt_state.py reset '([^']*)'~", $cmd, $m)) {
            $name = base64_decode($m[1]);
            $state = $this->telemtQuotaRead([]);
            $state['users'][$name] = ['used_bytes' => 0, 'last_reset_epoch_secs' => time()];
            $state['last_reset_epoch_secs'] = time(); $this->telemtQuotaWrite($state);
        }
        if (str_contains($cmd, 'telemt_state.py prepare')) {
            $state = $this->telemtQuotaRead($this->conf);
            $state['users'] = array_intersect_key($state['users'], $this->conf['telemt_users']);
            foreach ($this->conf['telemt_users'] as $name => $_) $state['users'][$name] ??= ['used_bytes'=>0,'last_reset_epoch_secs'=>0];
            $this->telemtQuotaWrite($state);
        }
        return 'TELEMT_STATE_OK';
    }
    public function update($chat, $message, $text, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->screen = ['text'=>$text,'buttons'=>$button]; }
    public function send($chat, $text, $reply_to_message_id = false, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { return ['result'=>['message_id'=>55]]; }
    public function stashReply($response, array $state) { $this->prompt = $state; }
    public function click(string $callback): void { $this->input['callback'] = $callback; $this->action(); }
}

$root = sys_get_temp_dir() . '/vpnbot-telemt-limits-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
$checks = 0;
$check = static function (bool $ok, string $message) use (&$checks): void { $checks++; if (!$ok) throw new RuntimeException($message); };
$reject = static function (callable $fn, string $message) use ($check): void {
    try { $fn(); } catch (RuntimeException $error) { $check(true, $message); return; }
    $check(false, $message);
};
try {
    $b = new TelemtLimitsBot($root, $i);
    $fresh = new TelemtLimitsBot($root . '/fresh', $i);
    $fresh->telemtQuotaWrite(['last_reset_epoch_secs'=>0, 'users'=>[]]);
    $check($fresh->telemtQuotaRead([])['users'] === [], 'Восстановление на новой установке создаёт каталог расхода');
    unlink($fresh->telemtQuotaPath()); rmdir($root . '/fresh');
    foreach (['0'=>0, '10'=>10737418240, '0.5'=>536870912, '0,5'=>536870912, '0.000001'=>1074, '1000000'=>1073741824000000] as $input => $bytes) {
        $check($b->telemtParseLimit('quota', (string) $input) === $bytes, 'GiB: ' . $input);
    }
    foreach (['-1','1e3','NaN','INF','1 GiB','1,000.5','.5','0.0000001','1000000.1','999999999999999999','','+1','1/2'] as $input) $reject(fn()=>$b->telemtParseLimit('quota',$input), 'Некорректная квота: ' . $input);
    foreach (['0'=>0,'1'=>1,'1000'=>1000] as $input=>$expected) $check($b->telemtParseLimit('ips',(string)$input)===$expected, 'IP: '.$input);
    foreach (['-1','1.5','1,5','1001','1e2','+1','abc',''] as $input) $reject(fn()=>$b->telemtParseLimit('ips',$input),'Некорректный IP: '.$input);
    $toml = $b->telemtToml();
    $check(!str_contains($toml, '[access.user_data_quota]') && !str_contains($toml, '[access.user_max_unique_ips]'), 'Нет ограничений по умолчанию');
    $b->restartTelemt();
    $fp = hash('sha256', $b->conf['telemt_users']['alice']);
    $b->telemtChangeLimit('alice', 'quota', 1073741824, $fp);
    $check($b->telemtQuotaRead($b->conf)['users']['alice']['used_bytes'] === 0, 'Включение квоты начинает новый период');
    $check(str_contains($b->toml, "[access.user_data_quota]\n\"alice\" = 1073741824"), 'Точная квота в байтах');
    $check(str_contains($b->toml, "[server.api]\nenabled = true") && str_contains($b->toml, 'read_only = true'), 'API включён без beobachten и только для чтения');
    $state = $b->telemtQuotaRead($b->conf); $state['users']['alice']['used_bytes'] = 777; $state['users']['bob']['used_bytes'] = 888; $b->telemtQuotaWrite($state);
    $b->telemtChangeLimit('alice', 'quota', 500, $fp);
    $check($b->telemtQuotaRead($b->conf)['users']['alice']['used_bytes'] === 777, 'Снижение квоты сохраняет расход');
    $b->telemtChangeLimit('alice', 'ips', 2, $fp);
    $check(str_contains($b->toml, "[access.user_max_unique_ips]\n\"alice\" = 2"), 'Индивидуальный IP лимит');
    $check(str_contains($b->toml, 'user_max_unique_ips_mode = "active_window"'), 'Лимит одновременных IP');
    $before = $b->starts; $b->telemtChangeLimit('alice','ips',2,$fp);
    $check($before === $b->starts, 'Повтор значения не переподключает пользователей');
    $beforeConf = $b->conf;
    $reject(fn()=>$b->telemtChangeLimit('alice','ips',1001,$fp),'Валидация прямого вызова');
    $check($beforeConf === $b->conf, 'Ошибка не меняет PAC');
    $b->image = false;
    $reject(fn()=>$b->telemtChangeLimit('alice','ips',3,$fp),'Старый образ отклонён');
    $check($beforeConf === $b->conf && $before === $b->starts,'Старый образ не меняет ограничения');
    $b->image = true; $b->failReady = true;
    $reject(fn()=>$b->telemtChangeLimit('alice','ips',3,$fp),'Ошибка готовности видна вызывающему');
    $check($beforeConf === $b->conf && str_contains($b->toml, "\"alice\" = 2"), 'Настройки и TOML восстановлены после отказа');
    $check($b->stateEnabled, 'Откат восстановил разрешение запуска');
    $b->failWrite = true;
    $reject(fn()=>$b->telemtChangeLimit('alice','ips',3,$fp),'Ошибка записи TOML видна');
    $check($beforeConf === $b->conf,'Ошибка TOML не меняет PAC');
    $b->admin = false; $b->telemtChangeLimit('alice','quota',0,$fp); $b->admin = true;
    $check($beforeConf === $b->conf,'Неадминистратор не меняет лимиты');
    $card = $b->telemtUserCallback('alice', 999999, 'fixture-relay');
    $b->conf['telemt_relays']['fixture-relay'] = ['address'=>'relay.example'];
    $b->click($card . ' limits');
    $check(str_contains($b->screen['text'], $b->i18n('telemt limits exhausted')), 'Исчерпанная квота видна в меню');
    $check(str_contains($b->screen['text'], $b->i18n('telemt limits snapshot')), 'Недоступная API не выдаётся за текущие данные');
    foreach ($b->screen['buttons'] as $row) foreach ($row as $button) $check(strlen($button['callback_data']) <= 64, 'Callback <=64');
    $help = $b->screen['buttons'][4][0]['callback_data'];
    $b->click($help);
    $check(end($b->screen['buttons'])[0]['callback_data'] === $card . ' limits','Справка возвращает в того же пользователя/relay');
    foreach (['ru', 'en'] as $language) {
        $b->language = $language;
        for ($page = 0; $page <= 3; $page++) {
            $b->click(str_replace(' 0 ', ' ' . $page . ' ', $help));
            $check($b->messageTextLength($b->screen['text']) <= 4096, 'Справка укладывается в Telegram');
            foreach ($b->screen['buttons'] as $row) foreach ($row as $button) $check(strlen($button['callback_data']) <= 64, 'Справка: callback <=64');
        }
    }
    $b->language = 'ru';
    $b->click($card . ' quota');
    $check($b->prompt['callback'] === 'telemtLimitReply' && $b->prompt['args'] === ['alice',999999,'fixture-relay','quota',$fp], 'Промпт сохраняет полный контекст и отпечаток');
    $b->telemtLimitReply('ошибка', ...$b->prompt['args']);
    $check(str_contains($b->screen['text'], '❌') && ($b->conf['telemt_user_limits']['alice']['quota'] === 500), 'Ошибка ввода видна без изменения');
    $b->apiFixture = ['/v1/stats/users/quota'=>['users'=>[['username'=>'alice','used_bytes'=>777,'last_reset_epoch_secs'=>5]]], '/v1/stats/users/active-ips'=>[['username'=>'alice','active_ips'=>['127.0.0.1','::1']]]];
    $b->click($card . ' limits');
    $check(!str_contains($b->screen['text'], $b->i18n('telemt limits snapshot')) && str_contains($b->screen['text'], 'активных IP: 2'), 'Текущие счётчики расхода и IP');
    $b->click($card . ' reset');
    $confirm = $b->screen['buttons'][0][0]['callback_data'];
    $check($b->telemtQuotaRead($b->conf)['users']['alice']['used_bytes'] === 777, 'Сброс требует подтверждения');
    $b->click($confirm);
    $state = $b->telemtQuotaRead($b->conf);
    $check($state['users']['alice']['used_bytes'] === 0 && $state['users']['bob']['used_bytes'] === 888, 'Подтверждение сбрасывает только выбранного');
    $check($b->conf['telemt_user_limits']['alice'] === ['quota'=>500,'ips'=>2], 'Сброс сохраняет оба лимита');
    $b->conf['telemt_users']['alice'] = str_repeat('ef',16);
    $b->click($confirm);
    $check(str_contains($b->screen['text'], $b->i18n('telemt limits stale')), 'Старое подтверждение после ротации отвергнуто');
    $reject(fn()=>$b->telemtChangeLimit('alice','quota',0,$fp), 'Старый ответ после ротации отвергнут');
    $fp = hash('sha256',$b->conf['telemt_users']['alice']);
    $b->telemtChangeLimit('alice','quota',0,$fp);
    $check(!str_contains($b->toml,'[access.user_data_quota]'), 'Безлимит опускает таблицу quota');
    $b->telemtChangeLimit('alice','ips',0,$fp);
    $check(!str_contains($b->toml,'[access.user_max_unique_ips]'), 'Выключение IP опускает таблицу');
    $check(str_contains($b->toml,"[server.api]\nenabled = true") && str_contains($b->toml, 'read_only = true'), 'API остаётся для учёта подключений, но только на чтение');
    $b->telemtChangeLimit('alice','quota',1000,$fp);
    $backup = $b->telemtBackupSnapshot();
    $check($backup['pac'] === $b->conf && $backup['telemt_quota']['users']['bob']['used_bytes'] === 888,'Согласованная резервная копия');
    $backup['telemt_quota']['users']['alice']['used_bytes'] = 123;
    $b->telemtQuotaRestore($backup['telemt_quota'], $backup['pac']);
    $check($b->telemtQuotaRead($b->conf)['users']['alice']['used_bytes'] === 123,'Восстановленный расход не затирается старым процессом');
    $missing = $backup['telemt_quota']; unset($missing['users']['alice']);
    $reject(fn()=>$b->telemtQuotaRestore($missing,$backup['pac']),'Неполная копия отклонена');
    $check($b->telemtQuotaRead($b->conf)['users']['alice']['used_bytes'] === 123,'Отказ копии сохраняет расход');
    foreach ([false,'100',-1,1.5] as $value) {
        $bad = $b->conf; $bad['telemt_user_limits']['alice']['quota'] = $value;
        $reject(fn()=>$b->telemtToml($bad),'Невалидная импортированная квота не становится безлимитом');
    }
    $b->telemtDelUser('alice');
    $check(!isset($b->conf['telemt_user_limits']['alice']) && !isset($b->telemtQuotaRead($b->conf)['users']['alice']), 'Удаление очищает метаданные и расход');
    $b->conf['telemt_user_limits']['alice'] = ['quota'=>1,'ips'=>1];
    $b->telemtUserAdd('alice');
    $check(!isset($b->conf['telemt_user_limits']['alice']) && $b->telemtQuotaRead($b->conf)['users']['alice']['used_bytes'] === 0,'Повторное имя не наследует ограничения/расход');
    echo "telemt_limits_test: $checks OK\n";
} finally {
    foreach (glob("$root/*") as $path) unlink($path);
    rmdir($root);
}
