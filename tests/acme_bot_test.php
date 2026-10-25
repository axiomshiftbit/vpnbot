<?php
// Бот и служба хоста acme-window (BotAcme, acme_renew.php): запросы, состояние,
// меню, уведомления, имена сертификата и выбор пути в setSSL.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level, $message, $file, $line) { if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line); return true; });

$checks = 0;
function check(bool $condition, string $label): void { global $checks; $checks++; if (!$condition) { fwrite(STDERR, "FAIL: $label\n"); exit(1); } }

class AcmeBot extends Bot
{
    public array $conf = [];
    public array $sent = [];
    public array $updated = [];
    public array $issued = [];
    public array $applied = [];
    public array $managed = [];
    public int $issueCode = 0;

    public function __construct(string $language = 'ru')
    {
        $this->key = '123456:TEST-KEY';
        $this->ip = '203.0.113.9';
        $this->language = $language;
        Lang::$en = $language === 'en';
        require __DIR__ . '/../app/i18n.php';
        $this->i18n = $i;
        $this->input = ['chat' => 1, 'message_id' => 2, 'callback_id' => 3, 'callback' => ''];
    }
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { $this->conf = $conf; }
    public function managedCertificateNames(): array { return $this->managed; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    { $this->sent[] = [$chat, $text, $button]; return ['ok' => true]; }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML')
    { $this->updated[] = [$text, $button]; return ['ok' => true]; }
    public function menu($type = false, $arg = false, $return = false) { $this->updated[] = ['menu', $type]; }
    public function issueLetsencrypt(array $conf, bool $dryRun = false): array { $this->issued[] = $dryRun; return [$this->issueCode, ['certbot output']]; }
    public function applyCertificateBundle(string $bundle, array $conf): bool { $this->applied[] = $conf; return true; }
    public function acmeWaitTaken(string $file, float $seconds = 4.0): bool { return !file_exists($file); }
}

$root = sys_get_temp_dir() . '/vpnbot-acme-' . bin2hex(random_bytes(6));
register_shutdown_function(static fn() => exec('rm -rf ' . escapeshellarg($root)));
mkdir("$root/state", 0700, true);
mkdir("$root/request", 0700, true);

$state = static function (string $name, array $extra = []) use ($root): void {
    file_put_contents("$root/state/$name.json", json_encode($extra + [
        'version' => 1, 'name' => $name, 'kind' => $name === 'vpnbot' ? 'vpnbot' : 'nginx-ssl',
        'label' => ['ru' => $name === 'vpnbot' ? 'бот' : 'видеобот', 'en' => $name === 'vpnbot' ? 'bot' : 'video bot'],
        'auto' => true, 'updated' => time(), 'busy' => false, 'not_after' => time() + 40 * 86400,
        'not_before' => time() - 50 * 86400, 'due_at' => time() + 10 * 86400, 'next_attempt' => time() + 10 * 86400,
        'last_attempt' => 0, 'last_result' => '', 'last_detail' => '', 'last_success' => 0, 'failures' => 0, 'last_rejected' => 0,
    ]));
};
$agent = static function (int $updated) use ($root): void {
    file_put_contents("$root/state/agent.json", json_encode(['version' => 1, 'updated' => $updated, 'targets' => ['vpnbot', 'videobot']]));
};
$requests = static fn () => array_map('basename', glob("$root/request/*") ?: []);
$clear = static function () use ($root): void { foreach (glob("$root/request/*") ?: [] as $f) unlink($f); };

$bot = new AcmeBot();
$bot->acmeRoot = $root;

// ── служба есть или нет ──
check($bot->acmeAgent() === null && !$bot->acmeAgentStale(), 'без agent.json службы нет');
$agent(time() - 4 * 3600);
check($bot->acmeAgent() === null && $bot->acmeAgentStale(), 'старый agent.json — служба молчит');
$agent(time());
check(is_array($bot->acmeAgent()), 'свежий agent.json — служба есть');

// ── состояние: порядок, проверка, мусор ──
$state('videobot');
$state('vpnbot');
file_put_contents("$root/state/broken.json", '{oops');
file_put_contents("$root/state/other.json", json_encode(['name' => 'wrong']));
file_put_contents("$root/state/Bad.json", json_encode(['name' => 'Bad']));
// Ссылка на правдоподобный файл вне state: отбрасывается именно как ссылка.
mkdir("$root/outside");
file_put_contents("$root/outside/evil.json", json_encode(['name' => 'evil', 'kind' => 'vpnbot', 'updated' => time()]));
symlink("$root/outside/evil.json", "$root/state/evil.json");
$states = $bot->acmeStates();
check(array_keys($states) === ['vpnbot', 'videobot'], 'свой сертификат первым, мусор и ссылки отброшены: ' . implode(',', array_keys($states)));
check($bot->acmeSelfTarget() === 'vpnbot', 'цель бота найдена по kind');
$state('videobot', ['busy' => true, 'updated' => time() - 2 * 3600]);
check($bot->acmeStates()['videobot']['busy'] === false, 'зависший busy не показывается вечно');
$state('videobot', ['last_detail' => str_repeat('x', 1000)]);
check(mb_strlen($bot->acmeStates()['videobot']['last_detail']) === 300, 'пояснение обрезается');

// ── запросы ──
check($bot->acmeRequest('renew', 'vpnbot') && $requests() === ['req-renew-vpnbot'], 'запрос выпуска записан');
check($bot->acmeRequest('renew', 'vpnbot') && $requests() === ['req-renew-vpnbot'], 'повторный запрос не дублируется');
$clear();
check(!$bot->acmeRequest('renew', 'unknown') && !$bot->acmeRequest('renew', '../x') && !$bot->acmeRequest('rm', 'vpnbot'), 'чужие цели и действия отвергаются');
check($requests() === [], 'отвергнутые запросы не оставляют файлов');
check($bot->acmeRequest('refresh') && $requests() === ['req-refresh'], 'запрос обновления без цели');
$clear();

// ── имена и команда certbot ──
$bot->conf = ['domain' => 'vpn.example.org', 'oc_domain' => 'aaaa1111', 'np_domain' => 'bbbb2222', 'tw_domain' => 'cccc3333',
    'telemt_web' => 1, 'adguardkey' => 'dns', 'domain_aliases' => ['alias.example.net']];
$bot->managed = ['anytls.example.org', 'vpn.example.org'];
$names = $bot->letsencryptNames($bot->conf);
check($names === ['vpn.example.org', 'aaaa1111.vpn.example.org', 'bbbb2222.vpn.example.org', 'cccc3333.vpn.example.org',
    'dns.vpn.example.org', 'alias.example.net', 'dns.alias.example.net', 'anytls.example.org'], 'имена как у прежней команды, без повторов: ' . implode(' ', $names));
$cmd = $bot->letsencryptCommand($bot->conf);
check(str_starts_with($cmd, 'timeout -k 10 300 certbot certonly --force-renew '), 'certbot ограничен по времени');
check(str_contains($cmd, "--cert-name 'vpn.example.org' -d 'vpn.example.org' -d 'aaaa1111.vpn.example.org'"), 'одна цепочка на домен, первым — домен');
check(str_contains($cmd, '--webroot -w /certs/') && !str_contains($cmd, '--dry-run'), 'webroot прежний');
check(str_contains($bot->letsencryptCommand($bot->conf, true), ' --dry-run 2>&1'), 'пробный выпуск');
unset($bot->conf['telemt_web']);
check(!in_array('cccc3333.vpn.example.org', $bot->letsencryptNames($bot->conf), true), 'поддомен WEB telemt только при включённом WEB');
foreach ([['domain' => 'vpn.example.org;id'], ['domain' => ''], ['domain' => 'vpn.example.org', 'adguardkey' => 'a b']] as $bad) {
    try {
        $bot->letsencryptNames($bad);
        check(false, 'опасное имя принято: ' . json_encode($bad));
    } catch (InvalidArgumentException $e) {
        check($e->getMessage() !== '', 'опасное имя отвергнуто');
    }
}

// ── setSSL: со службой — запрос, без неё — certbot как раньше ──
$bot->conf = ['domain' => 'vpn.example.org', 'oc_domain' => 'aaaa1111', 'np_domain' => 'bbbb2222'];
$bot->setSSL('letsencrypt');
check($requests() === ['req-renew-vpnbot'], 'со службой кнопка ставит запрос');
check($bot->issued === [] && $bot->applied === [], 'со службой certbot в боте не запускается');
check(!empty($bot->conf['acme_requested']), 'первый выпуск помечен для check');
check(str_contains(end($bot->sent)[1], 'служб'), 'администратор знает, куда ушёл запрос');
$clear();
unlink("$root/state/agent.json");
$bot->sent = [];
$bot->issueCode = 1;
$bot->setSSL('letsencrypt');
check($bot->issued === [false] && $requests() === [], 'без службы certbot запускается сам');
check(str_starts_with(end($bot->sent)[1], "ERROR\n"), 'отказ certbot виден администратору');
$bot->conf = ['domain' => 'bad domain'];
$bot->issued = [];
$bot->setSSL('letsencrypt');
check($bot->issued === [] && str_contains(end($bot->sent)[1], 'ОШИБКА'), 'неверный домен останавливает выпуск');
$agent(time());

// ── меню и кнопки ──
foreach (['ru', 'en'] as $lang) {
    $b = new AcmeBot($lang);
    $b->acmeRoot = $root;
    $state('vpnbot', ['last_attempt' => time() - 600, 'last_result' => 'fail_issue', 'failures' => 2, 'last_rejected' => time()]);
    $b->acmeMenu();
    [$text, $buttons] = end($b->updated);
    $callbacks = array_merge(...array_map(fn ($row) => array_column($row, 'callback_data'), $buttons));
    check(in_array('/acmeAuto vpnbot off', $callbacks, true) && in_array('/acmeRenew videobot', $callbacks, true), "$lang: кнопки обеих целей");
    check(in_array('/menu config', $callbacks, true) && in_array('/acmeMenu refresh', $callbacks, true), "$lang: назад и обновить");
    check(in_array('/menuhelp acme 0', $callbacks, true), "$lang: кнопка справки");
    foreach ($callbacks as $cb) {
        check(strlen($cb) <= 64, "$lang: callback_data не длиннее 64 байт: $cb");
    }
    $cyr = (bool) preg_match('~[а-яА-Я]~u', $text);
    check($lang === 'ru' ? $cyr : !$cyr, "$lang: текст меню на своём языке");
    check(str_contains($text, $lang === 'ru' ? 'неудач подряд: 2' : 'failures in a row: 2'), "$lang: счёт неудач");
    check(str_contains($text, $lang === 'ru' ? 'видеобот' : 'video bot'), "$lang: подпись цели на своём языке");
}
$state('vpnbot');

// Подтверждение перед принудительным выпуском.
$bot->updated = [];
$bot->acmeRenew('vpnbot', false);
check($requests() === [] && end($bot->updated)[1][0][0]['callback_data'] === '/acmeRenew vpnbot confirm', 'выпуск сейчас только после подтверждения');
$bot->acmeRenew('vpnbot', true);
check($requests() === ['req-renew-vpnbot'], 'подтверждённый выпуск ставит запрос');
$clear();
$bot->acmeRenew('nobody', true);
check($requests() === [], 'неизвестная цель не принимается');
$bot->acmeAuto('videobot', false);
check($requests() === ['req-auto-off-videobot'], 'выключение автообновления');
$clear();

// ── уведомления ──
$s = $bot->acmeStates()['vpnbot'];
$s['last_detail'] = '<b>Challenge</b> & failed';
$text = $bot->acmeNotifyText($s, 'fail_issue');
check(str_contains($text, '&lt;b&gt;Challenge&lt;/b&gt; &amp; failed') && !str_contains($text, '<b>Challenge'), 'пояснение экранировано');
check(str_contains($text, 'следующая попытка'), 'после неудачи — время следующей попытки');
$ok = $bot->acmeNotifyText($s, 'ok');
check(str_contains($ok, '✅') && !str_contains($ok, 'Challenge'), 'успех без пояснения ошибки');
check(str_contains($bot->acmeNotifyText($s, 'rate_limited'), 'лимит'), 'отказ по лимиту понятен');
check($bot->acmeResultText('<x>') === '&lt;x&gt;', 'неизвестный код экранирован');

// ── установка бандла: флаг первого выпуска снимается ──
$bot->conf = ['domain' => 'vpn.example.org', 'acme_requested' => 1];
check((fn () => Bot::applyCertificateBundle('no key here', ['domain' => 'x']))->call($bot) === false && $bot->conf['acme_requested'] === 1,
    'без ключа в бандле ничего не записывается');
$bot->pac = "$root/pac.json";          // каталог блокировки бэкапа
$bot->applied = [];
check($bot->installLetsencrypt('vpn.example.org') && end($bot->applied)['letsencrypt'] === 'letsencrypt'
    && !isset(end($bot->applied)['acme_requested']), 'после установки сертификат помечен как Let\'s Encrypt, пометка запроса снята');
// Восстановление из бэкапа прошло между выпуском и установкой.
$bot->applied = [];
$bot->conf = ['domain' => 'other.example.org', 'letsencrypt' => 'letsencrypt'];
check(!$bot->installLetsencrypt('vpn.example.org') && $bot->applied === [], 'домен сменился — выпущенный для прежнего не ставится');
$bot->conf = ['domain' => 'vpn.example.org', 'letsencrypt' => 'self'];
check(!$bot->installLetsencrypt('vpn.example.org') && $bot->applied === [], 'восстановлен свой сертификат — Let\'s Encrypt его не затирает');
// Идёт экспорт или восстановление: установка ждёт блокировку бэкапа.
$bot->conf = ['domain' => 'vpn.example.org', 'letsencrypt' => 'letsencrypt'];
$held = fopen("$root/.backup.lock", 'c');
flock($held, LOCK_EX);
$bot->acmeInstallLockWait = 1;
$started = microtime(true);
try {
    $bot->installLetsencrypt('vpn.example.org');
    check(false, 'установка прошла при чужой блокировке бэкапа');
} catch (RuntimeException $e) {
    check(microtime(true) - $started >= 0.9 && $bot->applied === [], 'установка ждала блокировку и ничего не записала');
}
flock($held, LOCK_UN);
fclose($held);
check($bot->installLetsencrypt('vpn.example.org') && count($bot->applied) === 1, 'после восстановления установка проходит');
$bot->applied = [];
$issuedNames = $bot->letsencryptNames($bot->conf);
$bot->conf['domain_aliases'] = ['restored-alias.example.org'];
check(!$bot->installLetsencrypt('vpn.example.org', $issuedNames) && $bot->applied === [],
    'основной домен тот же, но алиасы изменились — восстановленный сертификат сохранён');
check($bot->installLetsencrypt('vpn.example.org', array_reverse($bot->letsencryptNames($bot->conf)))
    && count($bot->applied) === 1, 'неизменившиеся имена принимаются независимо от порядка SAN');

// ── acme_renew.php: коды выхода без домена и без аргументов ──
// Bot читает /config/pac.json по абсолютному пути. Там, где он есть (контейнер
// с настоящим ботом), CLI мог бы запустить настоящий certbot — не трогаем.
if (file_exists('/config/pac.json')) {
    echo "acme_renew.php: пропуск — /config/pac.json настоящей установки\n";
} else {
    $app = "$root/app";
    mkdir($app);
    foreach (array_merge(glob(__DIR__ . '/../app/*.php'), glob(__DIR__ . '/../app/panel/*.php')) as $file) {
        $dest = str_contains($file, '/panel/') ? "$app/panel/" . basename($file) : "$app/" . basename($file);
        @mkdir(dirname($dest));
        copy($file, $dest);
    }
    file_put_contents("$app/config.php", '<?php $c = ["key" => "1:x", "admin" => [1]];');
    // check первым: issue запускается, только если check подтвердил «не Let's Encrypt».
    foreach ([['check', 3], ['issue', 3], ['install', 3], ['notify nobody ok', 2], ['', 2]] as [$args, $code]) {
        $out = [];
        exec('cd ' . escapeshellarg($app) . ' && php acme_renew.php ' . $args . ' 2>&1', $out, $rc);
        check($rc === $code, "acme_renew.php $args → $code (получено $rc): " . implode(' ', $out));
    }
    // Настоящий CLI передаёт домен выпуска в проверку под блокировкой.
    // Подменены только настройки и применение сертификата, без сервисов хоста.
    $fixture = <<<'PHP'
class AcmeCliBot extends Bot {
    public function __construct($key, $i) { $this->pac = __DIR__ . '/pac.json'; }
    public function getPacConf() { return ['domain' => 'restored.example.org', 'letsencrypt' => 'letsencrypt']; }
    public function letsencryptNames(array $conf): array { return [$conf['domain'], 'restored-alias.example.org']; }
    public function applyCertificateBundle(string $bundle, array $conf): bool { return true; }
}
PHP;
    file_put_contents("$app/config.php", file_get_contents("$app/config.php") . "\n" . $fixture);
    file_put_contents("$app/acme_renew.php", str_replace('new Bot(', 'new AcmeCliBot(', file_get_contents("$app/acme_renew.php")));
    foreach ([['install issued.example.org', 1], ['install restored.example.org', 0], ['install', 0]] as [$args, $code]) {
        $out = [];
        exec('cd ' . escapeshellarg($app) . ' && php acme_renew.php ' . $args . ' 2>&1', $out, $rc);
        check($rc === $code, "acme_renew.php $args: домен выпуска и совместимость → $code (получено $rc): " . implode(' ', $out));
    }
    foreach ([['issued-alias.example.org', 1], ['restored-alias.example.org', 0]] as [$alias, $code]) {
        $out = [];
        $names = escapeshellarg(json_encode(['restored.example.org', $alias]));
        exec('cd ' . escapeshellarg($app) . ' && php acme_renew.php install restored.example.org ' . $names . ' 2>&1', $out, $rc);
        check($rc === $code, "acme_renew.php: имена выпуска $alias → $code (получено $rc): " . implode(' ', $out));
    }
}

echo "acme_bot_test OK ($checks checks)\n";
