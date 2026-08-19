<?php

// Лимитер подписок и признак rule-set-запроса.
// Регрессии из аудита 2026-08-12 (K3, K4 и ?cdn=):
//  - subRateLimit(): ключ ведра содержал sid, поэтому перебор sid не
//    ограничивался вовсе и раздувал /logs/sub_ratelimit.json;
//  - ruleSetNames()/subTemplate(): 'r' в токене подписки составляет клиент,
//    и любое имя отключало HWID-проверку и включало ведро 'rs' (240 вместо 30);
//  - subDomain(): ?cdn= уезжал в href и в URL rule-provider'ов без проверки.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function subRlAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

class SubRlTestBot extends Bot
{
    public array $pacFake = [];
    public string $rlFile = '';

    public function getPacConf()
    {
        return $this->pacFake;
    }

    public function getDomain($cdn = false)
    {
        return 'origin.example';
    }

    public function nginxGetTypeCert()
    {
        return '';
    }

    // Файл лимитера — во временный каталог: тесты не трогают /logs.
    public function subRateFile(): string
    {
        return $this->rlFile;
    }
}

$bot = (new ReflectionClass(SubRlTestBot::class))->newInstanceWithoutConstructor();
$bot->pacFake = [];

// ── 1. Ведро промахов не зависит от sid ─────────────────────────────────────
// Ключ строится так же, как в subRateLimit(): с sid для обычных вёдер и без
// него — для 'miss'. Проверяем именно это свойство ключа.
$key = fn(string $sid, string $ip, string $scope) => substr(
    hash('sha256', ($scope === 'miss' ? '' : $sid) . "|$ip|$scope"),
    0,
    16,
);
subRlAssert($key('aaa', '1.2.3.4', 'miss') === $key('bbb', '1.2.3.4', 'miss'),
    'промахи с одного IP попадают в один счётчик независимо от sid');
subRlAssert($key('aaa', '1.2.3.4', 'miss') !== $key('aaa', '5.6.7.8', 'miss'),
    'разные адреса считаются раздельно');
subRlAssert($key('aaa', '1.2.3.4', '') !== $key('bbb', '1.2.3.4', ''),
    'основное ведро по-прежнему пер-подписочное');
subRlAssert($key('aaa', '1.2.3.4', 'rs') !== $key('aaa', '1.2.3.4', ''),
    'ведро rule-set отдельно от ведра подписки');

// Тот же вывод, но через настоящий subRateLimit(): много промахов с разными
// sid дают ОДИН счётчик и одну запись в файле, а не N записей по единице.
$bot->rlFile  = sys_get_temp_dir() . '/sub_rl_' . getmypid() . '.json';
$bot->pacFake = ['sub_rate_max_miss' => 5, 'sub_rate_max' => 5, 'sub_rate_window' => 300];
$_SERVER['REMOTE_ADDR'] = '203.0.113.7';
unset($_SERVER['HTTP_X_FORWARDED_FOR']);
foreach (['s1', 's2', 's3', 's4'] as $sid) {
    $bot->subRateLimit($sid, 'miss'); // 4 промаха — до лимита (5) не доходим
}
$data = json_decode((string) file_get_contents($bot->rlFile), true);
subRlAssert(count($data) === 1, 'четыре промаха с разными sid — одна запись: ' . count($data));
subRlAssert(reset($data)[0] === 4, 'счётчик промахов дошёл до 4: ' . json_encode(reset($data)));
// Обычные выдачи по-прежнему считаются раздельно по подпискам.
$bot->subRateLimit('s1');
$bot->subRateLimit('s2');
$data = json_decode((string) file_get_contents($bot->rlFile), true);
subRlAssert(count($data) === 3, 'ведро подписки осталось пер-подписочным: ' . count($data));
@unlink($bot->rlFile);

// Аудит 2026-08-18: XFF на /pac nginx не перетирал, и клиент подменял его сам —
// ключ ведра это hash(sid|ip|scope), так что смена заголовка давала новый
// счётчик и лимит не срабатывал никогда. Теперь nginx ставит X-Real-IP, и он
// имеет приоритет над клиентским XFF.
$bot->rlFile = sys_get_temp_dir() . '/sub_rl_xff_' . getmypid() . '.json';
$_SERVER['REMOTE_ADDR']          = '10.10.0.4';   // адрес nginx внутри сборки
$_SERVER['HTTP_X_REAL_IP']       = '198.51.100.9'; // ставит наш nginx
foreach (['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4'] as $spoof) {
    $_SERVER['HTTP_X_FORWARDED_FOR'] = $spoof;     // подделка клиента
    $bot->subRateLimit('sX', 'miss');
}
$data = json_decode((string) file_get_contents($bot->rlFile), true);
subRlAssert(count($data) === 1,
    'подделка X-Forwarded-For больше не даёт новых счётчиков: ' . count($data));
subRlAssert(reset($data)[0] === 4, 'все четыре запроса попали в одно ведро');
@unlink($bot->rlFile);

// Фолбэк для нестандартного фронта без X-Real-IP: берём первый элемент XFF.
$bot->rlFile = sys_get_temp_dir() . '/sub_rl_fb_' . getmypid() . '.json';
unset($_SERVER['HTTP_X_REAL_IP']);
$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.10, 10.10.0.4';
$bot->subRateLimit('sY', 'miss');
$fb = json_decode((string) file_get_contents($bot->rlFile), true);
$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.11, 10.10.0.4';
$bot->subRateLimit('sY', 'miss');
$fb2 = json_decode((string) file_get_contents($bot->rlFile), true);
subRlAssert(count($fb) === 1 && count($fb2) === 2,
    'без X-Real-IP лимитер по-прежнему работает по первому элементу XFF');
@unlink($bot->rlFile);
unset($_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_X_REAL_IP']);

// ── 2. ruleSetNames: только объявленные шаблоном имена ──────────────────────
$sing = ['route' => ['rules' => [
    ['outbound' => 'block', 'createruleset' => [
        ['name' => 'blocklist', 'interval' => '1d', 'rules' => []],
        ['name' => 'warplist',  'interval' => '1d', 'rules' => []],
    ]],
    ['outbound' => 'direct'],
]]];
$names = $bot->ruleSetNames($sing, 'sing');
subRlAssert($names === ['blocklist', 'warplist'], 'sing-box: имена из createruleset[] — ' . json_encode($names));
subRlAssert(!in_array('zzz', $names, true), 'выдуманное имя не проходит');

$clash = ['rules' => [
    ['type' => 'RULE-SET', 'name' => 'process', 'list' => ['a'], 'interval' => 86400, 'behavior' => 'classical'],
    ['type' => 'MATCH', 'name' => 'final'],
    ['type' => 'RULE-SET', 'name' => 'noList'], // без list — правило-ссылка, не наш SRS
]];
subRlAssert($bot->ruleSetNames($clash, 'clash') === ['process'],
    'mihomo: только RULE-SET со списком');
subRlAssert($bot->ruleSetNames($clash, 'v2ray') === [], 'у v2ray rule-set-выборок нет');
subRlAssert($bot->ruleSetNames(null, 'sing') === [], 'нечитаемый шаблон не роняет проверку');

// Тот самый признак из subscription(): имя обязано совпасть.
$isRuleSetReq = fn(string $r, string $type, $tpl) => $r !== ''
    && in_array($type, ['clash', 'sing'], true)
    && in_array($r, $bot->ruleSetNames($tpl, $type), true);
subRlAssert($isRuleSetReq('blocklist', 'sing', $sing) === true, 'настоящая выборка rule-set распознана');
subRlAssert($isRuleSetReq('zzz', 'sing', $sing) === false,
    'подделанный r в токене НЕ считается выборкой rule-set (HWID и ведро остаются обычными)');
subRlAssert($isRuleSetReq('blocklist', 'v2ray', $sing) === false, 'для v2ray признак не выставляется');

// ── 3. subTemplate ──────────────────────────────────────────────────────────
$bot->pacFake = [
    'singtemplates'       => ['mine' => ['route' => ['rules' => []], 'mark' => 'personal']],
    'defaultsingtemplate' => base64_encode('mine'),
];
subRlAssert(($bot->subTemplate('mine', 'sing', $bot->pacFake)['mark'] ?? '') === 'personal',
    'персональный шаблон клиента');
subRlAssert(($bot->subTemplate('', 'sing', $bot->pacFake)['mark'] ?? '') === 'personal',
    'дефолтный шаблон из pac.json');
// Несуществующее имя и 'origin' уходят в /config/<type>.json, которого в тестах
// нет: важно, что это не фатал, а null.
subRlAssert($bot->subTemplate('origin', 'sing', $bot->pacFake) === null,
    'origin читается из /config (в тестах его нет — null, без фатала)');
subRlAssert($bot->subTemplate('нет-такого', 'sing', $bot->pacFake) === null,
    'неизвестное имя шаблона откатывается на origin');

// ── 4. subDomain: только домены из настроек ─────────────────────────────────
// Синтаксической проверки мало (аудит 2026-08-18): домен отсюда уезжает в
// ~domain~/~dns~, в rule-providers mihomo, в createRuleSet() sing-box и в
// ссылку самообновления подписки. Обладатель чужого sub-URL пересылал жертве
// тот же URL с &cdn=evil.tld — и её клиент шёл за правилами, DoH и
// обновлением подписки на хост атакующего.
$bot->pacFake = [
    'domain'         => 'sub.example',
    'domain_aliases' => ['alias.example'],
    'linkdomain'     => 'cdn.example',
];
$_SERVER['SERVER_NAME'] = 'sub.example';
$_GET['cdn'] = "evil.example'\"><b";
subRlAssert($bot->subDomain($bot->pacFake) === 'sub.example',
    'мусор в ?cdn= игнорируется: ' . $bot->subDomain($bot->pacFake));
$_GET['cdn'] = 'evil.example';
subRlAssert($bot->subDomain($bot->pacFake) === 'sub.example',
    'ГЛАВНОЕ: синтаксически валидный, но чужой домен в ?cdn= не принимается');
$_GET['cdn'] = 'cdn.example';
subRlAssert($bot->subDomain($bot->pacFake) === 'cdn.example',
    'настроенный cdn-домен (linkdomain) принимается');
$_GET['cdn'] = 'ALIAS.example';
subRlAssert($bot->subDomain($bot->pacFake) === 'alias.example',
    'алиас домена принимается независимо от регистра');
unset($_GET['cdn']);
$_SERVER['SERVER_NAME'] = 'evil"onload=x';
subRlAssert($bot->subDomain($bot->pacFake) === 'origin.example',
    'мусорный Host тоже отбрасывается');
$_SERVER['SERVER_NAME'] = 'evil.example';
subRlAssert($bot->subDomain($bot->pacFake) === 'origin.example',
    'чужой Host отбрасывается так же, как чужой ?cdn=');
$_SERVER['SERVER_NAME'] = 'alias.example';
subRlAssert($bot->subDomain($bot->pacFake) === 'alias.example',
    'свой Host из списка алиасов принимается');
unset($_SERVER['SERVER_NAME']);
subRlAssert($bot->subDomain($bot->pacFake) === 'origin.example', 'фолбэк на домен из конфига');

if ($failed) {
    echo "audit_sub_ratelimit_test FAILED: $failed\n";
    exit(1);
}
echo "audit_sub_ratelimit_test OK\n";
