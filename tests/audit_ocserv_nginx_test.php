<?php

// Генерация конфигов ocserv и upstream-nginx.
// Регрессии из аудита 2026-08-12 (K8, K9, K10 и setUpstreamDomainOcserv):
//  - ocservRoute(): маршруты склеивались в одну строку, и ocserv не стартовал;
//  - подсеть проверялась регуляркой без якоря — «10.0.0.0/24 foo» уезжало целиком;
//  - поддомены oc/np сохранялись без валидации и уезжали в upstream.conf;
//  - chocdns(): многострочный ввод становился набором директив ocserv.conf;
//  - setUpstreamDomainOcserv(): жадный .+ и preg_replace с обратными ссылками
//    (в соседнем setUpstreamDomainNaive это уже было исправлено).

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function ocAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

class OcNginxTestBot extends Bot
{
    public array $pacFake  = [];
    public string $conf    = '';
    public string $written = '';
    public array $sent     = [];

    public function getPacConf()
    {
        return $this->pacFake;
    }

    public function setPacConf(array $conf)
    {
        $this->pacFake = $conf;
        return true;
    }

    public function restartOcserv($conf, bool $syncCamouflage = true)
    {
        $this->written = (string) $conf;
        return true;
    }

    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    {
        $this->sent[] = $text;
        return ['result' => ['message_id' => 1]];
    }

    public function menu($type = false, $arg = false, $return = false)
    {
        return null;
    }
}

$bot = (new ReflectionClass(OcNginxTestBot::class))->newInstanceWithoutConstructor();
$bot->input = ['chat' => 1, 'message_id' => 2];

// ── 1. ocservRoute: каждая подсеть своей строкой ────────────────────────────
$base = "auth = plain\nroute = default\ntcp-port = 443\n";

$t = Bot::ocservRouteConf($base, ['10.0.0.0/24', '192.168.0.0/16']);
ocAssert(substr_count($t, 'route = ') === 2, 'две директивы route: ' . json_encode($t));
ocAssert(!str_contains($t, '/24route'), 'строки не склеены: ' . json_encode($t));
foreach (explode("\n", trim($t)) as $line) {
    ocAssert(substr_count($line, 'route = ') <= 1, "в строке не больше одного route: $line");
}
ocAssert(str_contains($t, "tcp-port = 443\n"), 'остальные директивы целы');
ocAssert(!str_contains($t, 'route = default'), 'default снят, раз подсети заданы');

// Мусор в списке подсетей в конфиг не уезжает.
foreach (['10.0.0.0/24 foo', '999.1.1.1/24', '10.0.0.0/33', 'вообще не подсеть'] as $bad) {
    $t = Bot::ocservRouteConf($base, [$bad]);
    ocAssert(str_contains($t, 'route = default') && !str_contains($t, $bad),
        "мусор «{$bad}» отброшен: " . json_encode($t));
}
ocAssert(str_contains(Bot::ocservRouteConf($base, []), 'route = default'),
    'без подсетей остаётся default');
// Конфиг без завершающего перевода строки: маршрут не должен приклеиться к
// последней директиве.
$t = Bot::ocservRouteConf("auth = plain\ntcp-port = 443", ['10.0.0.0/24']);
ocAssert(str_contains($t, "tcp-port = 443\nroute = 10.0.0.0/24"),
    'маршрут начинается с новой строки: ' . json_encode($t));

// ── 2. isSubdomainLabel ─────────────────────────────────────────────────────
ocAssert(Bot::isSubdomainLabel('oc') === true, 'обычная метка');
ocAssert(Bot::isSubdomainLabel('a1b2c3d4') === true, 'хеш-метка по умолчанию');
ocAssert(Bot::isSubdomainLabel('my-vpn') === true, 'дефис внутри допустим');
ocAssert(Bot::isSubdomainLabel("x;}\nserver { listen 443; }") === false, 'инъекция в nginx-конфиг');
ocAssert(Bot::isSubdomainLabel('a.b') === false, 'точка — это уже не одна метка');
ocAssert(Bot::isSubdomainLabel('-x') === false, 'дефис в начале');
ocAssert(Bot::isSubdomainLabel('') === false, 'пустая метка');
ocAssert(Bot::isSubdomainLabel(str_repeat('a', 64)) === false, 'метка длиннее 63 символов');

// Мусор в pac.json (от старых версий) не выдаётся наружу.
$bot->pacFake = ['oc_domain' => "x;}\nserver{}"];
ocAssert($bot->getHashSubdomain('oc') === '', 'сохранённый мусор не уходит в конфиг');
$bot->pacFake = ['oc_domain' => 'good'];
ocAssert($bot->getHashSubdomain('oc') === 'good', 'валидный поддомен возвращается');

// Ввод не сохраняется.
$bot->pacFake = ['domain' => 'example.com'];
$bot->sent    = [];
$bot->chNpSubdomain("x;}\nserver { listen 443; }");
ocAssert(!isset($bot->pacFake['np_domain']), 'битый поддомен не сохранён');
ocAssert(count($bot->sent) === 1, 'пользователю сказано о формате');

// ── 3. chocdns: только адрес ────────────────────────────────────────────────
$bot->sent    = [];
$bot->written = '';
$bot->chocdns("8.8.8.8\nroute = 0.0.0.0/0");
ocAssert($bot->written === '', 'многострочный ввод в ocserv.conf не уехал');
ocAssert(count($bot->sent) === 1, 'пользователю сказано о формате dns');

// ── 4. upstreamReplace: нежадный маркер + литеральная замена ────────────────
$nginx = "#ocserv\n#oc.\$domain ocserv;\n#ocserv\n"
    . "map \$x \$y { default other; }\n"
    . "# ниже по файлу слово #ocserv в комментарии\n";
$t = Bot::upstreamReplace($nginx, '#ocserv', 'a1b2.example.com ocserv;');
ocAssert(str_contains($t, 'map $x $y { default other; }'),
    'третье упоминание маркера не съело соседние блоки: ' . json_encode($t));
ocAssert(substr_count($t, '#ocserv') === 3, 'маркеры на месте');
ocAssert(str_contains($t, "#ocserv\na1b2.example.com ocserv;\n#ocserv"), 'тело заменено');
// Обратные ссылки в теле: у preg_replace «$1» подставился бы как группа.
$t = Bot::upstreamReplace($nginx, '#ocserv', 'x$1\1.example.com ocserv;');
ocAssert(str_contains($t, 'x$1\1.example.com'), 'тело замены подставлено литералом: ' . json_encode($t));
// Тот же хелпер обслуживает и ветку naive — многострочное тело.
$t = Bot::upstreamReplace("#naive\n#np.\$domain naive;\n#naive\n", '#naive', "a naive;\nb naive;");
ocAssert(str_contains($t, "a naive;\nb naive;"), 'многострочное тело для naive');

// ── 5. addDomain: невалидное имя не сохраняется ─────────────────────────────
ocAssert(preg_match(Bot::DOMAIN_RE, 'example.com') === 1, 'обычный домен валиден');
ocAssert(preg_match(Bot::DOMAIN_RE, 'a-b.example.co.uk') === 1, 'многоуровневый домен валиден');
ocAssert(preg_match(Bot::DOMAIN_RE, 'not a domain') === 0, 'пробелы недопустимы');
ocAssert(preg_match(Bot::DOMAIN_RE, 'example.com; rm -rf /') === 0, 'shell-метасимволы недопустимы');
ocAssert(preg_match(Bot::DOMAIN_RE, '') === 0, 'пустая строка невалидна');



if ($failed) {
    echo "audit_ocserv_nginx_test FAILED: $failed\n";
    exit(1);
}
echo "audit_ocserv_nginx_test OK\n";
