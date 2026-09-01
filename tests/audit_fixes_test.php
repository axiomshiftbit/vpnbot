<?php

/**
 * Проверки к аудиту d9b044a..116b8d2 и последующим правкам.
 *
 * Коммит 56831f0 заявлял проверки на whitelist $fun, экранирование exclude и
 * эквивалентность alignment, но в репозиторий они не попали. Здесь они есть,
 * плюс покрытие гейта Bot::webappAuth() и прав на приватный ключ.
 */

require_once __DIR__ . '/../app/calc.php';
require_once __DIR__ . '/../app/bot.php';

function auditAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

// ── Bot::webappAuth(): подпись + auth_date + user.id ─────────────────────────
$key    = 'test-bot-token:AAH0000000000000000000000000';
$admins = [111, 222];

/** Собирает валидный initData так же, как это делает Telegram. */
$sign = function (array $fields) use ($key): array {
    $t = $fields;
    ksort($t);
    $s = [];
    foreach ($t as $k => $v) {
        $s[] = "$k=$v";
    }
    $sk             = hash_hmac('sha256', $key, 'WebAppData', true);
    $fields['hash'] = hash_hmac('sha256', implode("\n", $s), $sk);

    return $fields;
};

$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
$now = 1_800_000_000;

$valid = $sign(['auth_date' => $now - 10, 'user' => json_encode(['id' => 111])]);
auditAssert(
    $bot->webappAuth($valid, $key, $admins, 86400, $now),
    'валидный свежий initData админа должен проходить'
);

// Подпись — обязательна.
$forged         = $valid;
$forged['hash'] = str_repeat('0', 64);
auditAssert(!$bot->webappAuth($forged, $key, $admins, 86400, $now), 'подделанный hash не должен проходить');

$tampered              = $valid;
$tampered['auth_date'] = $now;
auditAssert(!$bot->webappAuth($tampered, $key, $admins, 86400, $now), 'изменённое поле должно ломать подпись');

auditAssert(!$bot->webappAuth([], $key, $admins, 86400, $now), 'пустой запрос не должен проходить');
auditAssert(!$bot->webappAuth($valid, 'other-key', $admins, 86400, $now), 'чужой ключ не должен проходить');

// Свежесть: строка initData из access_log не должна работать вечно.
$stale = $sign(['auth_date' => $now - 86401, 'user' => json_encode(['id' => 111])]);
auditAssert(
    !$bot->webappAuth($stale, $key, $admins, 86400, $now),
    'протухший initData (старше окна) не должен проходить — иначе запись из лога вечна'
);
$edge = $sign(['auth_date' => $now - 86400, 'user' => json_encode(['id' => 111])]);
auditAssert($edge && $bot->webappAuth($edge, $key, $admins, 86400, $now), 'ровно граница окна ещё валидна');

$noDate = $sign(['user' => json_encode(['id' => 111])]);
auditAssert(!$bot->webappAuth($noDate, $key, $admins, 86400, $now), 'initData без auth_date не должен проходить');

// Владелец: корректная подпись НЕ-админа не должна открывать эндпоинт.
$stranger = $sign(['auth_date' => $now - 10, 'user' => json_encode(['id' => 999])]);
auditAssert(
    !$bot->webappAuth($stranger, $key, $admins, 86400, $now),
    'валидно подписанный initData не-админа не должен проходить'
);
$noUser = $sign(['auth_date' => $now - 10]);
auditAssert(!$bot->webappAuth($noUser, $key, $admins, 86400, $now), 'initData без user не должен проходить');
auditAssert(!$bot->webappAuth($valid, $key, [], 86400, $now), 'при пустом списке админов не должен проходить никто');

// id приходит числом в JSON, а в config.php admin может лежать строкой.
auditAssert(
    $bot->webappAuth($valid, $key, ['111'], 86400, $now),
    'admin-id строкой должен сопоставляться с числовым user.id'
);

// Массивы в query («?hash[]=1», «?user[]=1») не должны ни проходить, ни давать
// «Array to string conversion»: hash попадал в (string), остальное — в "$k=$v".
set_error_handler(function ($no, $str) {
    throw new RuntimeException("PHP notice/warning в webappAuth: $str");
});
auditAssert(!$bot->webappAuth(['hash' => ['x']], $key, $admins, 86400, $now), 'hash массивом не должен проходить');
auditAssert(
    !$bot->webappAuth(['hash' => str_repeat('0', 64), 'x' => ['y']], $key, $admins, 86400, $now),
    'параметр массивом не должен проходить'
);
$userArr         = $valid;
$userArr['user'] = ['id' => 111];
auditAssert(!$bot->webappAuth($userArr, $key, $admins, 86400, $now), 'user массивом не должен проходить');
restore_error_handler();

// ── callIpReturn(): whitelist динамического вызова ───────────────────────────
// $fun приезжает из callback_data и вызывался как $this->{$fun}().
$spy = new class extends Bot {
    public array $calls = [];

    public function __construct()
    {
    }

    public function analysisIp(int $page = 0, $return = false)
    {
        $this->calls[] = 'analysisIp';
    }

    public function denyList($page = 0, $white = 0)
    {
        $this->calls[] = 'denyList';
    }

    public function ipMenu()
    {
        $this->calls[] = 'ipMenu';
    }

    public function restart($all = false)
    {
        $this->calls[] = 'restart';
    }

    public function call(string $fun): array
    {
        $this->calls = [];
        $m           = new ReflectionMethod(Bot::class, 'callIpReturn');
        $m->setAccessible(true);
        $m->invoke($this, $fun, 0, 0);

        return $this->calls;
    }
};

auditAssert($spy->call('analysisIp') === ['analysisIp'], 'analysisIp должен вызываться');
auditAssert($spy->call('denyList') === ['denyList'], 'denyList должен вызываться');
// Произвольный метод Bot из подделанной callback_data — только в меню.
foreach (['restart', 'ipMenu', 'getPacConf', 'nonexistentMethod', '', '0'] as $bad) {
    $calls = $spy->call($bad);
    auditAssert(
        !in_array('restart', $calls, true),
        "callIpReturn('$bad') не должен дёргать произвольный метод"
    );
    auditAssert($calls === [] || $calls === ['ipMenu'], "callIpReturn('$bad') должен уходить в ipMenu");
}

// ── excludePattern(): экранирование ──────────────────────────────────────────
require_once __DIR__ . '/../app/exclude_pattern.php';

// «.» не должна матчить произвольный символ.
$p = excludePattern(['ya.ru']);
auditAssert(preg_match($p, 'ya.ru') === 1, 'ya.ru должен исключаться');
auditAssert(preg_match($p, 'yaXru') === 0, '«.» не должна матчить произвольный символ');

// Спецсимволы не должны ломать регулярку целиком (иначе preg_match вернёт false
// и исключения перестают работать вообще).
foreach (['a+b.com', 'x(y).net', 'a[b].org', 'q~w.io', 'a|b.dev', 'c\\d.ru'] as $weird) {
    $p = excludePattern([$weird]);
    auditAssert(preg_match($p, $weird) === 1, "«{$weird}» должен матчить сам себя");
    auditAssert(preg_match($p, 'unrelated.example') === 0, "«{$weird}» не должен матчить чужой домен");
}

// «~» — делимитер паттерна: без preg_quote($e, '~') регулярка разваливалась.
$p = excludePattern(['q~w.io']);
auditAssert(preg_match($p, 'q~w.io') !== false, '«~» в exclude не должен ломать регулярку');

// Несколько записей объединяются через |.
$p = excludePattern(['ya.ru', 'vk.com']);
auditAssert(preg_match($p, 'vk.com') === 1 && preg_match($p, 'ya.ru') === 1, 'оба домена должны исключаться');
auditAssert(preg_match($p, 'ok.ru') === 0, 'посторонний домен не должен исключаться');

// ── Calc::alignment(): эквивалентность и отсутствие Undefined array key ──────
$calc = new Calc();

/** Референс: разворачиваем диапазоны поэлементно и сливаем обратно. */
$reference = function (array $arr): array {
    $set = [];
    foreach ($arr as [$a, $b]) {
        for ($i = $a; $i <= $b; $i++) {
            $set[$i] = true;
        }
    }
    ksort($set);
    $out  = [];
    $prev = null;
    foreach (array_keys($set) as $n) {
        if ($prev !== null && $n === $prev + 1) {
            $out[count($out) - 1][1] = $n;
        } else {
            $out[] = [$n, $n];
        }
        $prev = $n;
    }

    return $out;
};

$cases = [
    [[0, 50], [100, 200]],
    [[1, 5], [6, 9]],                 // смежные — должны слиться
    [[0, 3]],                         // диапазон с нуля: старая версия давала [null, 3]
    [[1, 1]],
    [[5, 10], [1, 3]],                // несортированный вход
    [[1, 10], [3, 5]],                // вложенный
    [[1, 4], [4, 8]],                 // пересечение
    [[10, 12], [1, 2], [5, 5], [3, 4]],
    [[0, 0], [2, 2], [1, 1]],
];
foreach ($cases as $n => $case) {
    $got  = $calc->alignment($case);
    $want = $reference($case);
    auditAssert(
        $got === $want,
        "alignment #$n: получено " . json_encode($got) . ', ожидалось ' . json_encode($want)
    );
}

// Пустой вход не должен падать и не должен давать затравку [[]].
auditAssert($calc->alignment([]) === [], 'alignment([]) должен вернуть []');

// Ни один вызов не должен поднимать Undefined array key.
set_error_handler(function ($no, $str) {
    throw new RuntimeException("PHP notice/warning в alignment: $str");
});
foreach ($cases as $case) {
    $calc->alignment($case);
}
restore_error_handler();

// ── writePrivateKey(): 0600 и отсутствие окна на 0644 ────────────────────────
$tmp  = sys_get_temp_dir() . '/audit_key_' . bin2hex(random_bytes(6));
$bot->writePrivateKey($tmp, "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n");
clearstatcache();
auditAssert(file_exists($tmp), 'ключ должен быть записан');
auditAssert((fileperms($tmp) & 0777) === 0600, 'права на приватный ключ должны быть 0600, получено ' . decoct(fileperms($tmp) & 0777));
auditAssert(str_contains((string) file_get_contents($tmp), 'BEGIN PRIVATE KEY'), 'содержимое ключа должно сохраняться');

// Перезапись файла, созданного старой версией с 0644, должна сузить права.
file_put_contents($tmp, 'old');
chmod($tmp, 0644);
$bot->writePrivateKey($tmp, 'new');
clearstatcache();
auditAssert((fileperms($tmp) & 0777) === 0600, 'перезапись должна сужать права до 0600');
auditAssert(file_get_contents($tmp) === 'new', 'перезапись должна заменять содержимое');
unlink($tmp);

// ── setPacConf(): отказ кодировщика не должен обнулять pac.json ──────────────
// json_encode() возвращает FALSE на невалидном UTF-8 (имя клиента из импорта,
// байты из ssh-вывода), а file_put_contents($f, false) пишет ПУСТУЮ строку и
// рапортует об успехе — rename() подменял бы конфиг нулевым файлом, то есть
// уносил клиентов, ключи reality и все шаблоны разом.
$pacFile   = sys_get_temp_dir() . '/audit_pac_' . bin2hex(random_bytes(6)) . '.json';
$bot->pac  = $pacFile;
$good      = ['clients' => ['ok'], 'privateKey' => 'secret'];
// Сравниваем по записанным ключам: getPacConf() подмешивает PAC_DEFAULTS
// (шаблон pac.json — это «{}», и 26 чтений без ?? иначе дают Undefined array
// key, а implode(',', null) в addSubnets — фатал).
auditAssert(false !== $bot->setPacConf($good), 'валидный конфиг записывается');
auditAssert(array_intersect_key($bot->getPacConf(), $good) === $good, 'записанный конфиг читается обратно');
auditAssert(false === $bot->setPacConf(['name' => "\xB1\x31"]), 'битый UTF-8 не записывается');
clearstatcache();
auditAssert(array_intersect_key($bot->getPacConf(), $good) === $good,
    'после отказа pac.json остаётся прежним, а не пустым');
foreach (glob($pacFile . '*') ?: [] as $f) {
    @unlink($f);
}

// ── Bot без конструктора: getPacConf() не должен падать ─────────────────────
// Тесты и разовые диагностические скрипты строят Bot через
// newInstanceWithoutConstructor(). Пока путь к pac.json задавался ТОЛЬКО в
// конструкторе, первый же getPacConf() (а его зовёт почти каждый метод) падал
// с «ValueError: Path must not be empty» из file_get_contents — не warning,
// поэтому @ его не гасила. В логе рабочего сервера это встречалось трижды: `php -r` с
// xrayCore() и /tmp/gen_mihomo.php с addClashRuleSet().
$bare = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();
foreach ([
    'pac'      => '/config/pac.json',
    'clients'  => '/config/clients.json',
    'clients1' => '/config/clients1.json',
    'adguard'  => '/config/AdGuardHome.yaml',
    'update'   => '/update/json',
    'hwid'     => '/config/hwid.json',
] as $prop => $path) {
    auditAssert($bare->$prop === $path, "путь \$$prop известен и без конструктора");
}
try {
    $conf = $bare->getPacConf();
    auditAssert(is_array($conf), 'getPacConf() на голом инстансе отдаёт массив');
    auditAssert(array_key_exists('language', $conf), 'и он дополнен PAC_DEFAULTS');
} catch (Throwable $e) {
    auditAssert(false, 'getPacConf() на голом инстансе падает: ' . get_class($e) . ': ' . $e->getMessage());
}
// Подмена пути тестами обязана продолжать работать — на ней стоят соседние
// проверки в этом же файле и весь audit_doh_id_test (он подменяет adguard).
$bare->pac     = $pacFile;
$bare->adguard = $pacFile . '.yaml';
auditAssert($bare->pac === $pacFile && $bare->adguard === $pacFile . '.yaml',
    'пути по-прежнему переопределяются присваиванием');

// Конструктор больше не обязан присваивать эти пути — но обязан оставить их
// теми же, что и дефолты, иначе боевой инстанс и голый разъедутся.
// Тело конструктора вырезаем ДО следующего объявления метода, а не окном
// фиксированной длины: конструктор растёт, и присваивание, добавленное после
// его конца, окно бы не поймало.
$src   = (string) file_get_contents(__DIR__ . '/../app/bot.php');
$from  = strpos($src, 'public function __construct');
$to    = strpos($src, "\n    public function ", $from + 1);
$body  = substr($src, $from, $to - $from);
auditAssert(substr_count($body, 'public function ') === 1, 'тело конструктора вырезано целиком');
foreach (['pac', 'clients', 'clients1', 'adguard', 'update', 'hwid'] as $prop) {
    auditAssert(!preg_match('~\$this->' . $prop . '\s*=~', $body),
        "конструктор не переопределяет \$$prop — дефолт один, на свойстве");
}

echo "audit_fixes_test OK\n";
