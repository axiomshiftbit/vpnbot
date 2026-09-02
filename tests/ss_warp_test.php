<?php

// «ss через warp» — тумблер, который отдаёт ИСХОДЯЩИЕ TCP-соединения ssserver
// в SOCKS5 WARP'а (ключ outbound_proxy, shadowsocks-rust 1.25.0, PR #2106).
//
// Что здесь сторожится — ровно то, что ломается молча:
//   1. URL без порта ядро отвергает на СТАРТЕ (OutboundProxy::from_url), то
//      есть ssserver просто не поднимется и SS умрёт целиком;
//   2. microsocks в wp закрыт iptables-ACL, где последним правилом стоит DROP.
//      ACCEPT, добавленный через -A, попал бы ПОСЛЕ него и не работал бы вовсе;
//      вставка обязана быть идемпотентной, иначе каждый клик плодит дубли;
//   3. состояние тумблера обязано жить в ssserver.json (как plugin у v2ray и
//      Enabled у cloak): второй источник в pac.json разъедется с конфигом,
//      который читает демон, и меню начнёт врать;
//   4. пин ss-rust в .env не должен уехать ниже 1.25.0 — в 1.24.0 ключа
//      outbound_proxy нет вовсе, и ssserver отвергнет конфиг;
//   5. start_wp.sh обязан ставить то же правило на старте контейнера, иначе
//      тумблер переживёт пересоздание wp только до первого рестарта.

require_once __DIR__ . '/../app/bot.php';

$failed = 0;

function swAssert(bool $cond, string $msg): void
{
    global $failed;
    if (!$cond) {
        $failed++;
        echo "FAIL: $msg\n";
    }
}

$bot = (new ReflectionClass(Bot::class))->newInstanceWithoutConstructor();

// ── 1. URL цепочки ──────────────────────────────────────────────────────────
$url = $bot->ssWarpUrl();
// Литерал сверяем только там, где ssWarpUrl() обязан вернуть константу:
// внутри php-контейнера /docker/compose — это docker-compose.override.yml, и
// на хосте с переназначенным адресом wp верный URL был бы другим. Форму
// (схема, явный порт, отсутствие маски) проверяем всегда — она от адреса не
// зависит, а ломается как раз она.
if (!is_file('/docker/compose')) {
    swAssert($url === 'socks5://10.10.0.13:1080', "URL цепочки: $url");
}
swAssert((bool) preg_match('~^socks5://[0-9.]+:\d+$~', $url), 'схема socks5 и ЯВНЫЙ порт (без порта ядро не стартует)');
swAssert(!str_contains($url, '/32'), 'маска из WARP_SOCKS_IP в URL не просачивается');
// microsocks умеет только CONNECT, поэтому http/https-хопы тут недопустимы:
// у ss-rust цепочка с http-хопом ещё и отключает UDP через неё.
swAssert(str_starts_with($url, 'socks5://'), 'только socks5: microsocks знает лишь CONNECT');

// ── 2. Правило ACL ──────────────────────────────────────────────────────────
$on  = Bot::warpSocksAllowCmd('10.10.0.6', true);
$off = Bot::warpSocksAllowCmd('10.10.0.6', false);

swAssert(str_contains($on, 'iptables -C WARP_SOCKS -s 10.10.0.6 -j ACCEPT'), 'включение проверяет наличие правила (-C)');
swAssert(str_contains($on, '|| iptables -I WARP_SOCKS'), 'включение вставляет через -I: -A попал бы после финального DROP');
swAssert(!preg_match('~iptables -A WARP_SOCKS~', $on), 'в команде включения нет -A');
swAssert(str_contains($off, 'iptables -D WARP_SOCKS -s 10.10.0.6 -j ACCEPT'), 'выключение удаляет правило');
swAssert(str_contains($off, 'while iptables -C'), 'выключение чистит ВСЕ дубли, а не одно правило');
// Идемпотентность включения: -C гейтит -I, значит повторный клик не плодит копий.
swAssert(substr_count($on, 'iptables -I') === 1, 'включение вставляет ровно одно правило');

// ── 3. Состояние читается из ssserver.json ─────────────────────────────────
swAssert(Bot::ssWarpOn(['outbound_proxy' => 'socks5://10.10.0.13:1080']), 'ключ есть — тумблер ON');
swAssert(!Bot::ssWarpOn(['method' => 'chacha20-ietf-poly1305']), 'ключа нет — тумблер OFF');
swAssert(!Bot::ssWarpOn(['outbound_proxy' => '']), 'пустой ключ — тумблер OFF (иначе меню врёт, а ядро игнорирует)');
swAssert(!Bot::ssWarpOn(null), 'битый ssserver.json не роняет меню');
swAssert(Bot::SS_WARP_KEY === 'outbound_proxy', 'имя ключа = имя из конфига ss-rust');

// Дублирующего флага в pac.json быть не должно: единственный источник истины —
// ssserver.json. Регрессия ловится по исходнику, а не по поведению.
$src = (string) file_get_contents(__DIR__ . '/../app/bot.php');
swAssert(!preg_match("~\\\$p\\['ss_warp'\\]|'ss_warp'~", $src), 'второго состояния в pac.json нет');

// ── 4. Пин ядра не ниже 1.25.0 ─────────────────────────────────────────────
$env = (string) @file_get_contents(__DIR__ . '/../.env');
if (preg_match('~^SS_RUST_VERSION=v?(\d+)\.(\d+)\.(\d+)~m', $env, $m)) {
    $ver = sprintf('%04d%04d%04d', $m[1], $m[2], $m[3]);
    swAssert($ver >= sprintf('%04d%04d%04d', 1, 25, 0),
        "SS_RUST_VERSION={$m[0]}: outbound_proxy появился в v1.25.0");
} else {
    swAssert(false, 'SS_RUST_VERSION в .env не найден');
}

// ── 5. start_wp.sh ставит то же правило на старте ──────────────────────────
$wp = (string) file_get_contents(__DIR__ . '/../scripts/start_wp.sh');
swAssert(str_contains($wp, "jq -r '.outbound_proxy // empty' /config/ssserver.json"),
    'start_wp.sh читает состояние из ssserver.json, а не из отдельного флага');
swAssert((bool) preg_match('~SS_IPS=\$\(getent hosts ss ~', $wp),
    'адрес ss резолвится через docker-DNS');
swAssert((bool) preg_match('~SOCKS_ALLOW="\$SOCKS_ALLOW ~', $wp),
    'адрес ss ДОБАВЛЯЕТСЯ к списку, а не заменяет xray (иначе отвалится warp у xray)');
// Резолв обязан идти ДО подмены resolv.conf — иначе имена контейнеров уже не
// резолвятся и в ACL уедет фолбэк.
$posSs     = strpos($wp, 'getent hosts ss ');
$posResolv = strpos($wp, "> /etc/resolv.conf");
swAssert($posSs !== false && $posResolv !== false && $posSs < $posResolv,
    'ss резолвится ДО строки, которая переписывает /etc/resolv.conf');

// ── 6. Роут и кнопка на месте ──────────────────────────────────────────────
swAssert(str_contains($src, "preg_match('~^/ssWarp$~'"), 'роут /ssWarp зарегистрирован');
swAssert(str_contains($src, "'callback_data' => \"/ssWarp\""), 'кнопка в меню SS ведёт на роут');
// Тело тумблера — до следующего объявления метода: иначе проверки ниже ловят
// соседние функции (там pkill sslocal встречается штатно).
preg_match('~public function ssWarp\(\).*?\n    public function ~s', $src, $bm);
$body = $bm[0] ?? '';
swAssert($body !== '', 'тело ssWarp() найдено');
// Перезапускать надо только ssserver: sslocal живёт в другом контейнере и
// цепочки не касается.
swAssert(str_contains($body, "pkill ssserver"), 'тумблер перезапускает ssserver');
swAssert(str_contains($body, "ssserver -v -d -c /config.json"), 'и поднимает его обратно');
// Именно вызовы, а не слово: в комментарии тела sslocal упомянут по делу.
swAssert(!preg_match('~ssh\(\s*.[^\n]*sslocal~', $body), 'sslocal тумблер не перезапускает');
// Порядок в ветке включения: сначала ACL, потом конфиг и рестарт — иначе
// ssserver стартует раньше, чем ему разрешат ходить в прокси.
swAssert(strpos($body, 'warpSocksAllowSS(true)') < strpos($body, 'file_put_contents'),
    'ACL ставится до перезаписи конфига');
// Включение только после успешной пробы: отката на direct у ядра нет.
swAssert(strpos($body, 'warpStatus()') < strpos($body, 'warpSocksAllowSS(true)'),
    'перед включением проверяется живость WARP');
// ...но и пробы мало: она ходит бот→xr→wp:1080, а iptables — бот→wp:22.
// Провалившийся ssh обязан отменить включение ДО записи конфига, иначе
// конфиг с outbound_proxy уедет к ssserver без ACCEPT в WARP_SOCKS.
$posAllow  = strpos($body, 'warpSocksAllowSS(true)');
$posFailed = strpos($body, '$this->sshFailed');
$posWrite  = strpos($body, 'file_put_contents');
swAssert($posFailed !== false && $posAllow < $posFailed && $posFailed < $posWrite,
    'после установки ACL проверяется sshFailed — до записи конфига');
swAssert(str_contains($body, "i18n('ss warp acl failed')"), 'и админ видит, почему тумблер не включился');

// ── 7. Цепочка из нескольких хопов не ломает рендер меню ───────────────────
// Ядро принимает и Chain(Vec<String>) — такой конфиг приезжает импортом или
// ручной правкой. Голое (string) дало бы «egress (TCP): Array» и «Array to
// string conversion» в логе на каждом рендере меню SS.
preg_match('~public function menuSS\(\).*?\n    public function ~s', $src, $mm);
$menu = $mm[0] ?? '';
swAssert($menu !== '', 'тело menuSS() найдено');
swAssert((bool) preg_match('~is_array\(\$chain\)\s*\?\s*implode~', $menu),
    'форма-цепочка склеивается, а не приводится к строке');
swAssert(!preg_match('~\(string\)\s*\(\$ss\[self::SS_WARP_KEY\]~', $menu),
    'голого (string) на значении outbound_proxy в меню нет');

// ── 8. Импорт настроек примиряет ACL с приехавшим конфигом ─────────────────
// Бэкап несёт ssserver.json целиком, вместе с ключом outbound_proxy, а правило
// в WARP_SOCKS с ним не едет. Без примирения бэкап С ключом на хосте БЕЗ
// правила молча роняет весь TCP клиентов ss, а бэкап БЕЗ ключа оставляет
// лишний ACCEPT висеть до пересоздания wp.
preg_match('~\n\s+// ss\n.*?\n\s+// sl\n~s', $src, $im);
$imp = $im[0] ?? '';
swAssert($imp !== '', 'ветка ss в импорте настроек найдена');
swAssert(str_contains($imp, 'warpSocksAllowSS(self::ssWarpOn('),
    'импорт выставляет ACL по приехавшему ssserver.json');
swAssert(strpos($imp, 'warpSocksAllowSS') < strpos($imp, 'ssserver -v -d -c /config.json'),
    'и делает это ДО старта ssserver — как в самом тумблере');

if ($failed) {
    echo "ss_warp_test: провалено проверок — $failed\n";
    exit(1);
}
echo "ss_warp_test OK\n";
