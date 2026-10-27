<?php
// Генерация маршрутов: совместимость старых нод и строгий локальный IPv6.
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($n, $s, $f, $l) { if (error_reporting() & $n) throw new ErrorException($s, 0, $n, $f, $l); return true; });
class Ipv6ExitBot extends Bot
{
    public array $p = [];
    public array $x = [];
    public array $network = [];
    public array $saved = [];
    public array $sets = [];
    public function exitRulesetCache(string $key): array { return $this->sets[$key] ?? []; }
    public string $answerText = '';
    public function __construct() {}
    public function getPacConf() { return $this->p; }
    public function getXray() { return $this->x; }
    protected function exitIpv6Network(): array { return $this->network; }
    public function exitStatus(): array { return []; }
    protected function exitStatusWrite(string $id, array $status): void { $this->saved[$id] = $status; }
    public function ssh($cmd, $service = 'wg', $wait = true, $log = '/dev/null') { $this->sshFailed = false; return $this->answerText; }
}
$checks = 0;
$check = static function ($ok, $message) use (&$checks) { $checks++; if (!$ok) throw new RuntimeException($message); };
$bot = new Ipv6ExitBot();
$id = 'abcdef01';
$remote = 'abcdef02';
$base = ['inbounds' => [['tag' => 'vless', 'settings' => ['clients' => [
    ['email' => 'alice', 'exit' => [$id, $remote]],
    ['email' => 'node-relay', 'exit_relay' => 1, 'exit' => [$id, $remote]],
]]]], 'outbounds' => [['protocol' => 'freedom', 'tag' => 'direct'], ['protocol' => 'blackhole', 'tag' => 'block']],
'routing' => ['rules' => [['type' => 'field', 'ruleTag' => 'vpnbot:routes:block:domain', 'domain' => ['domain:blocked.test'], 'outboundTag' => 'block']]]];
$link = 'vless://' . '11111111-1111-4111-8111-111111111111' . '@node.example.org:443?security=reality&sni=www.example.com&fp=chrome&pbk=' . str_repeat('a', 43) . '&sid=abcd&type=tcp&encryption=none';
$old = ['exits' => [$remote => ['link' => $link, 'routes' => ['domain:example.org' => 1]]]];
$c = $base; $bot->ensureExitNodes($c, $old);
$check($c['routing']['balancers'][0]['fallbackTag'] === 'direct', 'Старая нода сохраняет direct');
$check($c['outbounds'][0] === $base['outbounds'][0], 'Без IPv6 обычный выход не меняется');
$strict = $old; $strict['exits'][$remote]['fallback'] = 'block';
$c = $base; $bot->ensureExitNodes($c, $strict);
$check($c['routing']['balancers'][0]['fallbackTag'] === 'block', 'Строгая удалённая нода не использует direct');
$p = ['exits' => [$id => ['kind' => 'ipv6', 'fallback' => 'direct', 'routes' => ['domain:example.org' => 1, '2001:4860::/32' => 1], 'quic' => 'pass']]];
$c = $base; $bot->ensureExitNodes($c, $p);
$bot->p = $p;
$check($bot->exitNodes()[$id]['fallback'] === 'block', 'Локальный IPv6 нельзя ослабить импортом fallback=direct');
$out = array_column($c['outbounds'], null, 'tag')['vpnbot-exit-' . $id];
$check($out['sendThrough'] === Bot::EXIT_IPV6_SOURCE, 'Привязка к адресу выделенного контейнера');
$check($out['settings']['domainStrategy'] === 'ForceIPv6', 'Строгий DNS для TCP и UDP');
$check($out['streamSettings']['sockopt']['domainStrategy'] === 'ForceIPv6', 'Стратегия сокетов согласована с freedom');
$check($out['settings']['finalRules'][0]['ip'][0] === '0.0.0.0/0', 'IPv4 literal запрещён на конечном выходе');
$check(end($out['settings']['finalRules'])['ip'] === ['::/0'], 'Всё кроме разрешённого GUA закрыто');
$check(!isset($c['routing']['balancers']), 'Локальный IPv6 без запасного балансировщика');
$check($c['outbounds'][0]['settings']['domainStrategy'] === 'ForceIPv4', 'Обычный доменный выход остаётся IPv4');
$rules = array_values(array_filter($c['routing']['rules'], static fn($r) => isset($r['user'])));
$check(count($rules) === 2 && $rules[0]['user'] === ['alice'], 'Локальный маршрут только выбранному обычному пользователю');
$check($rules[0]['outboundTag'] === 'vpnbot-exit-' . $id && $rules[1]['ip'] === ['2001:4860::/32'], 'Общий компилятор доменов и CIDR');
$check($c['routing']['rules'][1]['ruleTag'] === 'vpnbot:routes:block:domain', 'Блокировки выше пользовательского маршрута');
$same = $c; $bot->ensureExitNodes($c, $p);
$check($same === $c, 'Повторная генерация не дублирует правила');
$c = $base; $c['inbounds'][0]['settings']['clients'][1]['exit_ipv6'] = 1;
$bot->ensureExitNodes($c, $old);
$relayRules = array_values(array_filter($c['routing']['rules'], static fn($r) => ($r['ruleTag'] ?? '') === 'vpnbot:exit:relay-ipv6'));
$check(count($relayRules) === 1 && $relayRules[0]['user'] === ['node-relay'], 'Служебный профиль получает отдельный конечный IPv6');
$check($relayRules[0]['outboundTag'] === Bot::EXIT_IPV6_TAG, 'Профиль не пересылает трафик в другую ноду');
$check(Bot::exitClientNodes($c['inbounds'][0]['settings']['clients'][1]) === [], 'Защита от петель сохранена');
$c['inbounds'][0]['settings']['clients'][1]['off'] = 'off'; $bot->ensureExitNodes($c, $old);
$check(!array_filter($c['routing']['rules'], static fn($r) => ($r['ruleTag'] ?? '') === 'vpnbot:exit:relay-ipv6'), 'Отключённая служебная учётка не получает правила');
$c = $base; $disabled = $p; $disabled['exits'][$id]['enabled'] = 0; $bot->ensureExitNodes($c, $disabled);
$check($c === $base, 'Явное выключение локального выхода снимает только его правила');
$bot->answerText = "probe=204 0.1\nip=192.0.2.1\nloc=XX\n";
$s = $bot->exitProbe($id, false);
$check(!$s['ok'] && $s['error'] === 'ipv6', 'IPv4 в ответе проверки не считается рабочим IPv6');
$bot->answerText = "probe=204 0.1\nip=2001:4860::1\nloc=XX\n";
$check($bot->exitProbe($id, false)['ok'], 'Подтверждение фактического IPv6');
$bot->network = ['enabled' => true, 'public' => '2001:4860::2'];
$check(in_array('2001:4860::2/128', $bot->exitIpv6Outbound()['settings']['finalRules'][0]['ip'], true), 'Публичный IPv6 самого хоста закрыт для клиентов');
$c = $base; $c['inbounds'][0]['settings']['clients'][1]['exit_ipv6'] = 1;
$bot->ensureExitNodes($c, $old); $bot->ensureWgGuard($c);
$check($c['routing']['rules'][0]['ruleTag'] === 'vpnbot:ipv6:relay-guard', 'Строгий relay не обходит IPv6 через исключения DNS/WARP');
$same = $c; $bot->ensureWgGuard($c); $check($c === $same, 'Relay guard идемпотентен');
$c['inbounds'] = []; $bot->ensureWgGuard($c);
$check(!array_filter($c['routing']['rules'], static fn($r) => ($r['ruleTag'] ?? '') === 'vpnbot:ipv6:relay-guard'), 'Без входов устаревший relay guard удаляется');
$bot->answerText = "probe=204 0.1\nip=2001:4860::1\nloc=XX\n";
$check($bot->exitProbe($id, false)['error'] === 'ipv6 source', 'Проверка обнаруживает ошибочный исходящий IPv6');
$bot->sets = ['https://sets.example/youtube.srs' => ['entries' => ['domain:srs.example']],
    'https://sets.example/networks.mrs' => ['entries' => ['2001:4860:1::/48']]];
$withSets = $p;
$withSets['exits'][$id]['rulesets'] = ['https://sets.example/youtube.srs' => ['on' => 1], 'https://sets.example/networks.mrs' => ['on' => 1]];
$c = $base; $bot->ensureExitNodes($c, $withSets);
$selected = array_values(array_filter($c['routing']['rules'], static fn($r) => ($r['user'] ?? []) === ['alice']));
$check(in_array('domain:srs.example', $selected[0]['domain'], true) && in_array('2001:4860:1::/48', $selected[1]['ip'], true), 'SRS и MRS выбирают тот же строгий IPv6-выход');
$check($selected[0]['outboundTag'] === 'vpnbot-exit-' . $id && $selected[1]['outboundTag'] === 'vpnbot-exit-' . $id, 'Наборы не создают запасного прямого маршрута');
// Потеря обязательных данных строгого маршрута не должна превращаться в direct.
$bot->sets = [];
$c = $base; $bot->ensureExitNodes($c, $withSets); $bot->ensureWgGuard($c);
$check(($c['routing']['rules'][0]['ruleTag'] ?? '') === 'vpnbot:exit:unavailable:' . $id
    && $c['routing']['rules'][0]['user'] === ['alice'] && $c['routing']['rules'][0]['outboundTag'] === 'block',
    'Нет SRS/MRS-кэша: пользователи строгого узла закрыты до WARP/DNS исключений');
$same = $c; $bot->ensureExitNodes($c, $withSets); $bot->ensureWgGuard($c);
$check($same === $c, 'Повторная сборка аварийного запрета идемпотентна');
$bot->sets = ['https://sets.example/youtube.srs' => ['entries' => ['domain:srs.example']],
    'https://sets.example/networks.mrs' => ['entries' => ['2001:4860:1::/48']]];
$bot->ensureExitNodes($c, $withSets); $bot->ensureWgGuard($c);
$check(!array_filter($c['routing']['rules'], static fn($r) => str_starts_with($r['ruleTag'] ?? '', 'vpnbot:exit:unavailable:')),
    'После восстановления кэша аварийный запрет снимается');
$missingDat = $p; $missingDat['exits'][$id]['routes']['ext:missing-ipv6-test.dat:youtube'] = 1;
$c = $base; $bot->ensureExitNodes($c, $missingDat); $bot->ensureWgGuard($c);
$check(($c['routing']['rules'][0]['ruleTag'] ?? '') === 'vpnbot:exit:unavailable:' . $id, 'Нет .dat: строгий маршрут закрыт');
$broken = $strict; $broken['exits'][$remote]['link'] = 'invalid';
$c = $base; $bot->ensureExitNodes($c, $broken);
$blocked = array_column($c['outbounds'], null, 'tag')['vpnbot-exit-' . $remote] ?? [];
$check(($blocked['protocol'] ?? '') === 'blackhole' && !isset($c['routing']['balancers']), 'Повреждённая строгая нода блокирует выбранные назначения');
$legacyMissing = $old; $legacyMissing['exits'][$remote]['rulesets'] = ['https://sets.example/missing.srs' => ['on' => 1]];
$c = $base; $bot->ensureExitNodes($c, $legacyMissing);
$check(!array_filter($c['routing']['rules'], static fn($r) => str_starts_with($r['ruleTag'] ?? '', 'vpnbot:exit:unavailable:')), 'Обычная нода сохраняет прежнюю обработку отсутствующих наборов');
$c = $base;
$c['outbounds'][0]['settings']['finalRules'] = [['action' => 'allow', 'ip' => ['2000::/3']], ['action' => 'block', 'ip' => ['::/0'], 'blockDelay' => 0]];
$bot->ensureExitNodes($c, $p);
$check($c['outbounds'][0]['settings']['finalRules'][0]['action'] === 'block', 'После импорта запрет обычного IPv6 возвращается перед allow');
foreach (['typo', null, 1, []] as $invalidFallback) {
    $bad = $old; $bad['exits'][$remote]['fallback'] = $invalidFallback;
    $check($bot->exitNodes($bad)[$remote]['fallback'] === 'block', 'Неизвестный fallback не разрешает direct');
}
$bad = $old; $bad['exits'][$remote]['kind'] = 'unknown';
$c = $base; $bot->ensureExitNodes($c, $bad);
$check(array_column($c['outbounds'], null, 'tag')['vpnbot-exit-' . $remote]['protocol'] === 'blackhole', 'Неизвестный тип выхода закрывает выбранное');
echo "exit_ipv6_test: $checks OK\n";
