<?php

// Limit IP Xray (frequencyAnalyze): различные адреса клиента за окно.
//
// Аудит 2026-10-31 на журнале тестового сервера: прежний счёт обнулялся после каждого
// уведомления — два постоянно активных адреса давали 446 уведомлений на 3000
// строк; IPv6 не учитывался; служебный «Профиль для узла» (к нему ходит
// другой сервер) поднимал тревогу. Здесь: одно уведомление на пользователя за
// окно, IPv4 и IPv6, служебные и выключенные учётки — без уведомлений.

require_once __DIR__ . '/../app/bot.php';

set_error_handler(static function ($level, $message, $file, $line) {
    if (error_reporting() & $level) throw new ErrorException($message, 0, $level, $file, $line);
    return false;
});

$checks = 0;
function ipCheck(bool $ok, string $label): void
{
    global $checks;
    if (!$ok) throw new RuntimeException($label);
    $checks++;
}

class IpLimitBot extends Bot
{
    public array $alerts = [];
    public array $xr;
    public function __construct()
    {
        $this->xr = ['inbounds' => [['settings' => ['clients' => [
            ['email' => 'alice', 'id' => 'a'],
            ['email' => 'node-example', 'id' => 'b', 'exit_relay' => 1],
            ['email' => 'carol', 'id' => 'c', 'off' => true],
            ['email' => 'Дима <b>', 'id' => 'd'],
        ]]]]];
    }
    public function getXray() { return $this->xr; }
    protected function ipLimitAlert(string $text, int $client): void { $this->alerts[] = [$text, $client]; }
    public function feed(array $ips, string $email = 'alice', array $pac = ['ip_limit' => 300, 'ip_count' => 1]): int
    {
        $before = count($this->alerts);
        foreach ($ips as $ip) {
            $host = str_contains($ip, ':') ? "[$ip]" : $ip;
            $this->frequencyAnalyze(date('Y/m/d H:i:s') . ".123456 from $host:40000 accepted tcp:example.com:443 [vless_tls >> direct] email: $email\n", $pac);
        }
        return count($this->alerts) - $before;
    }
}

$alternate = array_merge(...array_fill(0, 15, ['198.51.100.1', '198.51.100.2']));

// ── 1. Одно уведомление на окно вместо потока ───────────────────────────────
$b = new IpLimitBot();
ipCheck($b->feed($alternate) === 1, 'два чередующихся адреса — одно уведомление за окно');
ipCheck($b->alerts[0] === ['vless: alice limit ip 2 > 1', 0], 'текст и номер клиента для кнопки');
ipCheck($b->feed($alternate) === 0, 'повторно в том же окне — без уведомлений');
// Окно истекло: время уведомления и адресов отодвинуто назад.
$b->pool['alice']['alerted'] -= 301;
foreach ($b->pool['alice']['ips'] as $ip => $t) $b->pool['alice']['ips'][$ip] = $t - 301;
ipCheck($b->feed(['198.51.100.1']) === 0, 'после окна старые адреса забыты: один адрес — не превышение');
ipCheck($b->feed(['198.51.100.2']) === 1, 'после окна новое превышение — новое уведомление');

// ── 2. Подсчёт различных адресов ───────────────────────────────────────────
$b = new IpLimitBot();
ipCheck($b->feed(array_fill(0, 50, '198.51.100.1')) === 0, 'один адрес — никогда');
ipCheck($b->feed(['198.51.100.2']) === 1, 'смена сети в пределах окна при лимите 1 — два адреса, уведомление');
$b = new IpLimitBot();
$pac2 = ['ip_limit' => 300, 'ip_count' => 2];
ipCheck($b->feed(['198.51.100.1', '198.51.100.2', '198.51.100.1', '198.51.100.2'], 'alice', $pac2) === 0, 'лимит 2: два адреса допустимы');
ipCheck($b->feed(['198.51.100.3'], 'alice', $pac2) === 1 && $b->alerts[0][0] === 'vless: alice limit ip 3 > 2', 'лимит 2: третий адрес — уведомление');
$b = new IpLimitBot();
ipCheck($b->feed(['198.51.100.1', '198.51.100.2'], 'alice', ['ip_limit' => 300, 'ip_count' => 0]) === 1, 'пустое количество — как 1');

// ── 3. IPv6 и запись адреса ─────────────────────────────────────────────────
$b = new IpLimitBot();
ipCheck($b->feed(array_merge(...array_fill(0, 5, ['2001:db8::1', '2001:db8::2']))) === 1, 'IPv6 учитывается');
$b = new IpLimitBot();
ipCheck($b->feed(['2001:db8:0:0::1', '2001:db8::1', '2001:0db8::0001']) === 0 && count($b->pool['alice']['ips']) === 1, 'разные записи одного IPv6 — один адрес');
$b = new IpLimitBot();
$b->frequencyAnalyze("2026/10/31 13:15:25.326665 from tcp:198.51.100.1:42352 accepted tcp:www.gstatic.com:443 [vless_tls >> direct] email: alice\n", ['ip_limit' => 300, 'ip_count' => 1]);
$b->frequencyAnalyze("2026/10/31 13:15:25.326665 from 198.51.100.2:42352 accepted udp:1.1.1.1:53 [vless_tls -> direct] email: alice\n", ['ip_limit' => 300, 'ip_count' => 1]);
ipCheck(count($b->alerts) === 1, 'форматы строки журнала с префиксом tcp: и без него');
foreach (['garbage', "from 999.1.1.1:5 accepted x email: alice\n", "from 198.51.100.9:5 accepted x\n", "from 198.51.100.9:5 accepted x email: \n"] as $junk) {
    $b->frequencyAnalyze($junk, ['ip_limit' => 300, 'ip_count' => 1]);
}
ipCheck(count($b->alerts) === 1 && count($b->pool) === 1, 'мусорные строки не учитываются');

// ── 4. Кому уведомление не нужно ───────────────────────────────────────────
$b = new IpLimitBot();
ipCheck($b->feed($alternate, 'node-example') === 0, 'служебный «Профиль для узла» — без уведомлений');
ipCheck($b->feed($alternate, 'carol') === 0, 'выключенный пользователь — без уведомлений');
ipCheck($b->feed($alternate, 'ghost') === 0, 'неизвестный email — без уведомлений');
ipCheck($b->feed($alternate, 'Дима <b>') === 1 && $b->alerts[0][0] === 'vless: Дима &lt;b&gt; limit ip 2 > 1' && $b->alerts[0][1] === 3, 'имя экранируется для HTML');

echo "iplimit_test OK ($checks проверок)\n";
