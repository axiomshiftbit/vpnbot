<?php
require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/../app/i18n.php';
class Ipv6TransportBot extends Bot {
    public array $network = [], $p = ['transport'=>'Reality'], $x = [], $screen=[];
    public function __construct($i) { $this->i18n=$i; $this->language='ru'; $this->admin=true; $this->input=['chat'=>1,'message_id'=>1]; }
    protected function exitIpv6Network(): array { return $this->network; }
    public function applyExitNodes(callable $fn): string { return $fn($this->p,$this->x); }
    public function exitRelayLink(int $i, string $notice = ''): void { $this->screen=[$i,$notice]; }
}
$b=new Ipv6TransportBot($i); $n=0;
$check=static function($ok,$message) use (&$n) { $n++; if (!$ok) throw new RuntimeException($message); };
$client=['id'=>'11111111-1111-4111-8111-111111111111','email'=>'node-fixture','exit_relay'=>1,'exit_transport_ipv6'=>1];
$link='vless://11111111-1111-4111-8111-111111111111@node.example.org:443?security=reality&sni=cover.example.org&pbk='.str_repeat('B',43).'&sid=ab&type=tcp#Node';
$b->network=['enabled'=>true,'public'=>'2001:4860::2'];
$v6=$b->exitRelayEndpoint($link,$client,$b->p);
$check(str_contains($v6,'@[2001:4860::2]:443?'),'Буквальный IPv6 вместо имени');
$check(explode('?',$v6,2)[1]===explode('?',$link,2)[1],'SNI и все параметры Reality сохранены');
$parsed=ExitNodeLink::parse($v6);
$check(($parsed['address']??'')==='2001:4860::2','IPv6 ссылка принимается основным ботом');
foreach ([[],['enabled'=>true,'public'=>'::1'],['enabled'=>true,'public'=>'fd42::1'],['enabled'=>true,'public'=>'bad']] as $network) {
    $b->network=$network; $check($b->exitRelayEndpoint($link,$client,$b->p)==='','Нет IPv6 — нет незаметного возврата на IPv4');
}
$b->network=['enabled'=>true,'public'=>'2001:4860::2'];
foreach (['ws','xhttp','trojan-grpc'] as $transport) $check($b->exitRelayEndpoint($link,$client,['transport'=>$transport])==='','Неподдерживаемый транспорт закрывается');
$check($b->exitRelayEndpoint($link,[...$client,'exit_transport_ipv6'=>0],$b->p)===$link,'Обычный режим сохраняет прежнюю ссылку');
$check($b->exitRelayEndpoint($link,[...$client,'exit_relay'=>0],$b->p)===$link,'Обычные пользователи не меняются');
$check($b->exitRelayEndpoint('invalid',$client,$b->p)==='','Неправильная ссылка не выдаётся');
$b->x=['inbounds'=>[['settings'=>['clients'=>[ [...$client,'exit_ipv6'=>0,'exit_transport_ipv6'=>0] ]]]]];
$mark=Bot::exitRelayMark($client);
$b->exitRelayTransport(0,true,$mark);
$check($b->x['inbounds'][0]['settings']['clients'][0]['exit_transport_ipv6']===1,'IPv6 транспорт включается');
$check($b->x['inbounds'][0]['settings']['clients'][0]['exit_ipv6']===0,'Транспорт не меняет выход к сайтам');
$b->exitRelayTransport(0,true,$mark); $check($b->x['inbounds'][0]['settings']['clients'][0]['exit_transport_ipv6']===1,'Повторное нажатие идемпотентно');
$b->exitRelayTransport(0,false,str_repeat('f',16)); $check($b->x['inbounds'][0]['settings']['clients'][0]['exit_transport_ipv6']===1,'Старая кнопка чужого профиля не меняет настройки');
$b->exitRelayTransport(0,false,$mark); $check($b->x['inbounds'][0]['settings']['clients'][0]['exit_transport_ipv6']===0,'Прежний транспорт можно вернуть');
$b->p['transport']='ws'; $b->exitRelayTransport(0,true,$mark);
$check($b->x['inbounds'][0]['settings']['clients'][0]['exit_transport_ipv6']===0 && $b->screen[1]!=='','Включение без Reality объясняет отказ');
echo "exit_ipv6_transport_test: $n OK\n";
