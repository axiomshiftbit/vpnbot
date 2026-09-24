<?php
require_once __DIR__ . '/../app/bot.php';
set_error_handler(static function ($level,$message,$file,$line) { if(error_reporting() & $level) throw new ErrorException($message,0,$level,$file,$line);return true; });
class HyMenuBot extends Bot {
    public array $conf = ['domain'=>'vpn.example','hysteria_pass'=>'legacy<&', 'language'=>'en','limitpage'=>5];
    public array $messages=[]; public array $buttons=[]; public array $commands=[]; public array $prompt=[];
    public bool $writeFail=false; public bool $managed=true; public bool $module=true;
    public function __construct(string $root) {
        $this->hysteriaUsersRoot="$root/hysteria"; $this->hysteriaConf="$root/hysteria.yaml"; $this->update="$root/backup.json";
        $this->ip='2001:db8::10'; $this->admin=true; $this->input=['chat'=>1,'message_id'=>1,'callback_id'=>'test'];
    }
    public function getPacConf() { return $this->conf; }
    public function setPacConf(array $conf) { $this->conf=$conf;return true; }
    public function getPorts() { return ['hy'=>['enable'=>true,'port'=>443]]; }
    public function getDomain($cdn=false) { return $this->conf['domain'] ?? ''; }
    public function protocolModuleEnabled(string $key): bool { return $this->module; }
    public function flagName(string $name,string|array $hosts,bool $cacheOnly=true): string { return $name; }
    public function i18n(string $menu): string { return $menu; }
    public function withLock(string $name,callable $fn,int $timeout=0,$busy=null) { return $fn(); }
    public function ssh($cmd,$service='wg',$wait=true,$log='/dev/null') { $this->commands[]=$cmd;return $this->managed && str_contains($cmd,'printf managed') ? 'managed' : ''; }
    public function writePrivateKey(string $path,string $data): bool { return !$this->writeFail && parent::writePrivateKey($path,$data); }
    public function update($chat,$message_id,$text,$button=false,$reply=false,$mode='HTML') { $this->messages[]=$text;$this->buttons=is_array($button) ? $button : []; }
    public function send($chat,$text,?int $to=0,$button=false,$reply=false,$mode='HTML',$disable_notification=false) { $this->messages[]=$text;return ['result'=>['message_id'=>2]]; }
    public function stashReply($r,array $state) { $this->prompt=$state; }
    public function protocolError(string $message,string $back,string $retry=''): void { $this->messages[]=$message; }
    public function cloakNginx() {}
}
$root=sys_get_temp_dir().'/vpnbot-hy-menu-'.bin2hex(random_bytes(6));mkdir($root,0700);
$failures=[];$check=static function($ok,$name) use (&$failures) {if(!$ok)$failures[]=$name;};
$remove=static function($path) use (&$remove) {if(is_dir($path)){foreach(scandir($path) as $f)if($f!=='.'&&$f!=='..')$remove("$path/$f");rmdir($path);}else unlink($path);};
try {
    $b=new HyMenuBot($root);$store=$b->hysteriaUsersStore();
    $b->hyUserReply('before-upgrade','','name');$check(!$store->read()['users'],'Старый образ не выдаёт неконтролируемые персональные доступы');
    mkdir("$root/hysteria/runtime",0700,true);
    ManagedProtocol::writeJson("$root/hysteria/runtime/status.json",['schema'=>1,'time'=>time(),'running'=>true,'error'=>'']);
    ManagedProtocol::writeJson("$root/hysteria/runtime/usage.json",['users'=>[]]);
    $b->hyUserReply('Алиса <&>','','name');$id=(string)array_key_first($store->read()['users']);
    $check($id!=='' && str_contains(end($b->messages),'Алиса &lt;&amp;&gt;'),'Создание через reply и HTML-экранирование имени');
    $link=$b->hyPersonalLink($id);$check(rawurldecode(parse_url($link,PHP_URL_USER))===$id.':'.$store->read()['users'][$id]['password'],'URI сохраняет персональные реквизиты');
    foreach($b->buttons as $row)foreach($row as $button)$check(strlen($button['callback_data'])<=64,'Callback укладывается в Telegram');
    $b->hyUserCommand($id,'quota');$check($b->prompt['callback']==='hyUserReply' && $b->prompt['args']===[$id,'quota'],'Ответ на prompt сохраняет пользователя и поле');
    foreach(['-1','1e6','1000001','NaN'] as $bad){$before=$store->read();$b->hyUserReply($bad,$id,'quota');$check($store->read()===$before,'Неверная квота не меняет состояние');}
    $b->hyUserReply('0,5',$id,'quota');$check($store->read()['users'][$id]['quota']===536870912,'Дробная квота в GiB');
    $check($b->hyPersonalLink($id)==='','Ссылка с квотой ждёт появления счётчиков');
    $user=$store->read()['users'][$id];$usage=['users'=>[$id=>['reset'=>$user['reset'],'upload'=>1024,'download'=>2048]]];
    ManagedProtocol::writeJson("$root/hysteria/runtime/usage.json",$usage);$check($b->hyPersonalLink($id)!=='','Счётчики разрешают выдачу');
    $before=$store->read();$b->hyUserReply('2027-02-30 12:00',$id,'expires');$check($store->read()===$before,'Несуществующая дата отклонена');
    $b->hyUserReply('2000-01-01 00:00',$id,'expires');$check($b->hyPersonalLink($id)==='','Истёкший срок запрещает экспорт');
    $b->hyUserReply('0',$id,'expires');$b->hyUserCommand($id,'toggle');$check($b->hyPersonalLink($id)==='','Отозванный доступ не экспортируется');
    $b->hyUserCommand($id,'toggle');$old=$store->read()['users'][$id]['password'];$b->hyUserCommand($id,'rotate');$check($store->read()['users'][$id]['password']!==$old,'Меню меняет реквизиты');
    $b->module=false;$check($b->hyPersonalLink($id)==='','Выключенный модуль не выдаёт ссылки');$b->module=true;
    $b->conf['domain']='';$link=$b->linkHysteria();$check(str_contains($link,'@[2001:db8::10]:443/'),'IPv6 Hysteria заключён в скобки');
    $b->conf['domain']='vpn.example';$b->conf['hysteria_hop']='20000-20100';
    $link=$b->linkHysteria(['hy_address'=>'2001:db8::20','hy_port'=>'9443']);
    $check(str_contains($link,'@[2001:db8::20]:9443/') && str_contains($link,'sni=vpn.example'),'IPv6 relay меняет endpoint, сохраняя SNI и схлопывая hopping');
    file_put_contents($b->hysteriaConf,"auth:\n  type: password\n  password: legacy\n");
    $b->writeFail=true;$b->commands=[];$check(!$b->restartHysteria() && !$b->commands,'Ошибка записи не останавливает ядро');$b->writeFail=false;
    file_put_contents($b->hysteriaConf,'not: [valid');$check(!$b->restartHysteria() && !$b->commands,'Повреждённый YAML сохраняет работающее ядро');
    file_put_contents($b->hysteriaConf,"auth:\n  type: password\n  password: legacy\n");$b->restartHysteria();
    $check(count($b->commands)===1 && !str_contains($b->commands[0],'pkill'),'Новым ядром управляет supervisor');
    $snapshot=$store->snapshot();$store->edit($id,'delete');file_put_contents($b->update,json_encode(['hy_users'=>$snapshot]));
    $check($b->importFile($b->update)===true && isset($store->read()['users'][$id]),'Штатный importFile восстанавливает персональные доступы');
    $before=$store->read();$broken=$snapshot;$broken['usage']['users'][$id]['download']=-1;
    file_put_contents($b->update,json_encode(['hy_users'=>$broken,'pac'=>['domain'=>'should-not-change']]));
    $check($b->importFile($b->update)===false && $store->read()===$before && $b->conf['domain']==='vpn.example','Повреждённый снимок отвергается до любых изменений');
    $b->admin=false;$b->hyUserCommand($id,'delete-confirm');$b->hyUserReply('intruder',$id,'name');$check($store->read()===$before,'Неадминистратор не меняет доступы');
} finally {$remove($root);}
foreach($failures as $failure)echo "FAIL: $failure\n";
if($failures)exit(1);
echo "hysteria_menu_test OK\n";
