<?php
require_once __DIR__ . '/../app/bot.php';
require_once __DIR__ . '/../app/i18n.php';
ini_set('session.use_cookies', '0');
$root = sys_get_temp_dir() . '/vpnbot-navigation-' . bin2hex(random_bytes(6));
mkdir($root, 0700); session_save_path($root);
set_error_handler(static function ($n,$s,$f,$l) { if (error_reporting() & $n) throw new ErrorException($s,0,$n,$f,$l); return true; });
class NavigationTransport {
    public array $messages = [], $calls = [];
    public int $next = 100;
    public ?array $error = null;
    public array $clearedByUser = [];
    public function call($method, $data, $json = 0) {
        $this->calls[] = [$method,$data];
        $chat = (string) ($data['chat_id'] ?? 1);
        $id = $data['message_id'] ?? ++$this->next;
        // После очистки истории у пользователя Telegram продолжает подтверждать
        // правку: сообщение есть на стороне бота, но человек его не видит.
        if (in_array($id, $this->clearedByUser[$chat] ?? [], true)) {
            if ($method === 'deleteMessage') return ['ok'=>false,'error_code'=>400,'description'=>'Bad Request: message to delete not found'];
            if ($method === 'editMessageText') return ['ok'=>true,'result'=>['message_id'=>$id]];
        }
        if ($method === 'editMessageText') {
            if ($this->error) return $this->error;
            if (!isset($this->messages[$chat][$id])) return ['ok'=>false,'error_code'=>400,'description'=>'Bad Request: message to edit not found'];
        }
        if ($method === 'deleteMessage') unset($this->messages[$chat][$id]);
        elseif (in_array($method,['editMessageText','sendMessage','sendPhoto','sendDocument'],true)) $this->messages[$chat][$id] = $data;
        return ['ok'=>true,'result'=>['message_id'=>$id]];
    }
}
class NavigationBot extends Bot {
    public array $received = [];
    public function __construct($i) { $this->i18n=$i; $this->language='ru'; $this->admin=true; $this->transport=new NavigationTransport(); }
    public function getWgMsg() { return null; }
    public function setWgMsg($inst) {}
    public function getPacConf() { return self::PAC_DEFAULTS; }
    public function getHashBot($notset=false) { return 'fixture'; }
    public function collect($value) { $this->received[] = [$this->input['chat'],$value]; }
    public function begin($chat=1, $id=1) {
        $this->input=['from'=>987654,'chat'=>$chat,'message_id'=>$id,'callback_id'=>'fixture','callback'=>'/menu','message'=>'','reply'=>false];
        $this->chatNavigationStart();
    }
    public function stop() { $this->chatNavigationActive=false; }
}
$n=0;
$check=static function($ok,$why) use (&$n) { $n++; if (!$ok) throw new RuntimeException($why); };
$b = new NavigationBot($i); $t=$b->transport;
$buttons=[[['text'=>'Назад','callback_data'=>'/menu']]];
$t->messages[1][1]=['text'=>'Menu'];
try {
    for ($r=0;$r<5;$r++) {
        $b->begin();
        $b->update(1,1,str_repeat('Строка\n',1600),$buttons);
        $check(count($t->messages[1])>1,'Длинный экран имеет продолжение');
        $b->begin(); $b->update(1,1,'Menu',$buttons);
        $check(count($t->messages[1])===1,'Продолжения удалены при переходе');
        $b->send(1,'Ошибка ввода'); $b->sendPhoto(1,'fixture-photo');
        $b->begin(); $b->update(1,1,'Menu',$buttons);
        $check(count($t->messages[1])===1,'Подсказка и QR удалены при возврате');
    }
    $b->sendFile(1,'backup-fixture'); $backup=$t->next;
    $b->send(2,'Уведомление в другом чате'); $notification=$t->next;
    $b->stop(); $b->send(1,'Уведомление cron'); $cron=$t->next;
    $b->begin();
    $check(isset($t->messages[1][$backup],$t->messages[1][$cron],$t->messages[2][$notification]),'Бэкап, cron и другой чат сохранены');
    $b->send(1,'Временный ответ'); $temporary=$t->next;
    $b->begin(2); $check(isset($t->messages[1][$temporary]),'В другом чате временный ответ не удаляется');
    $b->begin(); $check(!isset($t->messages[1][$temporary]),'Возврат в исходный чат удаляет ответ');
    foreach ([1,2] as $chat) {
        $b->begin($chat); $t->messages[$chat][500]=['text'=>'Prompt'];
        $b->stashReply(['result'=>['message_id'=>500]],['start_message'=>1,'callback'=>'collect','args'=>[]]);
    }
    foreach ([2,1] as $chat) {
        $b->begin($chat,501); $b->input['reply']=500; $b->input['message']='chat'.$chat;
        $b->reply();
    }
    $check($b->received===[[2,'chat2'],[1,'chat1']],'Одинаковые номера запросов в разных чатах независимы');
    $b->begin();
    foreach (range(0,2) as $repeat) {
        $count=count($t->messages[1]);
        $cmd=++$t->next; $t->messages[1][$cmd]=['text'=>'/menu'];
        $b->input['message_id']=$cmd; $b->input['callback_id']=false; $b->input['message']='/menu';
        $b->menu('lang');
        $sent=array_filter($t->calls,static fn($call)=>$call[0]==='sendMessage');
        $check(!isset($t->messages[1][$cmd]) && count($t->messages[1])===$count,'Команда удаляется, меню остаётся одно');
        $check(empty(end($sent)[1]['reply_to_message_id']),'Меню не отвечает на удаляемую команду');
    }
    foreach (['/start','/menu'] as $command) {
        $t->clearedByUser[1]=array_map('intval',array_keys($t->messages[1]));
        $b->begin(); $cmd=++$t->next; $t->messages[1][$cmd]=['text'=>$command];
        $b->input['message_id']=$cmd; $b->input['callback_id']=false; $b->input['message']=$command;
        $b->menu('lang');
        $visible=array_diff(array_map('intval',array_keys($t->messages[1])),$t->clearedByUser[1]);
        $check(count($visible)===1 && !empty($t->messages[1][reset($visible)]['reply_markup']),"$command показывает меню после очистки истории");
    }
    $t->clearedByUser=[];
    $b->begin(); unset($t->messages[1][1]);
    $b->update(1,1,'Restored',$buttons); $restored=$b->input['message_id'];
    $check($restored!==1 && isset($t->messages[1][$restored]),'Удалённый экран заменяется одним новым');
    foreach ([['ok'=>false,'error_code'=>429,'description'=>'retry later'],['ok'=>false,'error_code'=>400,'description'=>'Bad Request: message is not modified'],['ok'=>false,'error_code'=>500,'description'=>'timeout']] as $error) {
        $t->error=$error; $before=$t->next; $b->update(1,$restored,'Restored',$buttons);
        $check($before===$t->next,'Неопределённый отказ/тот же текст не создаёт дубликат');
    }
    $t->error=null;
    preg_match_all("~case '([^']+)':~",file_get_contents(__DIR__.'/../app/BotMenuHelp.php'),$topics);
    foreach (['ru','en'] as $lang) {
        $b->language=$lang; Lang::$en=$lang==='en';
        foreach (array_unique($topics[1]) as $topic) {
            $help=$b->menuHelpContent($topic);
            if (!$help) continue; // контекстные темы проверяются menu_help_test
            foreach (range(0,count($help[2])) as $page) {
                $b->begin(1,$restored); $before=count($t->messages[1]);
                $b->menuHelp($topic,$page);
                $check(count($t->messages[1])===$before,"$lang/$topic/$page: справка редактирует один экран");
                $b->menuHelp($topic,$page);
                $check(count($t->messages[1])===$before,'Повторное нажатие не размножает справку');
            }
        }
    }
} finally {
    if (session_status()===PHP_SESSION_ACTIVE) session_write_close();
    foreach (glob($root.'/*') as $file) unlink($file); rmdir($root);
}
echo "chat_navigation_test: $n OK\n";
