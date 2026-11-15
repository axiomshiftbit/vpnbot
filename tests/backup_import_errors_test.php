<?php
require_once __DIR__ . '/../app/bot.php';
require __DIR__ . '/../app/i18n.php';
class BackupErrorBot extends Bot {
    public array $messages = [];
    public array $deleted = [];
    public function getWgMsg() { return null; }
    public function delete($chat, $message_id) { $this->deleted[] = $message_id; }
    protected function takeReply($messageId): ?array { return ['callback'=>'importFile','args'=>[],'start_message'=>10]; }
    public array $apiResult = ['ok' => true, 'result' => ['file_path' => 'upload.json']];
    public bool $failProtocols = false;
    public int $applied = 0;
    public function __construct(public string $root, array $translations) {
        $this->i18n = $translations; $this->language = 'ru'; $this->update = "$root/local.json";
        $this->pac="$root/pac.json"; $this->file = "$root/"; $this->input = ['chat' => 1, 'message_id' => 1, 'callback_id' => false, 'file_id' => 'synthetic-file'];
    }
    public function request($method, $data, $json_header = 0) { if ($method !== 'getFile') throw new LogicException('Unexpected API'); return $this->apiResult; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false) { $this->messages[] = $text; }
    public function answer($callback_id, $textNotify = false, $notify = false) { throw new LogicException('Документ не является callback query'); }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') {}
    public function importManagedProtocols(array $data, bool $syncUpstreams = true): void { if ($this->failProtocols) throw new RuntimeException('SYNTHETIC_SECRET_DO_NOT_LOG'); $this->applied++; }
    public function cloakNginx() {}
    public function menu($type = false, $arg = false, $return = false) {}
    public function getPacConf() { return ['language' => 'ru', 'limitpage' => 5]; }
}
class BackupWriteErrorBot extends BackupErrorBot {
    public array $commands = [];
    public array $updates = [];
    public int $writeAttempts = 0;
    protected function backupWriteInPlace(string $path, string $body): bool {
        if (++$this->writeAttempts === 1) return false;
        return parent::backupWriteInPlace($path, $body);
    }
    public function update($chat, $message_id, $text, $button = false, $reply = false, $mode = 'HTML') { $this->updates[] = $text; }
    public function protocolModuleEnabled(string $service): bool { return in_array($service, ['ss', 'proxy', 'ad'], true); }
    public function controlContainerService(string $container, string $service, string $action): bool {
        $this->commands[] = $container . ':' . $action; return true;
    }
    public function ssh($cmd, $service='wg', $wait=true, $log='/dev/null') {
        if (str_contains($cmd,'VPNBOT_AD_STOPPED')) { $this->commands[]='wait-ad'; return 'VPNBOT_AD_STOPPED'; }
        $this->commands[]=$cmd; return '';
    }
    public function stopAd() { $this->commands[]='stop-ad'; }
    public function startAd() { $this->commands[]='start-ad'; }
    public function verifyBackupServices(array $json): array { return []; }
}
function backupCheck(bool $ok, string $name): void { if (!$ok) throw new RuntimeException($name); }
$root = sys_get_temp_dir() . '/vpnbot-backup-errors-' . bin2hex(random_bytes(6)); mkdir($root, 0700);
$oldLog = ini_set('error_log', "$root/errors.log");
try {
    $cases = [
        'invalid_json' => 'broken',
        'telemt' => ['pac' => ['telemt_user_limits' => 'broken']],
        'missing_quota' => ['pac' => ['telemt_users' => ['test' => 'synthetic'], 'telemt_user_limits' => ['test' => ['quota' => 1]]]],
        'trusttunnel' => ['tt' => []],
        'hysteria' => ['hy_users' => ['broken' => true]],
        'protocols' => ['managed_protocols' => ['modules'=>[], 'protocols'=>[]]],
    ];
    foreach ($cases as $name => $data) {
        $b = new BackupErrorBot($root, $i); $b->failProtocols = true;
        file_put_contents("$root/upload.json", is_string($data) ? $data : json_encode($data));
        backupCheck($b->importFile() === false && count($b->messages) === 1 && $b->applied === 0, "$name: видимый отказ без применения");
        backupCheck(str_contains($b->messages[0], 'Восстановление прервано'), "$name: понятное сообщение");
    }
    foreach ([['ok' => false], ['ok' => true, 'result' => []], ['ok' => true, 'result' => ['file_path' => 'missing.json']]] as $response) {
        $b = new BackupErrorBot($root, $i); $b->apiResult = $response;
        backupCheck($b->importFile() === false && count($b->messages) === 1, 'Ошибка получения файла видна');
    }
    $b = new BackupErrorBot($root, $i); $b->input['file_id'] = false;
    backupCheck($b->importFile() === false && count($b->messages) === 1, 'Ответ текстом вместо файла виден');
    $b = new BackupErrorBot($root, $i);
    backupCheck($b->importFile('/etc/passwd') === false && count($b->messages) === 1, 'Произвольный путь не читается');
    $b = new BackupErrorBot($root, $i); $b->failProtocols = true;
    file_put_contents($b->update, json_encode(['managed_protocols' => ['modules'=>[], 'protocols'=>[]]]));
    backupCheck($b->importFile($b->update) === false && !$b->messages, 'selfUpdate сам обрабатывает отказ локальной копии');
    $log = file_get_contents("$root/errors.log");
    backupCheck(str_contains($log, 'stage=protocols RuntimeException') && !str_contains($log, 'SYNTHETIC_SECRET_DO_NOT_LOG'), 'Журнал содержит место ошибки без секрета');
    $b = new BackupErrorBot($root, $i);
    file_put_contents("$root/upload.json", json_encode(['managed_protocols' => ['modules'=>[], 'protocols'=>[]]]));
    backupCheck($b->importFile() === true && $b->applied === 1 && !$b->messages, 'Успешный импорт продолжает работать');
    foreach ([true, false] as $fail) {
        $b = new BackupErrorBot($root, $i); $b->failProtocols = $fail;
        $b->input += ['reply'=>20,'message'=>'']; $b->input['message_id']=30;
        $b->reply();
        backupCheck($b->deleted === [20], 'Документ бэкапа остаётся в чате при успехе и отказе');
        backupCheck(count($b->messages) === ($fail ? 1 : 0), 'reply сообщает об отказе ровно один раз');
    }
    foreach (['ss','sl','ad'] as $section) {
        $b = new BackupWriteErrorBot($root, $i);
        $config = $section === 'ad' ? ['test'=>'synthetic'] : ['server_port'=>8388, 'password'=>'synthetic-new', 'method'=>'chacha20-ietf-poly1305'];
        $path = "$root/" . ($section === 'ss' ? 'ssserver' : 'sslocal') . '.json';
        if ($section !== 'ad') file_put_contents($path, json_encode($config + ['fixture'=>'previous']));
        $before = $section === 'ad' ? null : file_get_contents($path);
        file_put_contents("$root/upload.json",json_encode([$section=>$config]));
        backupCheck($b->importFile()===false && $b->writeAttempts > 0, "$section: отказ именно записи достигнут");
        backupCheck($section === 'ad' ? count($b->messages)===1 : str_contains(implode("\n", $b->updates), '❌ Shadowsocks'), "$section: отказ записи виден");
        $service = $section === 'ss' ? 'ss' : 'proxy';
        backupCheck($b->commands===($section==='ad' ? ['stop-ad','wait-ad','start-ad'] : [$service.':stop',$service.':stop',$service.':start']), "$section: отказ записи не оставляет прежний сервис остановленным");
        if ($section !== 'ad') backupCheck(file_get_contents($path)===$before, "$section: прежний файл сохранён");
    }
    echo "backup_import_errors_test OK\n";
} finally {
    ini_set('error_log', $oldLog);
    foreach (glob("$root/*") as $p) unlink($p);
    @unlink("$root/.backup.lock");
    rmdir($root);
}
