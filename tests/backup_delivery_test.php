<?php
// Настоящий pinBackup, синтетические настройки и транспорт Telegram.
$dir = sys_get_temp_dir() . '/vpnbot-backup-delivery-' . bin2hex(random_bytes(6));
mkdir($dir, 0700);
foreach (glob(__DIR__ . '/../app/*.php') as $source) {
    if (!in_array(basename($source), ['config.php', 'debug.php'], true)) copy($source, $dir . '/' . basename($source));
}
file_put_contents("$dir/config.php", '<?php $c = ["admin" => [123]];');
require "$dir/bot.php";
class BackupDeliveryBot extends Bot {
    public array $conf = ['pinbackup' => 10];
    public array $calls = [];
    public array $response = ['ok' => true, 'result' => ['message_id' => 20]];
    public bool $pinOk = true;
    public bool $saveOk = true;
    public string $snapshot = '{"pac":{"domain":"example.test"}}';
    public function __construct() {}
    public function getPacConf() { return $this->conf; }
    public function setPacConf($conf) { $this->calls[] = 'save'; if (!$this->saveOk) return false; $this->conf = $conf; return true; }
    public function export() { return $this->snapshot; }
    public function request($method, $data, $json_header = 0) { return ['ok' => false]; }
    public function sendFile($chat, $id_url_cFile, $caption = false, $to = false) {
        if (!$id_url_cFile instanceof CURLStringFile || $id_url_cFile->data !== $this->snapshot) throw new RuntimeException('Содержимое отправки изменилось');
        $this->calls[] = 'send'; return $this->response;
    }
    public function pinAdmin($pin, $unpin = false) { $this->calls[] = ($unpin ? 'unpin:' : 'pin:') . $pin; return ['ok' => $this->pinOk]; }
}
function deliveryCheck(bool $ok, string $message): void { if (!$ok) throw new RuntimeException($message); }
try {
    foreach ([['ok'=>false], ['ok'=>true], ['ok'=>true, 'result'=>['message_id'=>'bad']]] as $response) {
        $b = new BackupDeliveryBot; $b->response = $response;
        deliveryCheck($b->pinBackup() === false && $b->calls === ['send'] && $b->conf['pinbackup'] === 10, 'Отказ API сохраняет прежнюю копию');
    }
    $b = new BackupDeliveryBot; $b->snapshot = 'broken';
    deliveryCheck($b->pinBackup() === false && !$b->calls, 'Повреждённый экспорт не отправляется');
    $b = new BackupDeliveryBot; $b->saveOk = false;
    deliveryCheck($b->pinBackup() === false && $b->calls === ['send','save'], 'Отказ записи не открепляет прежнюю копию');
    $b = new BackupDeliveryBot; $b->pinOk = false;
    deliveryCheck($b->pinBackup() === true && $b->calls === ['send','save','pin:20'], 'Доставленный файл сохранён даже при отказе закрепления');
    $b = new BackupDeliveryBot;
    deliveryCheck($b->pinBackup("$dir/local.json") === true && $b->calls === ['send','save','pin:20','unpin:10'], 'Сначала доставка и закрепление, затем открепление');
    deliveryCheck(file_get_contents("$dir/local.json") === $b->snapshot && (fileperms("$dir/local.json") & 0777) === 0600, 'Локальная копия полная и закрыта');
    $b = new BackupDeliveryBot;
    deliveryCheck($b->pinBackup("$dir/missing/local.json") === false && !$b->calls, 'Отказ локальной копии останавливает обновление');
    $b = new BackupDeliveryBot; $b->snapshot = json_encode(['pac'=>['large'=>str_repeat('x', 20 * 1024 * 1024)]]);
    deliveryCheck($b->pinBackup() === false && !$b->calls, 'Копия сверх лимита скачивания Telegram не отправляется');
    unset($b);
    $b = new BackupDeliveryBot;
    $b->conf += ['backup'=>date('Y-m-d H:i:s', time()-3600).'/1 day', 'last_backup_time'=>1];
    $b->response = ['ok'=>false]; $b->checkBackup();
    deliveryCheck($b->conf['last_backup_time'] === 1, 'Неуспешная доставка не отмечается выполненной в расписании');
    $b->response = ['ok'=>true,'result'=>['message_id'=>20]]; $before = time(); $b->checkBackup();
    deliveryCheck($b->conf['last_backup_time'] >= $before && $b->conf['pinbackup'] === 20, 'Повтор расписания сохраняет время успеха и новый pin');
    $calls = $b->calls; $b->checkBackup();
    deliveryCheck($b->calls === $calls, 'Успешная плановая копия не отправляется повторно в тот же период');
    echo "backup_delivery_test OK\n";
} finally {
    foreach (glob("$dir/*") as $file) unlink($file);
    rmdir($dir);
}
