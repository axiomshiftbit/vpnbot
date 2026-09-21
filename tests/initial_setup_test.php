<?php

// sslip() требует локальный config.php. Копия класса в отдельном каталоге
// позволяет проверить первый запуск, не создавая/меняя конфиг установки.
$dir = sys_get_temp_dir() . '/vpnbot-bootstrap-' . bin2hex(random_bytes(6));
mkdir($dir, 0700);
foreach (['bot.php', 'ClashTemplateValidator.php', 'VlessEncryption.php', 'BotProtocols.php', 'BotProtocolOptions.php', 'ProtocolModules.php', 'ManagedProtocol.php', 'ProtocolOptions.php', 'PanelPasswordVault.php'] as $file) {
    copy(__DIR__ . '/../app/' . $file, "$dir/$file");
}
file_put_contents("$dir/config.php", '<?php $c = ["admin" => [1]];');
require "$dir/bot.php";

class InitialSetupBot extends Bot
{
    public array $actions = [];
    public function __construct() { $this->ip = '192.0.2.1'; }
    public function send($chat, $text, ?int $to = 0, $button = false, $reply = false, $mode = 'HTML', $disable_notification = false)
    { return ['result' => ['message_id' => 1]]; }
    public function menu($type = false, $arg = false, $return = false) {}
    public function addDomain($domain, $nomenu = false) { $this->actions[] = ['domain', $domain]; }
    public function setSSL($name) { $this->actions[] = ['ssl', $name]; }
}

try {
    foreach ([[], ['domain' => 'existing.example'], ['hash' => 'existing-installation']] as $settings) {
        $bot = new InitialSetupBot();
        $bot->pac = "$dir/pac.json";
        file_put_contents($bot->pac, json_encode((object) $settings));
        $initialSetup = $bot->getPacConf() == Bot::PAC_DEFAULTS;
        // selfUpdate/ssPswdCheck сохраняют служебные данные до sslip().
        $bot->setPacConf($bot->getPacConf() + ['generated' => true]);
        $bot->sslip($initialSetup);
        $expected = $settings === [] ? [['domain', '192-0-2-1.nip.io'], ['ssl', 'letsencrypt']] : [];
        if ($bot->actions !== $expected) {
            throw new RuntimeException('Первый запуск и существующая установка перепутаны');
        }
    }
} finally {
    foreach (glob("$dir/*") as $file) unlink($file);
    rmdir($dir);
}
echo "initial_setup_test OK\n";
