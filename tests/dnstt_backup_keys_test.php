<?php
// BK-07 (аудит A): предварительная проверка бэкапа DNSTT принимает только
// согласованную пару Noise (X25519: открытый ключ выводится из закрытого) и
// настоящую пару SSH ed25519, а не произвольные строки. Ключи синтетические:
// вектор RFC 7748 и пары, созданные ssh-keygen во временном каталоге.
require_once __DIR__ . '/../app/bot.php';

class DnsttKeysBot extends Bot { public function __construct() { $this->language = 'ru'; $this->input = []; } }

$failed = 0; $count = 0;
$check = static function (bool $ok, string $what) use (&$failed, &$count) { $count++; if (!$ok) { $failed++; echo "FAIL: $what\n"; } };
$bot = new DnsttKeysBot();
$accepts = static function (array $dnstt) use ($bot): bool {
    try { $bot->validateBackup(['dnstt' => $dnstt]); return true; } catch (InvalidArgumentException) { return false; }
};
$root = sys_get_temp_dir() . '/vpnbot-dnstt-keys-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
$ssh = static function (string $name) use ($root): array {
    exec('ssh-keygen -q -t ed25519 -N "" -C vpnbot-test -f ' . escapeshellarg("$root/$name") . ' 2>&1', $out, $rc);
    if ($rc !== 0) throw new RuntimeException('ssh-keygen failed');
    return [file_get_contents("$root/$name"), file_get_contents("$root/$name.pub")];
};
try {
    // RFC 7748, раздел 6.1: закрытый и открытый ключ Алисы.
    $private = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a\n";
    $public  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a\n";
    $bobPublic = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f\n";
    [$a, $aPub] = $ssh('a'); [, $bPub] = $ssh('b');

    $check($accepts(['private' => $private, 'public' => $public, 'ssh_private' => $a, 'ssh_public' => $aPub]), 'согласованные пары принимаются');
    $check($accepts(['private' => $private, 'public' => $public, 'ssh_private' => '', 'ssh_public' => '']), 'копия без SSH-пары (старый формат) принимается');
    $check(!$accepts(['private' => $private, 'public' => $bobPublic]), 'открытый ключ DNSTT не от этого закрытого — отказ');
    $check(!$accepts(['private' => $private, 'public' => $public, 'ssh_private' => $a, 'ssh_public' => $bPub]), 'SSH-пара из разных ключей — отказ');
    $check(!$accepts(['private' => $private, 'public' => $public, 'ssh_private' => 'not a key', 'ssh_public' => 'ssh-ed25519 AAAA junk']), 'произвольные строки вместо SSH-ключей — отказ');
    $check(!$accepts(['private' => $private, 'public' => $public, 'ssh_private' => $a, 'ssh_public' => "ssh-rsa AAAAB3NzaC1yc2E= x\n"]), 'чужой тип ключа — отказ');
} finally {
    exec('rm -rf ' . escapeshellarg($root));
}
echo "dnstt_backup_keys_test: " . ($count - $failed) . "/$count\n";
exit($failed ? 1 : 0);
