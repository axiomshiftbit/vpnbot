<?php
// Управление синтетическим состоянием snolc тем же кодом, что у бота.
// Запуск: php control.php <действие> [аргументы]; вывод — JSON.
umask(0077);
require '/src/app/ManagedProtocol.php';
set_error_handler(function ($n, $message, $file, $line) {
    if (error_reporting() & $n) throw new ErrorException($message, 0, $n, $file, $line);
    return false;
});
function snolcFixtureUser(ManagedProtocol $s, string $name): string
{
    $id = bin2hex(random_bytes(8));
    $s->change(function (&$state) use ($id, $name) {
        $state['users'][$id] = ['name' => $name, 'password' => ManagedProtocol::secret(), 'token' => bin2hex(random_bytes(32)),
            'enabled' => true, 'expires' => null, 'quota' => null, 'reset' => bin2hex(random_bytes(8))];
    });
    return $id;
}
$s = new ManagedProtocol('snolc', '/lab/proto');
$action = $argv[1] ?? 'read';
$id = $argv[2] ?? '';
if ($action === 'init') {
    $s->configure(['host' => $argv[2], 'port' => 24448], true);
    $id = snolcFixtureUser($s, 'Native A');
} elseif ($action === 'add') $id = snolcFixtureUser($s, $argv[2]);
elseif ($action === 'user') $s->user($id, json_decode($argv[3], true, flags: JSON_THROW_ON_ERROR), $argv[4] ?? '');
elseif ($action === 'configure') $s->configure(json_decode($argv[2], true, flags: JSON_THROW_ON_ERROR), isset($argv[3]) ? (bool) (int) $argv[3] : null);
elseif ($action === 'snapshot') ManagedProtocol::writeJson('/lab/snapshot.json', $s->snapshot());
elseif ($action === 'restore') $s->restore(ManagedProtocol::readJson('/lab/snapshot.json'));
elseif ($action === 'zip') {
    // Тот же ZIP, что бот отдаёт в карточке пользователя и по личной ссылке.
    $document = $s->profileDocument($id, 'native');
    if ($document['extension'] !== 'zip' || $document['mime'] !== 'application/zip') throw new RuntimeException('not a zip');
    file_put_contents('/lab/exports/' . $id . '.zip', $document['body']);
} elseif ($action !== 'read') throw new RuntimeException('unknown action');
@mkdir('/lab/exports', 0700, true);
$state = $s->read();
foreach ($state['users'] as $uid => $_) {
    // Профиль недоступен выключенному, просроченному или исчерпавшему квоту.
    try { ManagedProtocol::writeJson('/lab/exports/' . $uid . '.json', $s->profile($uid, 'native')); }
    catch (RuntimeException $e) { @unlink('/lab/exports/' . $uid . '.json'); }
}
echo json_encode(['id' => $id, 'revision' => $state['revision'], 'enabled' => $state['enabled'], 'users' => array_keys($state['users'])]), "\n";
