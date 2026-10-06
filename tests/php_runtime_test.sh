#!/bin/sh
# Запускается в готовом PHP-образе: CLI и FreeUnit должны обслуживать один PHP
# с обязательными расширениями и смонтированным пользовательским php.ini.
set -eu
root=$(mktemp -d)
pid=
trap '[ -z "$pid" ] || kill "$pid" 2>/dev/null || true; rm -rf "$root"' EXIT
mkdir "$root/www"
cat > "$root/www/index.php" <<'PHP'
<?php
header('Content-Type: application/json');
echo json_encode([
    'php' => PHP_VERSION,
    'ini' => php_ini_loaded_file(),
    'extensions' => array_map('extension_loaded', ['curl', 'ssh2', 'yaml', 'intl', 'zip', 'openssl', 'mbstring', 'Zend OPcache']),
    'form' => $_POST,
    'upload' => isset($_FILES['backup']) ? filesize($_FILES['backup']['tmp_name']) : 0,
]);
PHP
cat > "$root/unit.json" <<JSON
{"listeners":{"127.0.0.1:18080":{"pass":"applications/php"}},"applications":{"php":{"type":"php","root":"$root/www","script":"index.php","user":"root","processes":1}}}
JSON
unitd --no-daemon --control "unix:$root/control.sock" --pid "$root/unit.pid" \
    --state "$root/state" --log "$root/unit.log" > "$root/unit.stdout" 2>&1 &
pid=$!
i=0
while [ ! -S "$root/control.sock" ] && [ "$i" -lt 50 ]; do
    sleep 0.1
    i=$((i + 1))
done
curl --fail --silent --show-error --max-time 5 --unix-socket "$root/control.sock" \
    -X PUT --data-binary "@$root/unit.json" http://localhost/config >/dev/null
curl --fail --silent --show-error --max-time 5 http://127.0.0.1:18080/ | php -r '
    $result = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
    if ($result["php"] !== PHP_VERSION || in_array(false, $result["extensions"], true)
        || $result["ini"] !== php_ini_loaded_file()) exit(1);
    echo "PHP CLI/FreeUnit: ", PHP_VERSION, "; extensions and php.ini OK\n";
'
# Невалидная конфигурация отклоняется, прежнее приложение остаётся доступно.
status=$(printf '{invalid' | curl --silent --show-error --max-time 5 --unix-socket "$root/control.sock" \
    -o /dev/null -w '%{http_code}' -X PUT --data-binary @- http://localhost/config)
[ "$status" = 400 ]
php -r 'file_put_contents($argv[1], str_repeat("x", 262144));' "$root/backup.json"
curl --fail --silent --show-error --max-time 5 -F "backup=@$root/backup.json" -F 'mode=restore' \
    http://127.0.0.1:18080/ | php -r '
    $result = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
    if ($result["upload"] !== 262144 || $result["form"] !== ["mode" => "restore"]) exit(1);
    echo "FreeUnit: invalid config rollback and multipart upload OK\n";
'
