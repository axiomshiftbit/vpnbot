#!/bin/sh
# Установка systemd-юнита. set -eu и подстановка через awk, а не sed:
# путь установки уходил в ТЕЛО sed-выражения, поэтому символ | в пути ломал
# выражение, а редирект в /etc/systemd/system/ без проверки успеха оставлял
# ПУСТОЙ юнит — и systemctl enable падал уже на следующей строке.
set -eu

path=$(pwd)
unit=/etc/systemd/system/vpnbot.service
tmp=$(mktemp)

# Заменяем отличимый плейсхолдер, а не слово «path» глобально, иначе замена
# затронула бы любое вхождение подстроки в шаблоне.
awk -v p="$path" '{ gsub(/__VPNBOT_PATH__/, p); print }' "$path/scripts/vpnbot.service" > "$tmp"
if [ ! -s "$tmp" ]; then
    rm -f "$tmp"
    echo "FATAL: не удалось собрать юнит из scripts/vpnbot.service" >&2
    exit 1
fi
cat "$tmp" > "$unit"
rm -f "$tmp"

systemctl daemon-reload
systemctl enable vpnbot
