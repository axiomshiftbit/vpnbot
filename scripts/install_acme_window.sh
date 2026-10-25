#!/bin/sh
# Установка службы acme-window (scripts/acme_window.py) на хост. Запускать от
# root из каталога бота:  sh scripts/install_acme_window.sh [--uninstall]
#
# Нужны заранее:
#   /etc/acme-window/config.json — адрес сервера и цели (пример ниже);
#   наборы acme_http_fwd (и acme_http_redirect, если есть цель с redirect) и
#   правила, которые на них ссылаются, в /etc/nftables.conf и в ядре.
# Без них служба не включается: окно некуда было бы открывать.
#
# {
#   "public_ip": "203.0.113.10",
#   "targets": [
#     {"name": "vpnbot", "kind": "vpnbot", "upstream": "10.10.0.2:80"}
#   ]
# }
set -eu

path=$(pwd)
units="acme-window.service acme-window-close.service acme-window.timer acme-window.path"

if [ "${1:-}" = "--uninstall" ]; then
    systemctl disable --now acme-window.timer acme-window.path 2>/dev/null || true
    # Отключение таймера не останавливает уже запущенный выпуск: он мог бы
    # снова открыть окно после close-all и удаления файлов службы.
    if [ "$(systemctl show -p LoadState --value acme-window.service)" != "not-found" ]; then
        systemctl stop acme-window.service
    fi
    if [ -f /usr/local/sbin/acme-window ]; then
        python3 /usr/local/sbin/acme-window close-all || {
            echo "FATAL: закрытие окна не подтверждено; файлы службы сохранены" >&2
            exit 1
        }
    fi
    # Иначе бот ещё три часа принимает оставшийся heartbeat за работающую
    # службу и отправляет запросы в очередь, которую уже некому читать.
    rm -f "$path/acme/state/agent.json"
    for u in $units; do rm -f "/etc/systemd/system/$u"; done
    rm -f /usr/local/sbin/acme-window
    systemctl daemon-reload
    echo "acme-window удалена; /etc/acme-window и /var/lib/acme-window оставлены"
    exit 0
fi

[ "$(id -u)" = 0 ] || { echo "FATAL: нужен root" >&2; exit 1; }
[ -f "$path/scripts/acme_window.py" ] || { echo "FATAL: запускать из каталога бота" >&2; exit 1; }
if [ ! -f /etc/acme-window/config.json ]; then
    echo "FATAL: нет /etc/acme-window/config.json (пример — в начале этого файла)" >&2
    exit 1
fi

install -m 0755 -o root -g root "$path/scripts/acme_window.py" /usr/local/sbin/acme-window.new
mv -f /usr/local/sbin/acme-window.new /usr/local/sbin/acme-window
install -d -m 0755 "$path/acme" "$path/acme/state"
install -d -m 0700 "$path/acme/request"

if ! python3 /usr/local/sbin/acme-window check; then
    echo "FATAL: в nftables нет наборов или правил окна; служба не включена" >&2
    exit 1
fi

for u in $units; do
    tmp=$(mktemp)
    awk -v p="$path" '{ gsub(/__VPNBOT_PATH__/, p); print }' "$path/scripts/$u" > "$tmp"
    if [ ! -s "$tmp" ]; then
        rm -f "$tmp"
        echo "FATAL: не удалось собрать $u" >&2
        exit 1
    fi
    install -m 0644 "$tmp" "/etc/systemd/system/$u"
    rm -f "$tmp"
done
systemctl daemon-reload
systemctl enable --now acme-window.timer acme-window.path
echo "acme-window установлена: таймер раз в час, запросы бота — сразу"
