#!/bin/sh
# Вызывать после остановки openvpn и до его запуска, в том числе после restore.
# client-to-client управляет userspace forwarding; без него TUN всё равно
# маршрутизирует клиентов через ядро. Отдельная цепочка закрывает этот путь.
set -eu

config=${1:-/etc/openvpn/server.conf}
if pidof openvpn >/dev/null 2>&1; then
    echo 'FATAL: stop OpenVPN before changing client isolation' >&2
    exit 1
fi

# Поддерживаем прямой конфиг, который создаёт бот. Вложенные config могли бы
# переопределить dev/client-to-client, поэтому их не интерпретируем частично.
settings=$(awk '
    /^[[:space:]]*([#;]|$)/ { next }
    { option=$1; sub(/^--/, "", option) }
    option == "config" { exit 1 }
    option == "dev" { if (dev != "" || NF < 2) exit 1; dev=$2 }
    option == "client-to-client" { allow=1 }
    END { if (dev == "") exit 1; print dev, allow+0 }
' "$config") || { echo 'FATAL: cannot determine OpenVPN client isolation from config' >&2; exit 1; }
device=${settings% *}
allow=${settings##* }
case "$device" in
    tun) device=tun+ ;;
    ''|*[!A-Za-z0-9_.-]*) echo 'FATAL: unsupported OpenVPN device name' >&2; exit 1 ;;
esac
[ "${#device}" -le 15 ] || { echo 'FATAL: unsupported OpenVPN device name' >&2; exit 1; }

for family in iptables ip6tables; do
    # --noflush сохраняет остальные правила. Flush нашей цепочки и новая
    # политика применяются одной транзакцией, без промежуточной пустой цепочки.
    {
        printf '*filter\n:VPNBOT_OVPN_CLIENTS - [0:0]\n-F VPNBOT_OVPN_CLIENTS\n'
        if [ "$allow" != 1 ]; then
            printf '%s\n' "-A VPNBOT_OVPN_CLIENTS -i $device -o $device -j REJECT"
        fi
        printf 'COMMIT\n'
    } | "$family-restore" --wait 5 --noflush || {
        echo 'FATAL: OpenVPN client isolation was not installed' >&2; exit 1;
    }
    "$family" --wait 5 -C FORWARD -j VPNBOT_OVPN_CLIENTS 2>/dev/null \
        || "$family" --wait 5 -I FORWARD 1 -j VPNBOT_OVPN_CLIENTS \
        || { echo 'FATAL: OpenVPN client isolation hook was not installed' >&2; exit 1; }
done
