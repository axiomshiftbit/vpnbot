#!/bin/bash
# Сетевые параметры ядра для VPNBot (init.sh): /etc/sysctl.d/99-vpnbot-sysctl.conf.
#   bash scripts/host_sysctl.sh full|node
# Дополняет scripts/host_hardening.sh (97-vpnbot-neighbor.conf: ARP, redirect,
# syncookies) и запрет маршрутизации ноды (98-vpnbot-node-forwarding.conf,
# scripts/node_setup.py). Повторный запуск безопасен: файл пишется целиком.
#  - BBR и очередь fq, буферы и очереди TCP/UDP, таймауты TCP, conntrack;
#  - IPv6: не принимать redirect и source route; строки выключения IPv6 —
#    закомментированы (выборочный IPv6-выход бота без IPv6 не работает);
#  - полный бот: ip_forward=1 (контейнеры Docker, NAT, VPN); нода — без
#    маршрутизации, ip_forward=0 задаёт установщик ноды.
set -euo pipefail
ROOT="${VPNBOT_HARDENING_ROOT:-}"
mode="${1:-}"
case "$mode" in full|node) ;; *) echo 'usage: host_sysctl.sh full|node' >&2; exit 2;; esac
target="$ROOT/etc/sysctl.d/99-vpnbot-sysctl.conf"
mkdir -p "$(dirname "$target")"
{
    echo "# VPNBot ($mode): сетевые параметры ядра (scripts/host_sysctl.sh)."
    echo '# Защита от соседей — 97-vpnbot-neighbor.conf (scripts/host_hardening.sh).'
    echo
    echo '# IPv6: чтобы выключить, раскомментируйте (выборочный IPv6-выход бота тогда недоступен).'
    echo '#net.ipv6.conf.all.disable_ipv6 = 1'
    echo '#net.ipv6.conf.default.disable_ipv6 = 1'
    echo '#net.ipv6.conf.lo.disable_ipv6 = 1'
    echo
    echo '# IPv6: redirect и source route не принимаются.'
    for key in accept_redirects accept_source_route; do
        for scope in all default; do echo "net.ipv6.conf.$scope.$key = 0"; done
    done
    echo '# Только при статической адресации IPv6 (без SLAAC/RA от хостера):'
    for key in accept_ra autoconf router_solicitations use_tempaddr; do
        for scope in all default; do echo "#net.ipv6.conf.$scope.$key = 0"; done
    done
    cat <<'SYSCTL'

# Сеть: BBR, буферы и очереди TCP/UDP
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.wmem_default = 2097152
net.core.netdev_max_backlog = 10240
net.core.somaxconn = 8192

# Защита
net.ipv4.tcp_syncookies = 1

# TCP
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_max_syn_backlog = 10240
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.udp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 16384 262144 8388608
net.ipv4.tcp_wmem = 32768 524288 16777216
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0

# Системные лимиты
fs.inotify.max_user_instances = 8192
net.ipv4.ip_local_port_range = 1024 45000

# Netfilter (conntrack загружается при старте: scripts/host_hardening.sh)
net.netfilter.nf_conntrack_max = 131072
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
net.netfilter.nf_conntrack_tcp_loose = 0
SYSCTL
    if [ "$mode" = full ]; then
        echo
        echo '# Маршрутизация: контейнеры Docker, NAT, VPN'
        echo 'net.ipv4.ip_forward = 1'
    fi
} > "$target.tmp"
chmod 644 "$target.tmp"
mv -f "$target.tmp" "$target"
# BBR — модуль ядра: без него параметр не применится и сейчас, и после загрузки.
if [ -z "$ROOT" ]; then
    if modprobe tcp_bbr 2>/dev/null; then echo tcp_bbr > /etc/modules-load.d/vpnbot-bbr.conf; fi
    # Ядро без IPv6 (ipv6.disable=1) не имеет ключей net.ipv6.*: их пропускаем
    # сейчас, а systemd-sysctl при загрузке пропускает отсутствующие сам.
    while IFS= read -r line; do
        case "$line" in
            net.ipv6.*) [ -d /proc/sys/net/ipv6 ] || continue ;;
        esac
        printf '%s\n' "$line"
    done < "$target" | sysctl -q -p - || echo 'WARN: часть параметров 99-vpnbot-sysctl.conf ядро не приняло' >&2
fi
echo "Host sysctl ($mode): 99-vpnbot-sysctl.conf"
