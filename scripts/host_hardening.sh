#!/bin/bash
# Сетевая защита хоста VPNBot: полная установка и нода (init.sh). Повторный
# запуск безопасен. Правила nftables здесь не меняются — их задаёт профиль.
#  - соседи по сети хостера: ARP только для адресов своего интерфейса,
#    без объявления внутренних адресов и без отправки ICMP redirect;
#  - nf_conntrack загружается при старте: иначе systemd-sysctl молча
#    пропускает net.netfilter.* из /etc/sysctl.d;
#  - LLMNR и mDNS systemd-resolved выключены: службам они не нужны,
#    порт 5355 больше не слушается даже при незагруженном firewall.
set -euo pipefail

ROOT="${VPNBOT_HARDENING_ROOT:-}"

write() {
    local target="$ROOT$1"
    mkdir -p "$(dirname "$target")"
    cat > "$target.tmp"
    chmod 644 "$target.tmp"
    mv -f "$target.tmp" "$target"
}

# send_redirects для уже поднятого интерфейса задаётся только по имени:
# значение default действует лишь на интерфейсы, созданные позже.
wan="$(ip -4 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')"
{
    echo '# VPNBot: защита от соседей по сети хостера (scripts/host_hardening.sh).'
    for key in arp_ignore=1 arp_announce=2 send_redirects=0 accept_redirects=0 secure_redirects=0 accept_source_route=0; do
        for scope in all default; do echo "net.ipv4.conf.$scope.${key%%=*} = ${key#*=}"; done
    done
    # send/secure redirects берутся по «или» с conf.all — интерфейс тоже по имени.
    if [[ "$wan" =~ ^[A-Za-z0-9_-]{1,15}$ ]]; then
        for key in send_redirects accept_redirects secure_redirects; do echo "net.ipv4.conf.$wan.$key = 0"; done
    fi
    echo 'net.ipv4.icmp_echo_ignore_broadcasts = 1'
    echo 'net.ipv4.icmp_ignore_bogus_error_responses = 1'
    # Поддельный SYN-флуд гасится без хранения состояния, а не лимитом по
    # адресу источника, который подделка исчерпывает.
    echo 'net.ipv4.tcp_syncookies = 1'
} | write /etc/sysctl.d/97-vpnbot-neighbor.conf
sysctl -q -p "$ROOT/etc/sysctl.d/97-vpnbot-neighbor.conf" || echo 'WARN: neighbour sysctl partially applied' >&2

echo nf_conntrack | write /etc/modules-load.d/vpnbot-conntrack.conf
if modprobe nf_conntrack 2>/dev/null; then
    # Ключи net.netfilter.* из уже установленных файлов теперь существуют.
    for file in "$ROOT"/etc/sysctl.d/*.conf; do
        [ -f "$file" ] && grep -q '^[[:space:]]*net\.netfilter\.' "$file" || continue
        grep '^[[:space:]]*net\.netfilter\.' "$file" | sysctl -q -p - || echo "WARN: netfilter sysctl from $file partially applied" >&2
    done
else
    echo 'NOTE: nf_conntrack is not loadable now; it loads at the next boot' >&2
fi

if systemctl is-enabled --quiet systemd-resolved 2>/dev/null; then
    printf '[Resolve]\nLLMNR=no\nMulticastDNS=no\n' | write /etc/systemd/resolved.conf.d/90-vpnbot-no-llmnr.conf
    systemctl try-restart systemd-resolved || echo 'WARN: systemd-resolved restart failed' >&2
fi
echo 'Host hardening: neighbour sysctl, nf_conntrack at boot, LLMNR/mDNS off'
