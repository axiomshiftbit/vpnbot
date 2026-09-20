#!/bin/sh
INTERFACE=$(route 2>/dev/null | grep '^default' | grep -o '[^ ]*$')
# route (net-tools) может отсутствовать или ещё не видеть default (гонка на
# старте сети контейнера) — берём дефолтный интерфейс через ip. Пустой
# INTERFACE означал MASQUERADE, который не встал: туннель поднимается, клиенты
# подключаются, наружу трафик не ходит — и ни строки в логе, потому что
# `2>/dev/null || true` гасил и вывод, и код возврата.
[ -z "$INTERFACE" ] && INTERFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
[ -n "$INTERFACE" ] || echo "WARN: default interface not detected — NAT rules will NOT be applied" >&2
cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
# Без exec: `exec cmd &` порождает подоболочку, которую exec собой и
# заменяет, то есть это обычный фоновый запуск, но читается как «заменить
# текущий процесс» (то же пояснение есть в start_wp.sh).
/usr/sbin/sshd -D -e "$@" &
# Интерфейсы клиентов создаёт ocserv с префиксом device из ocserv.conf.
# Закрываем от них службы контейнера и сеть сборки, сохраняя DNS AdGuard.
VPN_DEVICE=$(awk -F= '/^[[:space:]]*device[[:space:]]*=/ {gsub(/[[:space:]"]/, "", $2); print $2; exit}' /etc/ocserv/ocserv.conf)
if [ -z "$VPN_DEVICE" ]; then
    echo 'FATAL: ocserv device is empty — client isolation cannot be installed' >&2
    exit 1
fi
iptables -A INPUT -i "${VPN_DEVICE}+" -j REJECT
iptables -A FORWARD -i "${VPN_DEVICE}+" -d 10.10.0.5 -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -i "${VPN_DEVICE}+" -d 10.10.0.5 -p tcp --dport 53 -j ACCEPT
iptables -A FORWARD -i "${VPN_DEVICE}+" -d 10.10.0.0/16 -j REJECT
iptables -t nat -A POSTROUTING --destination 10.10.0.5 -j ACCEPT
iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
mkdir -p /logs
[ -f /logs/ocserv.log ] || : > /logs/ocserv.log
ocserv -f -c /etc/ocserv/ocserv.conf >>/logs/ocserv.log 2>&1 &
tail -f /dev/null
