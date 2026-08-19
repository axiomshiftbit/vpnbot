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
iptables -t nat -A POSTROUTING --destination 10.10.0.5 -j ACCEPT
iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
mkdir -p /logs
[ -f /logs/ocserv.log ] || : > /logs/ocserv.log
ocserv -f -c /etc/ocserv/ocserv.conf >>/logs/ocserv.log 2>&1 &
tail -f /dev/null
