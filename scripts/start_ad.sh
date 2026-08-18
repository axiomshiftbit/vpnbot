#!/bin/sh
for i in 1 2 3 4 5 10; do
    getent hosts wg wg1 oc >/dev/null 2>&1 && break
    sleep 1
done
WG_IP=$(getent hosts wg  | awk '{print $1}')
WG1_IP=$(getent hosts wg1 | awk '{print $1}')
OC_IP=$(getent hosts oc  | awk '{print $1}')
[ -n "$WG_IP"  ] && ip route replace 10.0.1.0/24 via "$WG_IP"
[ -n "$WG1_IP" ] && ip route replace 10.0.3.0/24 via "$WG1_IP"
[ -n "$OC_IP"  ] && ip route replace 10.0.2.0/24 via "$OC_IP"
cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
# Без exec: `exec cmd &` порождает подоболочку, которую exec собой и заменяет,
# то есть работает как обычный фоновый запуск, но читается как «заменить
# текущий процесс» (то же пояснение есть в start_wp.sh).
/usr/sbin/sshd -D -e "$@" &
# AdGuardHome работает в foreground и ДЕРЖИТ контейнер: если он упал, контейнер
# обязан завершиться, чтобы restart-политика подняла его заново. Прежний
# `tail -f /dev/null` был недостижим и только вводил в заблуждение.
/opt/adguardhome/AdGuardHome --no-check-update --pidfile /opt/adguardhome/pid -c /config/AdGuardHome.yaml -h 0.0.0.0 -w /opt/adguardhome/work
