#!/bin/sh
for i in 1 2 3 4 5 10; do
    getent hosts wg wg1 >/dev/null 2>&1 && break
    sleep 1
done
WG_IP=$(getent hosts wg  | awk '{print $1}')
WG1_IP=$(getent hosts wg1 | awk '{print $1}')
OC_IP=$(getent hosts oc  | awk '{print $1}')
# OpenConnect может стартовать позже AdGuard или быть выключен. Его адрес
# закреплён в Compose; обратный маршрут нужен и до появления имени в DNS.
# Если адрес уже разрешается (например, в override), сохраняем его приоритет.
OC_IP=${OC_IP:-10.10.0.11}
[ -n "$WG_IP"  ] && ip route replace 10.0.1.0/24 via "$WG_IP"
[ -n "$WG1_IP" ] && ip route replace 10.0.3.0/24 via "$WG1_IP"
[ -n "$OC_IP"  ] && ip route replace 10.0.2.0/24 via "$OC_IP"
cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
# Без exec: `exec cmd &` порождает подоболочку, которую exec собой и заменяет,
# то есть работает как обычный фоновый запуск, но читается как «заменить
# текущий процесс» (то же пояснение есть в start_wp.sh).
/usr/sbin/sshd -D -e "$@" &
# ВНИМАНИЕ: `tail -f /dev/null` ниже — НЕ мёртвый код, что бы ни казалось по
# чтению. Жизненным циклом AdGuardHome управляет БОТ, а не entrypoint:
# stopAd() делает `kill -15 $(cat pid)` по ssh, startAd() запускает демон
# заново — и так на каждый adguardSync() (а его безусловно зовёт service.php
# при каждом старте, плюс смена сертификата, домена и пароля). Пока tail есть,
# контейнер переживает эти циклы; без него первый же stopAd() убивал
# единственный процесс переднего плана, контейнер завершался с кодом 0, а
# startAd() было уже некуда достучаться: DNS всей установки ложился, а nginx
# уходил в unhealthy, потому что не резолвился upstream «ad».
# Проверено на рабочем сервере 2026-08-18: снятие этой строки положило AdGuard.
/opt/adguardhome/AdGuardHome --no-check-update --pidfile /opt/adguardhome/pid -c /config/AdGuardHome.yaml -h 0.0.0.0 -w /opt/adguardhome/work
tail -f /dev/null
