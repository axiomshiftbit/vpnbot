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
# Ключ узла выдаёт контейнер php (ssh/hosts/<сервис>): бот сверяет его
# отпечаток перед каждой командой. Случайный ключ бот не примет.
# Каталог подключён, а ключа ещё нет — php не успел его создать: ждём.
hostkey_wait=0; while [ -d /hostkey ] && [ ! -s /hostkey/ssh_host_ed25519_key.pub ] && [ "$hostkey_wait" -lt 60 ]; do sleep 1; hostkey_wait=$((hostkey_wait + 1)); done
cp -p /hostkey/ssh_host_ed25519_key /hostkey/ssh_host_ed25519_key.pub /etc/ssh/ 2>/dev/null || ssh-keygen -A
# Без exec: `exec cmd &` порождает подоболочку, которую exec собой и заменяет,
# то есть работает как обычный фоновый запуск, но читается как «заменить
# текущий процесс» (то же пояснение есть в start_wp.sh).
/usr/sbin/sshd -D -e "$@" &
# Supervisor сохраняет контейнер и SSH при intentional stopAd().
# Только аварийная остановка процесса при desired-on вызывает новый запуск.
exec /bin/sh /service_supervisor.sh supervise ad
