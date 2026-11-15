#!/bin/sh
cat /ssh/key.pub > /root/.ssh/authorized_keys
# Ключ узла выдаёт контейнер php (ssh/hosts/<сервис>): бот сверяет его
# отпечаток перед каждой командой. Случайный ключ бот не примет.
# Каталог подключён, а ключа ещё нет — php не успел его создать: ждём.
hostkey_wait=0; while [ -d /hostkey ] && [ ! -s /hostkey/ssh_host_ed25519_key.pub ] && [ "$hostkey_wait" -lt 60 ]; do sleep 1; hostkey_wait=$((hostkey_wait + 1)); done
cp -p /hostkey/ssh_host_ed25519_key /hostkey/ssh_host_ed25519_key.pub /etc/ssh/ 2>/dev/null || ssh-keygen -A
# Без exec: `exec cmd &` порождает подоболочку, которую exec собой и
# заменяет, то есть это обычный фоновый запуск, но читается как «заменить
# текущий процесс» (то же пояснение есть в start_wp.sh).
/usr/sbin/sshd -D -e "$@" &

# Не поднимаем caddy с плейсхолдерными кредами. Гард `!empty(naive.pass)` есть в
# restartNaive(), но на ЭТОТ путь он не распространялся: контейнер стартует сам,
# и на свежей установке naive уходил в сеть с угадываемыми «_ __». Поддомен при
# этом не секрет — certbot добавляет -d np.<domain>, то есть имя публикуется в
# Certificate Transparency.
if grep -qE '^[[:space:]]*basic_auth[[:space:]]+(CHANGEME[[:space:]]+CHANGEME|_[[:space:]]+__)[[:space:]]*$' /config/Caddyfile; then
    echo "naive: basic_auth не настроен (плейсхолдер) — caddy не запущен, задайте логин/пароль в боте" >> /logs/caddy
fi
exec /bin/sh /service_supervisor.sh supervise np
