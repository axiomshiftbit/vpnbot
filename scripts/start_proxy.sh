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
CURRENT_PORT=$(sed -n 's/"server_port": \([0-9]\+\),/\1/p' /config.json | tr -d ' ')
# Пустой порт (битый или пересозданный /config.json) в `-ne` — ошибка ash, а не
# «не равно»: сравниваем только когда там действительно число.
if [ -n "$CURRENT_PORT" ] && [ "$CURRENT_PORT" -ne 443 ]
then
    # Временный файл вместо полуфабриката в корне: /config.json — файловый
    # bind-mount, редирект усекал бы хостовый файл до записи. cat > , не mv.
    tmp=$(mktemp) || exit 1
    sed 's/"server_port": [0-9]\+/"server_port": 8388/' /config.json > "$tmp"
    [ -s "$tmp" ] && cat "$tmp" > /config.json
    rm -f "$tmp"
fi
exec /bin/sh /service_supervisor.sh supervise proxy
