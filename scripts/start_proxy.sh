#!/bin/sh
cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
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
mkdir -p /logs
nohup setsid sslocal -v -c /config.json </dev/null >>/logs/shadowsocks_proxy 2>&1 &
tail -f /dev/null
