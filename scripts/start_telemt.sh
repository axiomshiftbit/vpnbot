#!/bin/sh
cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
# Без exec: `exec cmd &` порождает подоболочку, которую exec собой и
# заменяет, то есть это обычный фоновый запуск, но читается как «заменить
# текущий процесс» (то же пояснение есть в start_wp.sh).
/usr/sbin/sshd -D -e "$@" &

# /telemt — bind-mount конфига (config/telemt). data/ хранит replay-кэш и
# fake-сертификаты telemt. /logs — для просмотра журнала в боте.
mkdir -p /telemt/data /logs
[ -f /logs/telemt ] || : > /logs/telemt

# Общая с restartTelemt блокировка исключает запуск старого TOML во время
# ротации доступа или пересоздания контейнера. Дочернее ядро не наследует lock.
# Отсутствующий service-enabled совместим с установками до выключателя.
while :; do
    (
        flock -x 9 || exit 1
        enabled=1
        if [ -e /telemt/service-enabled ]; then
            enabled=$(cat /telemt/service-enabled 2>/dev/null) || enabled=0
        fi
        if [ "$enabled" = 1 ] && [ -s /telemt/telemt.toml ] \
            && grep -q '^show_link = \["' /telemt/telemt.toml; then
            if ! pgrep -x telemt >/dev/null; then
                telemt run --data-path /telemt/data /telemt/telemt.toml </dev/null >>/logs/telemt 2>&1 9>&- &
            fi
        else
            pkill -9 -x telemt 2>/dev/null || true
        fi
    ) 9>/logs/.lock.telemt
    sleep 1
done
