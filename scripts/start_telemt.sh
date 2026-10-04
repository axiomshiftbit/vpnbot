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

state() { python3 /telemt_state.py "$@" 2>>/logs/telemt; }
state_watch=
watch_state() {
    if command -v python3 >/dev/null && [ -f /telemt_state.py ]; then
        if [ -z "$state_watch" ] || ! kill -0 "$state_watch" 2>/dev/null; then
            python3 /telemt_state.py watch >/dev/null 2>>/logs/telemt &
            state_watch=$!
        fi
    fi
}
stop_core() {
    if command -v python3 >/dev/null && [ -f /telemt_state.py ]; then
        state stop >/dev/null
    else
        # Совместимость до обновления образа; квоты требуют нового helper.
        pkill -TERM -x telemt 2>/dev/null || true
        i=0
        while pgrep -x telemt >/dev/null && [ "$i" -lt 150 ]; do
            sleep 0.2; i=$((i+1))
        done
        ! pgrep -x telemt >/dev/null
    fi
}
shutdown() {
    trap '' TERM INT
    if [ -n "$state_watch" ]; then kill -TERM "$state_watch" 2>/dev/null || true; fi
    stop_result=0
    (flock -x 9 && stop_core) 9>/logs/.lock.telemt || stop_result=$?
    if [ -n "$state_watch" ]; then wait "$state_watch" 2>/dev/null || true; fi
    exit "$stop_result"
}
trap shutdown TERM INT

# Общая с restartTelemt блокировка исключает запуск старого TOML во время
# ротации доступа или пересоздания контейнера. Дочернее ядро не наследует lock.
# Отсутствующий service-enabled совместим с установками до выключателя.
while :; do
    watch_state
    (
        flock -x 9 || exit 1
        enabled=1
        if [ -e /telemt/service-enabled ]; then
            enabled=$(cat /telemt/service-enabled 2>/dev/null) || enabled=0
        fi
        if [ "$enabled" = 1 ] && [ -s /telemt/telemt.toml ] \
            && grep -q '^show_link = \["' /telemt/telemt.toml; then
            if ! pgrep -x telemt >/dev/null; then
                if command -v python3 >/dev/null && [ -f /telemt_state.py ]; then
                    state prepare >/dev/null || exit 1
                elif grep -q '^\[access.user_data_quota\]' /telemt/telemt.toml; then
                    echo 'TeleMT: quota support requires the updated image' >&2
                    exit 1
                fi
                telemt run --data-path /telemt/data /telemt/telemt.toml </dev/null >>/logs/telemt 2>&1 9>&- &
            fi
        else
            if pgrep -x telemt >/dev/null; then stop_core; fi
        fi
    ) 9>/logs/.lock.telemt
    sleep 1 &
    wait "$!"
done
