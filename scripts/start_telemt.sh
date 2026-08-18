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

# Бинарь поднимает сам бот (restartTelemt) после записи telemt.toml, поэтому
# здесь только держим контейнер живым.
tail -f /dev/null
