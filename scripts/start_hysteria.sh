#!/bin/sh
cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
# Без exec: `exec cmd &` порождает подоболочку, которую exec собой и
# заменяет, то есть это обычный фоновый запуск, но читается как «заменить
# текущий процесс» (то же пояснение есть в start_wp.sh).
/usr/sbin/sshd -D -e "$@" &
# Повторное включение модуля не перезапускает PHP и его общий init.
# Ядро само проверяет сохранённую конфигурацию и отвергает пустой пароль.
if [ -s /config/hysteria.yaml ]; then
    hysteria server -c /config/hysteria.yaml </dev/null >>/logs/hysteria 2>&1 &
fi
tail -f /dev/null
