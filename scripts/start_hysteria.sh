#!/bin/sh
cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
# Без exec: `exec cmd &` порождает подоболочку, которую exec собой и
# заменяет, то есть это обычный фоновый запуск, но читается как «заменить
# текущий процесс» (то же пояснение есть в start_wp.sh).
/usr/sbin/sshd -D -e "$@" &
if [ -f /hysteria_service.py ]; then
    # The container must stop with its supervisor: a surviving core would keep
    # existing sessions after the quota/expiry worker had died.
    exec python3 /hysteria_service.py
fi
# Old images may run the legacy shared password until upgraded. They must not
# silently ignore already configured personal restrictions.
if [ -s /config/hysteria/users.json ]; then
    echo 'Hysteria: update the image to run personal access controls' >&2
    exit 1
fi
# Повторное включение модуля не перезапускает PHP и его общий init.
# Ядро само проверяет сохранённую конфигурацию и отвергает пустой пароль.
if [ -s /config/hysteria.yaml ]; then
    hysteria server -c /config/hysteria.yaml </dev/null >>/logs/hysteria 2>&1 &
fi
tail -f /dev/null
