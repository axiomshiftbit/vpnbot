#!/bin/sh
# POSIX-форма вместо [[ ]]: скрипт запускается как ["CMD","/bin/sh", …] и
# работает лишь потому, что busybash alpine собран с ASH_BASH_COMPAT. Переезд
# php-образа на debian-базу (как раньше было у tt) означал бы healthcheck с
# кодом 127, вечный unhealthy у php — и остановку всех, кто зависит от него по
# condition: service_healthy.
[ -f /start ] && [ -s /ssh/key.pub ] || exit 1
# Сам маркер polling остаётся на диске и после аварии Unit/FreeUnit.
# Проверяем живой control API; его сокет никогда не публикуется в сеть.
exec curl --fail --silent --show-error --max-time 3 \
    --unix-socket /var/run/control.unit.sock http://localhost/status >/dev/null
