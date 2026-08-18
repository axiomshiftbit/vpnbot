#!/bin/sh
# POSIX-форма вместо [[ ]]: скрипт запускается как ["CMD","/bin/sh", …] и
# работает лишь потому, что busybash alpine собран с ASH_BASH_COMPAT. Переезд
# php-образа на debian-базу (как уже сделано для tt) означал бы healthcheck с
# кодом 127, вечный unhealthy у php — и остановку всех, кто зависит от него по
# condition: service_healthy.
if [ -f "/start" ] && [ -f "/ssh/key.pub" ] && [ -s "/ssh/key.pub" ]; then
    exit 0;
else
    exit 1;
fi
