#!/bin/sh
set -e
# Маркер предыдущего запуска не подтверждает готовность нового процесса.
rm -f /start
# Пара ключей пересоздавалась при КАЖДОМ старте php, а authorized_keys в
# остальных контейнерах обновляется только их собственным start_*.sh. Один
# `docker restart php` (его же провоцирует healthcheck) — и у php новый
# приватный ключ, а у wg/xr/ng/ss/ovpn/ipsec старый публичный: все ssh-операции
# бота начинали падать, пока не пересоздашь каждый контейнер. Симптом в меню —
# «всё выключено», причина ниоткуда не видна. Генерируем только при отсутствии.
if [ ! -s /ssh/key ] || [ ! -s /ssh/key.pub ]; then
    rm -f /ssh/key /ssh/key.pub
    ssh-keygen -m PEM -t rsa -f /ssh/key -N ''
fi
# Публичный ключ отдельным каталогом для контейнеров, которые терминируют
# НЕДОВЕРЕННЫЙ клиентский трафик (wg, wg1). Им нужен только key.pub — положить
# его в authorized_keys, чтобы бот мог зайти внутрь. Раньше туда монтировался
# весь /ssh, то есть вместе с ПРИВАТНЫМ ключом, а он даёт root-SSH во все
# остальные контейнеры (xr, ng, php…): одна дыра в wireguard-контейнере
# превращалась в компрометацию всей сборки.
mkdir -p /ssh/pub
cp /ssh/key.pub /ssh/pub/key.pub
chmod 0644 /ssh/pub/key.pub
# Обновление образа не должно менять сертификат существующих клиентов.
# Отсутствующий или истёкший сертификат создаётся при первоначальном запуске.
if [ ! -s /certs/self_private ] || [ ! -s /certs/self_public ] \
    || ! openssl x509 -checkend 0 -noout -in /certs/self_public >/dev/null 2>&1; then
    openssl req -newkey rsa:2048 -sha256 -nodes -x509 -days 365 -keyout /certs/self_private -out /certs/self_public -subj "/C=NN/ST=N/L=N/O=N/CN=$IP"
fi
# Control API unit — ТОЛЬКО unix-сокет. Аутентификации у него нет by design,
# поэтому `--control 0.0.0.0:8080` означал: любой контейнер сети default ходит
# на 10.10.0.7:8080 и через PUT /config объявляет приложение с произвольным
# executable от root (в unit.json оба приложения — user: root). Достижимо это
# было и с VPN-клиента (freedom-outbound явно allow'ит 10.10.0.0/16), и с хоста
# через проброс 127.0.0.1:8081, который убран из docker-compose.
# controlUnit() в bot.php и так ходит именно в этот сокет — до сих пор он не
# существовал, и функция всегда отвечала «lost connect to unit».
CONTROL_SOCK=/var/run/control.unit.sock
if [ -f "/ssh/key.pub" ] && [ -s "/ssh/key.pub" ]; then
    unitd --control "unix:$CONTROL_SOCK" --log /logs/unit_error
    # unitd демонизируется, сокет появляется не мгновенно: без ожидания
    # первый же PUT уходил в никуда и контейнер поднимался без конфигурации.
    i=0
    while [ ! -S "$CONTROL_SOCK" ] && [ "$i" -lt 50 ]; do
        sleep 0.1
        i=$((i + 1))
    done
    # Неверный JSON, отсутствующий PHP-модуль или недоступный control API
    # должны остановить запуск: polling без работающего HTTP вводит в заблуждение.
    curl --fail --silent --show-error --max-time 10 --unix-socket "$CONTROL_SOCK" \
        -X PUT --data-binary @/config/unit.json http://localhost/config
    exec php init.php
else
    exit 1;
fi
