#!/bin/sh
# Запуск сборки из systemd-юнита (scripts/vpnbot.service).
#
# Раньше вся логика висела одной строкой в ExecStart:
#   IP=$(curl https://ipinfo.io/ip) VER=$(git describe --tags) docker compose …
# и это не косметика. $IP уходит в SAN серверного сертификата strongSwan
# (start_ipsec.sh), в `id =` conn ikev2 и в CN self-signed серта (start_php.sh),
# то есть в идентити, по которой коннектятся нативные клиенты IKEv2.
#
# Что было не так:
#   - curl без -f: тело ответа 4xx/5xx (HTML страницы ошибки, текст rate-limit)
#     попадало в $IP как валидное значение → серт с мусорным SAN, клиенты рвут
#     соединение на несовпадении IDr, и причина не видна нигде, кроме swanctl;
#   - без --max-time: недоступная сеть на раннем бут-этапе + TimeoutStartSec=0
#     означали, что юнит висит на загрузке неограниченно долго;
#   - без фолбэка: у makefile он есть (hostname -I), а systemd шёл мимо make;
#   - git describe --tags без --always: в клоне без тегов $VER пустой, имена
#     контейнеров схлопываются в «php-», «wg-» и up --force-recreate конфликтует
#     сам с собой. В makefile это давно исправлено, юнит с ним разъехался.
cd "$(dirname "$0")/.." || exit 1

IP=$(curl -fsS --max-time 5 https://ipinfo.io/ip 2>/dev/null | tr -dc '0-9.')
# Форма «хоть сколько-то похоже на IPv4»: tr выше уже вырезал всё, кроме цифр и
# точек, поэтому от HTML-страницы осталась бы строка без четырёх групп.
case "$IP" in
    *.*.*.*) ;;
    *) IP='' ;;
esac
[ -n "$IP" ] || IP=$(hostname -I 2>/dev/null | awk '{print $1}')

VER=$(git describe --tags --always 2>/dev/null || echo local)
[ -n "$VER" ] || VER=local

touch ./override.env ./docker-compose.override.yml

exec env IP="$IP" VER="$VER" \
    docker compose --env-file ./.env --env-file ./override.env up -d --force-recreate
