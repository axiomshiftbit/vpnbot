#!/bin/sh
# Идемпотентные фиксапы wgcf-профиля. ОБЩИЙ скрипт для start_wp.sh (каждый
# старт контейнера) и кнопки «set key» бота (addWarpPlus, после wgcf generate).
# Раньше бот дублировал sed'ы у себя и разошёлся с ними (не вырезал DNS) —
# правки вносить только здесь.
set -e

WGCF_CONF="${WGCF_CONF:-/etc/warp/wgcf-profile.conf}"

# IPv6 вырезаем ИЗ списков, а не строки целиком: wgcf >= 2.2.31 пишет
# "Address = <v4>, <v6>" и "AllowedIPs = 0.0.0.0/0, ::/0" ОДНОЙ строкой —
# старые delete-sed'ы (/^Address.*:/d) сносили вместе с v6 и v4-часть,
# оставляя интерфейс без адреса и маршрутов. Отдельные чисто-v6 строки
# (двухстрочный формат старых wgcf <= 2.2.22) по-прежнему удаляем.
for key in Address AllowedIPs; do
    # ", <v6>" в середине/конце списка
    sed -i "/^$key[[:space:]]*=/s/,[[:space:]]*[^,]*:[^,]*//g" "$WGCF_CONF"
    # "<v6>, " в начале списка
    sed -i "/^$key[[:space:]]*=/s/=[[:space:]]*[^,]*:[^,]*,[[:space:]]*/= /" "$WGCF_CONF"
    # строка из одного v6-значения
    sed -i "/^$key[[:space:]]*=[^,]*:[^,]*$/d" "$WGCF_CONF"
done

# DNS= убираем: resolv.conf в контейнере пишет start_wp.sh сам, а resolvconf
# из openresolv 3.17.4 (alpine edge) в docker падает и роняет wg-quick up.
sed -i '/^DNS[[:space:]]*=/d' "$WGCF_CONF"

# Отдельный внутренний порт туннеля: случайный порт может попасть в диапазон
# SOCKS relay, где INPUT пропускает только прокси-клиентов. Профиль используют
# также кнопки ON, смена ключа и восстановление старой резервной копии.
sed -i '/^ListenPort[[:space:]]*=/d; /^\[Interface\]/a ListenPort = 51820' "$WGCF_CONF"

# Держит handshake живым без полезного трафика; по возрасту handshake
# warp_probe.sh судит о здоровье туннеля, когда curl в образе отсутствует.
grep -q '^PersistentKeepalive' "$WGCF_CONF" || \
    sed -i '/^\[Peer\]/a PersistentKeepalive = 25' "$WGCF_CONF"
