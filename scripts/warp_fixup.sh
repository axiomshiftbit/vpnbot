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

# Режим up: поднять туннель и дождаться РЕАЛЬНОГО рукопожатия (`wg-quick up`
# успешен и без ответа endpoint). Одна реализация для сторожа start_wp.sh и
# кнопок бота. Cloudflare принимает WARP WireGuard на нескольких UDP-портах;
# некоторые сети (например, у хостера) режут 2408 — тогда профиль переводится
# на следующий отвечающий порт и остаётся на нём.
[ "${1:-}" = up ] || exit 0
set +e
WGCF_IF="$(basename "$WGCF_CONF" .conf)"
handshake() {
    wg-quick up "$WGCF_CONF" || return 1
    # Служебный порт WireGuard отделён от SOCKS relay и не опубликован.
    if ! wg set "$WGCF_IF" listen-port 51820; then
        wg-quick down "$WGCF_CONF" 2>/dev/null || true
        return 1
    fi
    i=0
    while [ "$i" -lt 15 ]; do
        hs=$(wg show "$WGCF_IF" latest-handshakes 2>/dev/null | awk '{print $2}' | sort -n | tail -1)
        if [ -n "$hs" ] && [ "$hs" -gt 0 ] 2>/dev/null; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    # Интерфейс создаётся до handshake: не оставляем его после неудачи,
    # иначе сторож принял бы его за готовый туннель.
    wg-quick down "$WGCF_CONF" 2>/dev/null || true
    return 1
}
set_port() {
    # В профиле закрытый ключ: временная копия только для root.
    tmp="$WGCF_CONF.port.$$"
    if ! (umask 077; sed -E "s/^(Endpoint *= *.+):[0-9]+[[:space:]]*$/\1:$1/" "$WGCF_CONF" > "$tmp") || [ ! -s "$tmp" ]; then
        rm -f "$tmp"
        return 1
    fi
    cat "$tmp" > "$WGCF_CONF"
    rm -f "$tmp"
}
# Порт, выбранный администратором в боте (официальные порты Cloudflare WARP):
# только он, без перебора. Без выбора — автоматический перебор ниже.
fixed=$(jq -r '.warp_port // empty' "${WARP_PAC:-/config/pac.json}" 2>/dev/null || true)
case "$fixed" in
    2408|500|1701|4500)
        set_port "$fixed" || exit 1
        handshake && exit 0
        echo "[warp] no handshake on the selected UDP $fixed"
        exit 1
        ;;
esac
current=$(sed -n 's/^Endpoint *= *.*:\([0-9][0-9]*\)[[:space:]]*$/\1/p' "$WGCF_CONF" | head -n 1)
handshake && exit 0
[ -n "$current" ] || exit 1
for port in 2408 500 1701 4500; do
    [ "$port" = "$current" ] && continue
    set_port "$port" || exit 1
    echo "[warp] no handshake on UDP $current, trying endpoint port $port"
    if handshake; then
        echo "[warp] endpoint port $port answers"
        exit 0
    fi
    current=$port
done
exit 1
