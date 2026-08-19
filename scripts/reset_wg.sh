#!/bin/sh
# РУЧНОЙ инструмент: пересоздать ключ инстанса и поднять wg0 заново
# (`sh /reset_wg.sh <Address> <ListenPort>` внутри контейнера). Из бота НЕ
# вызывается — restartWG() пишет конфиг и делает {wg|awg}-quick down/up сам.
# Скрипт смонтирован в оба wg-контейнера и обязан оставаться
# инстанс-нейтральным: тип стека определяется по живому wg0/$HOSTNAME (ниже).
INTERFACE=$(route 2>/dev/null | grep '^default' | grep -o '[^ ]*$')
# route (net-tools) может отсутствовать — берём дефолтный интерфейс через ip.
[ -z "$INTERFACE" ] && INTERFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
# Тип стека (wg/awg) берём у ПОДНЯТОГО wg0, а не из /pac.json. Жёсткий wg-quick
# поднимал туннель обычным wg даже при amnezia=1 — бот при следующем restartWG
# звал awg-quick down над чужим интерфейсом.
#
# wg/awg — разные netlink-семейства, поэтому `wg show wg0` на amneziawg-интерфейсе
# возвращает ошибку, и наоборот: это надёжный признак (проверено на обоих
# инстансах). Если wg0 не поднят — падаем на pac.json.
#
# pac.json читаем через КАТАЛОГ (/config): bind-mount на файл прибит к иноду, а
# setPacConf() пишет tmp + rename(), поэтому старый /pac.json внутри контейнера
# застывает на версии момента создания контейнера и врёт. /pac.json оставлен
# фолбэком для контейнеров со старым docker-compose.yml.
PAC=/config/pac.json
[ -f "$PAC" ] || PAC=/pac.json
# HOSTNAME кладёт в окружение docker, сама busybox ash её не заводит: при
# ручном запуске через ssh переменная могла не пробрасываться, и скрипт брал
# ключи нулевого инстанса (amnezia вместо wg1_amnezia), поднимая не тот стек.
HOSTNAME="${HOSTNAME:-$(hostname)}"
if awg show wg0 >/dev/null 2>&1; then
    WG=awg
elif wg show wg0 >/dev/null 2>&1; then
    WG=wg
elif [ "$HOSTNAME" = "wireguard1" ]; then
    [ "$(jq -r '.wg1_amnezia // 0' "$PAC" 2>/dev/null)" = "1" ] && WG=awg || WG=wg
else
    [ "$(jq -r '.amnezia // 0' "$PAC" 2>/dev/null)" = "1" ] && WG=awg || WG=wg
fi
# $1 и $2 попадают в wg0.conf, а строка PostUp исполняется wg-quick как
# КОМАНДА ОТ ROOT при каждом подъёме интерфейса — и остаётся в хостовом
# config/wg0.conf (bind-mount). Адрес вида «10.0.1.1/24; curl …|sh» давал бы
# закреплённое выполнение произвольного кода. Скрипт заявлен ручным, но лежит
# смонтированным в обоих wg-контейнерах, то есть доступен всякому, кто получил
# shell в контейнере с недоверенным клиентским трафиком.
case "$1" in
    [0-9]*.[0-9]*.[0-9]*.[0-9]*/[0-9]*) ;;
    *) echo "usage: reset_wg.sh <Address/CIDR> <ListenPort>" >&2; exit 1 ;;
esac
case "$1" in
    *[!0-9./]*) echo "FATAL: address contains unexpected characters" >&2; exit 1 ;;
esac
case "$2" in
    ''|*[!0-9]*) echo "FATAL: port must be a number" >&2; exit 1 ;;
esac

PRIVATEKEY=$(umask 077; $WG genkey | tee /etc/wireguard/privatekey)
echo "[Interface]" > /etc/wireguard/wg0.conf
echo "PrivateKey = $PRIVATEKEY" >> /etc/wireguard/wg0.conf
echo "Address = $1" >> /etc/wireguard/wg0.conf
echo "ListenPort = $2" >> /etc/wireguard/wg0.conf
# RETURN для клиентской подсети обязан стоять ПЕРЕД MASQUERADE: он уводит
# трафик клиентов в tun0/xray, иначе тот выйдет напрямую с публичного IP —
# туннель «работает», но это утечка. start_wg.sh ставит правило один раз при
# старте контейнера, а здесь его не было вовсе; -C || -I делает восстановление
# идемпотентным, поэтому дубли не копятся при каждом wg-quick up.
# -C перед -A у ВСЕХ трёх правил. RETURN был идемпотентным, а ACCEPT и
# MASQUERADE добавлялись через голый -A: PostDown снимает по одной копии и
# только при штатном down, а бот дёргает down/up на каждое добавление и
# удаление клиента — цепочка nat/POSTROUTING росла линейно, и отличить мусор от
# рабочих правил становилось нельзя.
echo "PostUp = iptables -t nat -C POSTROUTING --destination 10.10.0.5 -j ACCEPT 2>/dev/null || iptables -t nat -A POSTROUTING --destination 10.10.0.5 -j ACCEPT;iptables -t nat -C POSTROUTING -o $INTERFACE -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE;iptables -t nat -C POSTROUTING -s $1 -j RETURN 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s $1 -j RETURN" >> /etc/wireguard/wg0.conf
echo "PostDown = iptables -t nat -D POSTROUTING --destination 10.10.0.5 -j ACCEPT;iptables -t nat -D POSTROUTING -o $INTERFACE -j MASQUERADE" >> /etc/wireguard/wg0.conf
$WG-quick down wg0
$WG-quick up wg0
