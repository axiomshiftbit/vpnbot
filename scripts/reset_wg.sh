#!/bin/sh
INTERFACE=$(route 2>/dev/null | grep '^default' | grep -o '[^ ]*$')
# route (net-tools) может отсутствовать — берём дефолтный интерфейс через ip.
[ -z "$INTERFACE" ] && INTERFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
# Тип стека (wg/awg) берём у ПОДНЯТОГО wg0, а не из /pac.json. Жёсткий wg-quick
# поднимал туннель обычным wg даже при amnezia=1 — бот при следующем restartWG
# звал awg-quick down над чужим интерфейсом.
#
# Почему не jq по /pac.json, как в start_wg.sh: файл прокинут в контейнер
# bind-mount'ом на ФАЙЛ, а setPacConf() пишет во временный файл и делает
# rename() — инод меняется, и внутри работающего контейнера /pac.json навсегда
# застывает на той версии, что была на момент старта (на рабочем сервере там осталось «{}»).
# start_wg.sh это не задевает — он читает один раз при старте, когда монтирование
# только что разрешилось; reset_wg.sh же зовётся по живому, и pac.json ему врёт.
# wg/awg — разные netlink-семейства, поэтому `wg show wg0` на amneziawg-интерфейсе
# возвращает ошибку, и наоборот: это надёжный признак (проверено на обоих
# инстансах). Если wg0 не поднят — падаем на pac.json с оговоркой выше.
if awg show wg0 >/dev/null 2>&1; then
    WG=awg
elif wg show wg0 >/dev/null 2>&1; then
    WG=wg
elif [ "$HOSTNAME" = "wireguard1" ]; then
    [ "$(jq -r '.wg1_amnezia // 0' /pac.json 2>/dev/null)" = "1" ] && WG=awg || WG=wg
else
    [ "$(jq -r '.amnezia // 0' /pac.json 2>/dev/null)" = "1" ] && WG=awg || WG=wg
fi
PRIVATEKEY=$($WG genkey | tee /etc/wireguard/privatekey)
echo "[Interface]" > /etc/wireguard/wg0.conf
echo "PrivateKey = $PRIVATEKEY" >> /etc/wireguard/wg0.conf
echo "Address = $1" >> /etc/wireguard/wg0.conf
echo "ListenPort = $2" >> /etc/wireguard/wg0.conf
echo "PostUp = iptables -t nat -A POSTROUTING --destination 10.10.0.5 -j ACCEPT;iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE" >> /etc/wireguard/wg0.conf
echo "PostDown = iptables -t nat -D POSTROUTING --destination 10.10.0.5 -j ACCEPT;iptables -t nat -D POSTROUTING -o $INTERFACE -j MASQUERADE" >> /etc/wireguard/wg0.conf
$WG-quick down wg0
$WG-quick up wg0
