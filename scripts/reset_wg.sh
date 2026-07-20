#!/bin/sh
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
if awg show wg0 >/dev/null 2>&1; then
    WG=awg
elif wg show wg0 >/dev/null 2>&1; then
    WG=wg
elif [ "$HOSTNAME" = "wireguard1" ]; then
    [ "$(jq -r '.wg1_amnezia // 0' "$PAC" 2>/dev/null)" = "1" ] && WG=awg || WG=wg
else
    [ "$(jq -r '.amnezia // 0' "$PAC" 2>/dev/null)" = "1" ] && WG=awg || WG=wg
fi
PRIVATEKEY=$($WG genkey | tee /etc/wireguard/privatekey)
echo "[Interface]" > /etc/wireguard/wg0.conf
echo "PrivateKey = $PRIVATEKEY" >> /etc/wireguard/wg0.conf
echo "Address = $1" >> /etc/wireguard/wg0.conf
echo "ListenPort = $2" >> /etc/wireguard/wg0.conf
# RETURN для клиентской подсети обязан стоять ПЕРЕД MASQUERADE: он уводит
# трафик клиентов в tun0/xray, иначе тот выйдет напрямую с публичного IP —
# туннель «работает», но это утечка. start_wg.sh ставит правило один раз при
# старте контейнера, а здесь его не было вовсе; -C || -I делает восстановление
# идемпотентным, поэтому дубли не копятся при каждом wg-quick up.
echo "PostUp = iptables -t nat -A POSTROUTING --destination 10.10.0.5 -j ACCEPT;iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE;iptables -t nat -C POSTROUTING -s $1 -j RETURN 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s $1 -j RETURN" >> /etc/wireguard/wg0.conf
echo "PostDown = iptables -t nat -D POSTROUTING --destination 10.10.0.5 -j ACCEPT;iptables -t nat -D POSTROUTING -o $INTERFACE -j MASQUERADE" >> /etc/wireguard/wg0.conf
$WG-quick down wg0
$WG-quick up wg0
