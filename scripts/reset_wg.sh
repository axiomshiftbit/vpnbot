#!/bin/sh
INTERFACE=$(route 2>/dev/null | grep '^default' | grep -o '[^ ]*$')
# route (net-tools) может отсутствовать — берём дефолтный интерфейс через ip.
[ -z "$INTERFACE" ] && INTERFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
# Тип стека определяем так же, как start_wg.sh: инстанс по $HOSTNAME, режим по
# своему ключу в pac.json. Жёсткий wg-quick поднимал туннель обычным wg даже
# при amnezia=1 — бот при следующем restartWG звал awg-quick down над чужим
# интерфейсом.
if [ "$HOSTNAME" = "wireguard1" ]; then
    AMNEZIA=$(jq -r '.wg1_amnezia // 0' /pac.json 2>/dev/null)
else
    AMNEZIA=$(jq -r '.amnezia // 0' /pac.json 2>/dev/null)
fi
if [ "$AMNEZIA" = "1" ]; then
    WG=awg
else
    WG=wg
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
