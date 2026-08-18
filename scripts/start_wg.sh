#!/bin/bash
INTERFACE_VPN="tun0"
TABLE_ID=100

cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
exec /usr/sbin/sshd -D -e "$@" &

INTERFACE=$(route | grep '^default' | grep -o '[^ ]*$')
if [ "$(wc -c < /etc/wireguard/wg0.conf)" -eq 0 ]
then
    PRIVATEKEY=$(wg genkey | tee /etc/wireguard/privatekey)
    echo "[Interface]" > /etc/wireguard/wg0.conf
    echo "PrivateKey = $PRIVATEKEY" >> /etc/wireguard/wg0.conf
    echo "Address = $ADDRESS" >> /etc/wireguard/wg0.conf
    echo "ListenPort = 51820" >> /etc/wireguard/wg0.conf
else
    sed "s/ListenPort = [0-9]\+/ListenPort = 51820/" /etc/wireguard/wg0.conf > change_port
    sed "s|Address = [0-9\.\/ ]\+|Address = $ADDRESS|" change_port > change_address
    cat change_address > /etc/wireguard/wg0.conf
fi
iptables -t nat -A POSTROUTING --destination 10.10.0.5 -j ACCEPT
iptables -t nat -A POSTROUTING -o "$INTERFACE" -j MASQUERADE
# -f: на рестарте контейнера симлинк уже есть, и голый `ln -s` только шумел
# ошибкой в лог.
ln -sf /etc/wireguard/wg0.conf /etc/amnezia/amneziawg/wg0.conf

# Читаем pac.json через КАТАЛОГ (/config), а не через bind-mount на файл.
# setPacConf() пишет во временный файл и делает rename() — инод меняется, а
# bind-mount на файл прибит к старому иноду, поэтому /pac.json внутри контейнера
# навсегда застывает на версии момента создания контейнера (на рабочем сервере там «{}» при
# 218 КБ на хосте). Из-за этого wireguard1 при каждом рестарте поднимался
# обычным wg-quick, хотя wg1_amnezia=1, и без block_torrent/block_exchange —
# корректное состояние возвращал только следующий restartWG/iptablesWG из бота.
# Монтирование каталога переживает rename; /pac.json оставлен фолбэком на
# случай контейнера, поднятого со старым docker-compose.yml.
PAC=/config/pac.json
[ -f "$PAC" ] || PAC=/pac.json
if [ "$HOSTNAME" = "wireguard1" ]
then
    PFX=wg1_
else
    PFX=
fi
# pac() печатает 1/0: битый или отсутствующий pac.json не должен ронять старт
# сравнением `[ "" -eq 1 ]` — отдаём 0 и поднимаем инстанс в дефолтном виде.
pac() {
    v=$(jq -r ".${PFX}$1 // 0" "$PAC" 2>/dev/null)
    [ "$v" = "1" ] && echo 1 || echo 0
}
# ВАЖЕН ПОРЯДОК: tun0, policy-routing и RETURN для клиентской подсети ставим ДО
# поднятия wg0. Раньше интерфейс поднимался первым, а эти правила — на 15 строк
# ниже: клиент, успевший подключиться в это окно, попадал под MASQUERADE (стр.
# выше) и выходил в интернет НАПРЯМУЮ с публичным IP сервера, мимо tun0/xray.
# Туннель при этом «работал», поэтому утечка была незаметной.
ip tuntap add mode tun dev $INTERFACE_VPN || true
ip addr add 10.255.0.1/24 dev $INTERFACE_VPN || true
ip link set up dev $INTERFACE_VPN
ip rule add from "$ADDRESS" table $TABLE_ID || true
ip route add default dev $INTERFACE_VPN table $TABLE_ID || true
# Служебная сеть docker недостижима для клиентской подсети. Штатно весь
# клиентский трафик уводит в tun0 policy-routing выше, но обе команды идут с
# `|| true`: если правило/маршрут не встали, трафик остаётся в main-таблице,
# где 10.10.0.0/16 — подключённая сеть, и клиент дотягивается до sshd любого
# контейнера, до веб-панели и до control API unit. Хостовый nft это закрывает,
# но /nft в поставку не входит (.gitignore), так что дублируем здесь.
# Внутренний DNS (10.10.0.5) обязан остаться доступным — на нём AdGuard.
# -C перед -I: без него правила копились бы на каждом рестарте контейнера.
if [ -n "$ADDRESS" ]; then
    iptables -C FORWARD -s "$ADDRESS" -d 10.10.0.5 -j ACCEPT 2>/dev/null \
        || iptables -I FORWARD 1 -s "$ADDRESS" -d 10.10.0.5 -j ACCEPT
    iptables -C FORWARD -s "$ADDRESS" -d 10.10.0.0/16 -j REJECT 2>/dev/null \
        || iptables -I FORWARD 2 -s "$ADDRESS" -d 10.10.0.0/16 -j REJECT
fi
iptables -A FORWARD -i $INTERFACE_VPN -j ACCEPT
iptables -A FORWARD -o $INTERFACE_VPN -j ACCEPT
iptables -t nat -I POSTROUTING 1 -s "$ADDRESS" -j RETURN
tun2socks -device $INTERFACE_VPN -proxy socks5://xr:10808 &

if [ "$(pac amnezia)" -eq 1 ]
then
    awg-quick up wg0
else
    wg-quick up wg0
fi
# block_*.sh вставляют правила через -I (в голову FORWARD), а ACCEPT для tun0
# выше добавлен через -A (в хвост) — фильтры торрента проверяются раньше и не
# обходятся им, порядок как был.
if [ "$(pac blocktorrent)" -eq 1 ]
then
    sh /block_torrent.sh
fi
if [ "$(pac exchange)" -eq 1 ]
then
    sh /block_exchange.sh
fi

tail -f /dev/null
