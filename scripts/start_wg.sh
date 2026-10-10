#!/bin/bash
# Журнал обоих инстансов доступен в меню бота, включая запуск tun2socks.
HOSTNAME="${HOSTNAME:-$(hostname)}"
mkdir -p /logs
if [ "$HOSTNAME" = "wireguard1" ]; then
    exec >>/logs/wireguard1 2>&1
else
    exec >>/logs/wireguard 2>&1
fi
INTERFACE_VPN="tun0"
TABLE_ID=100

# Пустой ADDRESS (нет WGADDRESS/WG1ADDRESS в .env, затёрт в override.env) —
# это не «поднимемся как-нибудь», а тихая УТЕЧКА: `ip rule from ""` и правило
# RETURN не встают (оба под `|| true`), а MASQUERADE ниже остаётся, и трафик
# клиентов выходит напрямую с публичного IP сервера мимо tun0/xray. Плюс в
# wg0.conf уезжает «Address = », wg-quick падает, а контейнер живёт через
# `tail -f /dev/null` и в меню бота выглядит зелёным. Падаем честно.
if [ -z "$ADDRESS" ]; then
    echo "FATAL: ADDRESS is empty (WGADDRESS/WG1ADDRESS not set) — refusing to start" >&2
    exit 1
fi

cat /ssh/key.pub > /root/.ssh/authorized_keys
# Ключ узла выдаёт контейнер php (ssh/hosts/<сервис>): бот сверяет его
# отпечаток перед каждой командой. Случайный ключ бот не примет.
# Каталог подключён, а ключа ещё нет — php не успел его создать: ждём.
hostkey_wait=0; while [ -d /hostkey ] && [ ! -s /hostkey/ssh_host_ed25519_key.pub ] && [ "$hostkey_wait" -lt 60 ]; do sleep 1; hostkey_wait=$((hostkey_wait + 1)); done
cp -p /hostkey/ssh_host_ed25519_key /hostkey/ssh_host_ed25519_key.pub /etc/ssh/ 2>/dev/null || ssh-keygen -A
# Без exec: `exec cmd &` порождает подоболочку, которую exec собой и
# заменяет, то есть это обычный фоновый запуск, но читается как «заменить
# текущий процесс» (то же пояснение есть в start_wp.sh).
/usr/sbin/sshd -D -e "$@" &

INTERFACE=$(route 2>/dev/null | grep '^default' | grep -o '[^ ]*$')
# route (net-tools) может отсутствовать или ещё не видеть default (гонка на
# старте сети контейнера) — берём дефолтный интерфейс через ip. Пустой
# INTERFACE означал MASQUERADE, который не встал: туннель поднимается, клиенты
# подключаются, наружу трафик не ходит — и ни строки в логе, потому что
# `2>/dev/null || true` гасил и вывод, и код возврата.
[ -z "$INTERFACE" ] && INTERFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
[ -n "$INTERFACE" ] || echo "WARN: default interface not detected — NAT rules will NOT be applied" >&2
# -f обязателен: если хостового config/wg0.conf нет, docker создаёт на его
# месте КАТАЛОГ, и `wc -c <` падает, а `[ "" -eq 0 ]` — это ошибка ash.
if [ ! -f /etc/wireguard/wg0.conf ] || [ "$(wc -c < /etc/wireguard/wg0.conf)" -eq 0 ]
then
    PRIVATEKEY=$(umask 077; wg genkey | tee /etc/wireguard/privatekey)
    echo "[Interface]" > /etc/wireguard/wg0.conf
    echo "PrivateKey = $PRIVATEKEY" >> /etc/wireguard/wg0.conf
    echo "Address = $ADDRESS" >> /etc/wireguard/wg0.conf
    echo "ListenPort = 51820" >> /etc/wireguard/wg0.conf
else
    # Одной операцией во временный файл, и только потом — по месту.
    # Раньше здесь были два файла-полуфабриката (change_port/change_address) в
    # корне контейнера: WORKDIR в wireguard.dockerfile не задан. Проблем было
    # две. Первая: `> /etc/wireguard/wg0.conf` усекает ХОСТОВЫЙ config/wg0.conf
    # (файловый bind-mount) ДО запуска cat, поэтому сбой sed или ENOSPC на /
    # обнулял файл вместе с приватным ключом сервера и всеми пирами —
    # восстановить нечем, clients.json серверный ключ не хранит. Вторая:
    # полуфабрикаты переживают docker restart, и при сбое первого sed в конфиг
    # молча возвращалась прошлая версия (удалённые клиенты воскресали).
    # cat > , а не mv: инод прибит bind-mount'ом, rename его подменит и
    # контейнер навсегда останется на старом файле.
    tmp=$(mktemp) || exit 1
    if [ -n "$ADDRESS" ]; then
        sed -e 's/ListenPort = [0-9]\+/ListenPort = 51820/' \
            -e "s|Address = [0-9./ ]\+|Address = $ADDRESS|" \
            /etc/wireguard/wg0.conf > "$tmp"
    else
        # Пустой $ADDRESS затёр бы адрес интерфейса — правим только порт.
        sed -e 's/ListenPort = [0-9]\+/ListenPort = 51820/' /etc/wireguard/wg0.conf > "$tmp"
    fi
    [ -s "$tmp" ] && cat "$tmp" > /etc/wireguard/wg0.conf
    rm -f "$tmp"
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
# HOSTNAME кладёт в окружение docker, сама busybox ash её не заводит: при
# ручном запуске через ssh переменная могла не пробрасываться, и скрипт брал
# ключи нулевого инстанса (amnezia вместо wg1_amnezia), поднимая не тот стек.
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
# tun2socks 2.7 использует pflag: длинным параметрам нужны два дефиса.
# С одним дефисом -device/-proxy разбираются как -d evice / -p roxy.
tun2socks --device "$INTERFACE_VPN" --proxy socks5://xr:10808 &

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
