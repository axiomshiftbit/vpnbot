#!/bin/sh
# OpenVPN Community Edition entrypoint.
# - Каждый PKI-файл создаётся независимо (идемпотентно): если предыдущий
#   запуск упал между build-ca и genkey, ta.key теперь догенерируется,
#   а не игнорируется намертво из-за существующего ca.crt.
# - server.conf пишется только если отсутствует — бот правит port/proto/
#   isolation in-place.
# - Runs sshd так же, как в других контейнерах.
# - openvpn в фоне; контейнер живёт через tail. Бот рестартит через
#   `pkill openvpn; ssh ovpn 'openvpn --config ...'`.

# Намеренно БЕЗ `set -e`: easyrsa иногда возвращает non-zero при
# существующих артефактах (например при повторном build-ca), что
# раньше убивало контейнер. Ошибки детектируем через проверку
# наличия файлов на следующем шаге.

cat /ssh/key.pub > /root/.ssh/authorized_keys 2>/dev/null || true
# Ключ узла выдаёт контейнер php (ssh/hosts/<сервис>): бот сверяет его
# отпечаток перед каждой командой. Случайный ключ бот не примет.
# Каталог подключён, а ключа ещё нет — php не успел его создать: ждём.
hostkey_wait=0; while [ -d /hostkey ] && [ ! -s /hostkey/ssh_host_ed25519_key.pub ] && [ "$hostkey_wait" -lt 60 ]; do sleep 1; hostkey_wait=$((hostkey_wait + 1)); done
{ cp -p /hostkey/ssh_host_ed25519_key /hostkey/ssh_host_ed25519_key.pub /etc/ssh/ 2>/dev/null || ssh-keygen -A; } >/dev/null 2>&1 || true
/usr/sbin/sshd -D -e "$@" &

INTERFACE=$(route 2>/dev/null | grep '^default' | grep -o '[^ ]*$')
# route (net-tools) может отсутствовать или ещё не видеть default (гонка на
# старте сети контейнера) — берём дефолтный интерфейс через ip. Пустой
# INTERFACE означал MASQUERADE, который не встал: туннель поднимается, клиенты
# подключаются, наружу трафик не ходит — и ни строки в логе, потому что
# `2>/dev/null || true` гасил и вывод, и код возврата.
[ -z "$INTERFACE" ] && INTERFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
[ -n "$INTERFACE" ] || echo "WARN: default interface not detected — NAT rules will NOT be applied" >&2
# Внутренний listen-порт openvpn ФИКСИРОВАН на 1194: и docker-override
# (host:EXT -> ovpn:1194), и nginx upstream (`server ovpn:1194` в
# upstream.conf, #ovpn-port stream-блок) целятся именно в 1194. OVPNPORT —
# это ВНЕШНИЙ порт (host-side), он используется ботом только для маппинга и
# клиентских .ovpn (remote host:OVPNPORT), но НЕ для bind внутри контейнера.
# Если сюда подставить OVPNPORT, openvpn забиндится не на тот порт и трафик
# из nginx/docker (1194) до него не дойдёт.
PORT=1194
PROTO="${OVPNPROTO:-udp4}"
case "$PROTO" in udp4|tcp4) ;; *) PROTO="udp4" ;; esac
SUBNET="${OVPNSUBNET:-10.8.0.0/24}"
NET=$(echo "$SUBNET" | cut -d/ -f1)
MASK=$(echo "$SUBNET" | awk -F/ '{
    n=$2; for(i=0;i<4;i++){ b=(n>=8?8:n); printf("%s%d", i?".":"", 256-2^(8-b)); n-=b }
}')

PKI=/etc/openvpn/pki
SRV=/etc/openvpn/server.conf
EASYRSA_BIN=/usr/share/easy-rsa/easyrsa
export EASYRSA_PKI="$PKI"
export EASYRSA_BATCH=1
# Дефолты easy-rsa: сертификаты 825 дней, CRL 180 дней. Оба тихо протухают:
# клиенты перестают коннектиться через ~2.3 года, а из-за crl-verify ВСЕ
# новые handshake падают через полгода ("CRL has expired"). 3650 дней = 10
# лет, как у CA.
export EASYRSA_CERT_EXPIRE=3650
export EASYRSA_CRL_DAYS=3650

mkdir -p "$PKI" /etc/openvpn/ccd /etc/openvpn/clients /logs
: >> /logs/openvpn.log
: >> /logs/openvpn-connections.log

# Один inode с Bot::withOvpnPkiLock() в php-контейнере (/logs общий bind
# mount). Без этого selfUpdate мог одновременно с revoke снять/восстановить
# рваный snapshot: crt возвращался в issued/, а index.txt и CRL — уже нет.
exec 8>/logs/.lock.ovpn-pki
if ! flock 8; then
    echo "FATAL: cannot lock OpenVPN PKI" >&2
    exit 1
fi

# Счётчики пишутся hook-ом до допуска клиента и при завершении сессии.
# Ошибка durable storage не разрешает запуск без учёта.
if ! python3 /ovpn_traffic.py --prepare; then
    echo "FATAL: OpenVPN traffic accounting is unavailable" >&2
    exit 1
fi

log() { echo "[start_ovpn $(date +%H:%M:%S)] $*" >> /logs/openvpn.log; }

# init-pki создаёт служебную разметку (serial, index.txt и пр.). Только
# если её нет — иначе easyrsa отказывается работать в существующем PKI.
if [ ! -f "$PKI/serial" ] && [ ! -f "$PKI/index.txt" ]; then
    log "init-pki"
    "$EASYRSA_BIN" init-pki >>/logs/openvpn.log 2>&1 || log "init-pki FAILED"
fi

if [ ! -f "$PKI/ca.crt" ] || [ ! -f "$PKI/private/ca.key" ]; then
    # Битый CA — обе части нужны; чистим req/key чтобы build-ca не упёрся
    # в "file already exists".
    rm -f "$PKI/reqs/ca.req" "$PKI/private/ca.key" "$PKI/ca.crt"
    log "build-ca"
    "$EASYRSA_BIN" --req-cn="vpnbot-ovpn-ca" build-ca nopass >>/logs/openvpn.log 2>&1 || log "build-ca FAILED"
fi

if [ ! -f "$PKI/issued/server.crt" ] || [ ! -f "$PKI/private/server.key" ]; then
    # Главный source of bug, который ловил пользователя: stale reqs/server.req
    # от прошлого частичного запуска блокировал build-server-full (easyrsa
    # отказывается перезаписывать .req даже в batch). Удаляем артефакты
    # и перевыпускаем server-cert полностью.
    rm -f "$PKI/reqs/server.req" "$PKI/private/server.key" "$PKI/issued/server.crt"
    log "build-server-full server"
    # ВАЖНО: easy-rsa 3.1+ запрещает --req-cn вместе с build-server-full/
    # build-client-full; CN берётся из имени файла. Попытка задать CN
    # через флаг даёт "Option conflict: does not support setting an
    # external commonName". Поэтому --req-cn тут НЕ пишем.
    "$EASYRSA_BIN" build-server-full server nopass >>/logs/openvpn.log 2>&1 || log "build-server-full FAILED"
fi

# CRL перегенерируем на КАЖДОМ старте, а не только при отсутствии: nextUpdate
# у старых CRL мог быть выписан с дефолтными 180 днями, и после его истечения
# openvpn с crl-verify отвергает все новые подключения. gen-crl дёшев и
# идемпотентен. Без ca.key генерация невозможна (импортированный PKI без
# приватника CA) — тогда оставляем существующий crl.pem как есть.
if [ -f "$PKI/private/ca.key" ]; then
    log "gen-crl (refresh, EASYRSA_CRL_DAYS=$EASYRSA_CRL_DAYS)"
    "$EASYRSA_BIN" gen-crl >>/logs/openvpn.log 2>&1 || log "gen-crl FAILED"
elif [ ! -f "$PKI/crl.pem" ]; then
    log "gen-crl SKIPPED: no ca.key and no crl.pem"
fi

if [ ! -f "$PKI/ta.key" ]; then
    # OpenVPN 2.5+: `--genkey secret FILE`. Fallback на старый синтаксис
    # `--genkey --secret FILE`, если попадётся 2.4 (маловероятно, но дёшево).
    log "genkey ta.key"
    openvpn --genkey secret "$PKI/ta.key" 2>>/logs/openvpn.log \
        || openvpn --genkey --secret "$PKI/ta.key" 2>>/logs/openvpn.log \
        || log "genkey ta.key FAILED"
fi

# Если что-то всё равно не собралось — явный лог, чтобы бот мог его показать.
for f in "$PKI/ca.crt" "$PKI/issued/server.crt" "$PKI/private/server.key" "$PKI/crl.pem" "$PKI/ta.key"; do
    [ -f "$f" ] || log "MISSING $f — PKI init failed; openvpn won't start"
done

if [ ! -f "$SRV" ]; then
    cat > "$SRV" <<EOF
# Generated by vpnbot start_ovpn.sh — bot edits port/isolation in place.
port $PORT
proto $PROTO
dev tun
topology subnet

ca $PKI/ca.crt
cert $PKI/issued/server.crt
key $PKI/private/server.key
dh none
tls-crypt $PKI/ta.key
crl-verify $PKI/crl.pem

# В TLS-режиме OpenVPN 2.6 директива "cipher" ИГНОРИРУЕТСЯ (шифр выбирается
# согласованием по data-ciphers) и остаётся только ради --secret. Не пишем её,
# чтобы не собирать deprecation-предупреждения в журнале.
auth SHA256
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-256-GCM
tls-version-min 1.2

server $NET $MASK
ifconfig-pool-persist /etc/openvpn/ipp.txt
# Bot switches between "all traffic" and "selected networks" here.
#ovpn-gateway
push "redirect-gateway def1 bypass-dhcp"
#ovpn-gateway
#ovpn-routes
#ovpn-routes
push "dhcp-option DNS 10.10.0.5"

# Bot sets mssfix and the second listening socket (udp+tcp) between these markers.
#ovpn-mss
#ovpn-mss
#ovpn-dual
#ovpn-dual

# block-outside-dns разбирается в options.c только под #ifdef _WIN32. Для
# любого не-Windows клиента это НЕИЗВЕСТНАЯ push-опция, а неизвестная опция в
# PUSH_REPLY фатальна: apply_push_options() возвращает ошибку и соединение
# рвётся ещё до поднятия туннеля. Поэтому по умолчанию не пушим; включить
# можно кнопкой в меню бота (актуально для Windows-only парка).
# Bot toggles the Windows-only DNS-leak guard between these markers.
#ovpn-winblockdns
#ovpn-winblockdns

client-config-dir /etc/openvpn/ccd
keepalive 10 60
explicit-exit-notify 1

# Bot toggles client isolation between these markers — do not edit by hand.
#ovpn-isolation
#ovpn-isolation

status /etc/openvpn/openvpn-status.log 5
status-version 2
log-append /logs/openvpn.log
verb 3

management /var/run/openvpn-mgmt.sock unix

# Журнал подключений (UP/DOWN + real IP) через внешний hook.
# script-security 2 разрешает вызов системных скриптов.
script-security 2
client-connect "/usr/bin/python3 /ovpn_traffic.py"
client-disconnect "/usr/bin/python3 /ovpn_traffic.py"

# persist-key не пишем: 2.7 отвечает «DEPRECATED OPTION: --persist-key
# option ignored. Keys are now always persisted across restarts.»
persist-tun
EOF
fi

# Миграции существующего server.conf вынесены в отдельный скрипт: тот же
# набор правок обязан применяться и когда бот восстанавливает server.conf из
# бэкапа (importOvpnPki), а контейнер при этом не пересоздаётся.
sh /ovpn_migrate.sh "$SRV"

# EasyRSA/PKI/server.conf больше не меняются; демон может стартовать без лока.
flock -u 8

# VPN-клиентам разрешён только DNS внутри служебной сети сборки.
# REJECT нужны дополнительные модули ядра (их нет на части хостов), DROP
# изолирует клиентов так же, только без ответа об отказе. Если не встало ни то,
# ни другое — служба не запускается.
ovpn_guard() {
    iptables "$@" && return 0
    reject=0; n=$#; i=0
    for arg in "$@"; do
        [ "$i" -eq 0 ] && set --
        i=$((i + 1))
        if [ "$i" -eq "$n" ] && [ "$arg" = REJECT ]; then reject=1; set -- "$@" DROP; else set -- "$@" "$arg"; fi
    done
    if [ "$reject" = 1 ] && iptables "$@"; then
        echo 'WARN: REJECT is unavailable; OpenVPN clients are isolated with DROP' >&2
        return 0
    fi
    echo 'FATAL: OpenVPN client firewall was not installed' >&2; exit 1
}
ovpn_guard -A INPUT -i tun+ -j REJECT
ovpn_guard -A FORWARD -i tun+ -d 10.10.0.5 -p udp --dport 53 -j ACCEPT
ovpn_guard -A FORWARD -i tun+ -d 10.10.0.5 -p tcp --dport 53 -j ACCEPT
ovpn_guard -A FORWARD -i tun+ -d 10.10.0.0/16 -j REJECT
iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$INTERFACE" -j MASQUERADE 2>/dev/null || true
sh /ovpn_firewall.sh "$SRV" || exit 1

mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200

mkdir -p /logs
[ -f /logs/openvpn.log ] || : > /logs/openvpn.log

# Запускаем openvpn только если все обязательные файлы PKI на месте.
# Иначе бот показал бы «on» при падающем демоне; лучше честно off.
if [ -f "$PKI/ca.crt" ] && [ -f "$PKI/issued/server.crt" ] \
   && [ -f "$PKI/private/server.key" ] && [ -f "$PKI/crl.pem" ] && [ -f "$PKI/ta.key" ]; then
    openvpn --config "$SRV" >/dev/null 2>&1 &
fi

tail -f /dev/null
