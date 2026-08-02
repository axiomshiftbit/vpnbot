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
ssh-keygen -A >/dev/null 2>&1 || true
/usr/sbin/sshd -D -e "$@" &

INTERFACE=$(route | grep '^default' | grep -o '[^ ]*$')
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

# Hook для client-connect/disconnect: пишет UP/DOWN-события с CN и реальным
# IP клиента в отдельный журнал /logs/openvpn-connections.log. Без script-
# security 2 openvpn игнорирует этот хук. Обязательный `exit 0` — чтобы
# падение скрипта не разорвало клиентскую сессию.
HOOK=/etc/openvpn/connect.sh
cat > "$HOOK" <<'HOOKEOF'
#!/bin/sh
# OpenVPN client-connect / client-disconnect hook.
# Вызывается openvpn'ом с env vars:
#   script_type             — client-connect | client-disconnect
#   common_name             — CN клиента из TLS-сертификата
#   trusted_ip, trusted_port — реальный публичный адрес клиента
#   ifconfig_pool_remote_ip  — выданный внутренний IP (10.8.0.x)
#   bytes_received, bytes_sent — только на disconnect
LOG=/logs/openvpn-connections.log
TS=$(date '+%Y-%m-%d %H:%M:%S')
case "$script_type" in
    client-connect)
        printf '%s UP   %-20s %s:%s -> %s\n' \
            "$TS" "$common_name" "$trusted_ip" "$trusted_port" \
            "$ifconfig_pool_remote_ip" >> "$LOG"
        ;;
    client-disconnect)
        printf '%s DOWN %-20s %s:%s  rx=%s tx=%s\n' \
            "$TS" "$common_name" "$trusted_ip" "$trusted_port" \
            "${bytes_received:-0}" "${bytes_sent:-0}" >> "$LOG"
        ;;
esac
exit 0
HOOKEOF
chmod +x "$HOOK"

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
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 10.10.0.5"

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
client-connect /etc/openvpn/connect.sh
client-disconnect /etc/openvpn/connect.sh

persist-key
persist-tun
EOF
fi

# Миграции уже существующего server.conf (бот правит его in-place; мы тут
# подтягиваем только безопасные для OpenSSL 3.0+ строки, ничего пользова-
# тельского не перезаписывая).
if [ -f "$SRV" ]; then
    # Внутренний bind-порт всегда 1194 (см. комментарий к PORT выше). Старые
    # server.conf, сгенерированные когда OVPNPORT≠1194, могли получить
    # неправильный `port` — принудительно чиним, иначе nginx/docker (1194) не
    # достучатся до демона и openvpn будет «on», но недоступен снаружи.
    sed -i 's/^port[[:space:]]\+[0-9]\+[[:space:]]*$/port 1194/' "$SRV"
    # ecdh-curve игнорируется в OpenSSL 3.0+ с warning'ом — убираем.
    sed -i '/^ecdh-curve[[:space:]]/d' "$SRV"
    # management через TCP на 127.0.0.1 → unix-сокет (убирает "TCP port
    # WITHOUT passwords is STRONGLY discouraged" warning и безопаснее).
    sed -i 's|^management[[:space:]]\+127\.0\.0\.1[[:space:]]\+7505[[:space:]]*$|management /var/run/openvpn-mgmt.sock unix|' "$SRV"
    # explicit-exit-notify ignored for --proto tcp — держим только для UDP.
    if grep -qE '^proto[[:space:]]+tcp' "$SRV"; then
        sed -i '/^explicit-exit-notify[[:space:]]/d' "$SRV"
    elif ! grep -qE '^explicit-exit-notify[[:space:]]' "$SRV"; then
        # При возврате на UDP вернуть директиву, если её когда-то удаляли.
        printf '\nexplicit-exit-notify 1\n' >> "$SRV"
    fi
    # Миграция #1: если в старом server.conf нет маркеров #ovpn-isolation —
    # добавляем пустой блок. Без маркеров toggleOvpnIsolation silently no-op
    # и кнопка «трафик между клиентами» всегда показывает off.
    if ! grep -q '^#ovpn-isolation[[:space:]]*$' "$SRV"; then
        printf '\n# Bot toggles client isolation between these markers — do not edit by hand.\n#ovpn-isolation\n#ovpn-isolation\n' >> "$SRV"
    fi
    # Миграция #2: без `status` директивы openvpn-status.log не пишется,
    # из-за чего getOvpnStatus() возвращает пусто и все клиенты в меню
    # отображаются как offline (⚪). Добавляем обе директивы, если их нет.
    if ! grep -qE '^status[[:space:]]' "$SRV"; then
        printf '\nstatus /etc/openvpn/openvpn-status.log 5\n' >> "$SRV"
    fi
    if ! grep -qE '^status-version[[:space:]]' "$SRV"; then
        printf 'status-version 2\n' >> "$SRV"
    fi
    # Миграция #3: client-connect/disconnect hook для журнала подключений
    # (/logs/openvpn-connections.log с CN + real IP). Требует script-security 2.
    # Без этой миграции существующие server.conf не увидят новый хук.
    if ! grep -qE '^script-security[[:space:]]' "$SRV"; then
        printf '\nscript-security 2\n' >> "$SRV"
    fi
    if ! grep -qE '^client-connect[[:space:]]' "$SRV"; then
        printf 'client-connect /etc/openvpn/connect.sh\n' >> "$SRV"
    fi
    if ! grep -qE '^client-disconnect[[:space:]]' "$SRV"; then
        printf 'client-disconnect /etc/openvpn/connect.sh\n' >> "$SRV"
    fi
    # Миграция #4: `push "block-outside-dns"` роняет ВСЕХ не-Windows клиентов
    # (неизвестная опция в PUSH_REPLY = фатальная ошибка на стороне клиента).
    # Убираем безусловный push и заводим маркеры, между которыми бот включает
    # его обратно по кнопке — осознанно и только там, где парк на Windows.
    if ! grep -q '^#ovpn-winblockdns[[:space:]]*$' "$SRV"; then
        if grep -qE '^[[:space:]]*push[[:space:]]+"block-outside-dns"' "$SRV"; then
            log 'migration: push "block-outside-dns" disabled (breaks non-Windows clients); re-enable via bot menu'
        fi
        sed -i '/^[[:space:]]*push[[:space:]]\+"block-outside-dns"/d' "$SRV"
        printf '\n# Bot toggles the Windows-only DNS-leak guard between these markers.\n#ovpn-winblockdns\n#ovpn-winblockdns\n' >> "$SRV"
    fi
    # Миграция #5: `cipher` в TLS-режиме игнорируется с 2.6 и только засоряет
    # лог deprecation-предупреждением. data-ciphers/-fallback уже заданы.
    sed -i '/^[[:space:]]*cipher[[:space:]]/d' "$SRV"
fi

iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$INTERFACE" -j MASQUERADE 2>/dev/null || true

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
