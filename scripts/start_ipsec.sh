#!/bin/sh
# strongSwan (IKEv1 для L2TP/IPsec + IKEv2 EAP-MSCHAPv2) + xl2tpd entrypoint.
# - Все персистентные артефакты (PSK, PKI, secrets, chap-secrets, swanctl.conf)
#   живут на bind mount /config/ipsec — их правит бот из php-контейнера.
# - Конфиги в /etc/* (xl2tpd, ppp options, charon logging) НЕ персистентны и
#   переписываются на каждом старте: единственный source of truth — этот скрипт.
# - Клиенты за DNAT всегда работают через NAT-T (udp/4500) — ESP/50 наружу не
#   нужен, nft-конфиг хоста открывает только udp 500/4500.
# - L2TP требует на ХОСТЕ загруженный модуль l2tp_ppp (modprobe l2tp_ppp +
#   /etc/modules-load.d/vpnbot-l2tp.conf). Без него IKEv2 работает, L2TP — нет.
#
# Намеренно БЕЗ `set -e`: ошибки детектируем через проверку наличия файлов
# и явные log-записи (стиль start_ovpn.sh).

cat /ssh/key.pub > /root/.ssh/authorized_keys 2>/dev/null || true
ssh-keygen -A >/dev/null 2>&1 || true
/usr/sbin/sshd -D -e "$@" &

CONF=/config/ipsec
PKI=$CONF/pki
LOG=/logs/ipsec.log
INTERFACE=$(route | grep '^default' | grep -o '[^ ]*$')

L2TP_SUBNET="${L2TPSUBNET:-10.9.1.0/24}"
IKEV2_SUBNET="${IKEV2SUBNET:-10.9.2.0/24}"
L2TP_BASE=$(echo "$L2TP_SUBNET" | cut -d/ -f1 | cut -d. -f1-3)
DNS=10.10.0.5

mkdir -p "$PKI" /logs /var/run/l2tp-sessions /etc/swanctl/x509ca /etc/swanctl/x509 /etc/swanctl/private
: >> "$LOG"
: >> /logs/l2tp.log
: >> /logs/ipsec-connections.log

log() { echo "[start_ipsec $(date +%H:%M:%S)] $*" >> "$LOG"; }

# /dev/ppp нужен pppd; на голом контейнере его нет. CAP_MKNOD есть по
# умолчанию, поэтому создаём сами вместо device-маппинга в compose (маппинг
# падал бы, если на хосте ещё не сделан modprobe ppp_generic).
[ -c /dev/ppp ] || mknod /dev/ppp c 108 0 2>>"$LOG" || log "mknod /dev/ppp FAILED"

# Явная диагностика отсутствия kernel-модуля: xl2tpd молча не сможет
# создавать сессии, а так причина сразу видна в логе и в меню бота.
if [ ! -d /sys/module/l2tp_ppp ]; then
    log "WARN: kernel module l2tp_ppp is NOT loaded on the host — L2TP will not work."
    log "WARN: run on host: modprobe l2tp_ppp && echo l2tp_ppp > /etc/modules-load.d/vpnbot-l2tp.conf"
fi

# ─── PSK (общий для всех L2TP/IPsec-клиентов) ────────────────────────────
if [ ! -s "$CONF/psk" ]; then
    log "generate PSK"
    openssl rand -base64 24 > "$CONF/psk" 2>>"$LOG" || log "PSK generation FAILED"
    chmod 600 "$CONF/psk" 2>/dev/null
fi
PSK=$(cat "$CONF/psk" 2>/dev/null)

# ─── PKI: собственный CA + серверный серт для IKEv2 ──────────────────────
# CA на 10 лет; клиенты получают ca.crt внутри профиля (.mobileconfig/.sswan)
# от бота. Никакой зависимости от домена/Let's Encrypt.
command -v pki >/dev/null 2>&1 || log "MISSING pki binary — strongswan package broken?"
if [ ! -f "$PKI/ca.key" ] || [ ! -f "$PKI/ca.crt" ]; then
    rm -f "$PKI/ca.key" "$PKI/ca.crt" "$PKI/server.key" "$PKI/server.crt"
    log "generate CA"
    pki --gen --type rsa --size 3072 --outform pem > "$PKI/ca.key" 2>>"$LOG" \
        || log "CA key FAILED"
    pki --self --ca --lifetime 3650 --in "$PKI/ca.key" \
        --dn "CN=vpnbot-ipsec-ca" --outform pem > "$PKI/ca.crt" 2>>"$LOG" \
        || log "CA cert FAILED"
fi

# Серверный серт: SAN обязан содержать текущий публичный IP (identity, по
# которой коннектятся клиенты), иначе нативные клиенты рвут TLS-фазу IKE.
# При смене IP сервера серт перевыпускается автоматически (CA остаётся —
# развёрнутые клиентские профили продолжают работать).
SAN_OK=0
if [ -f "$PKI/server.crt" ] && [ -f "$PKI/server.key" ] && [ -n "$IP" ]; then
    if openssl x509 -in "$PKI/server.crt" -noout -text 2>/dev/null | grep -q "IP Address:$IP"; then
        if [ -z "$DOMAIN" ] || openssl x509 -in "$PKI/server.crt" -noout -text 2>/dev/null | grep -q "DNS:$DOMAIN"; then
            SAN_OK=1
        fi
    fi
fi
if [ "$SAN_OK" != "1" ] && [ -f "$PKI/ca.key" ] && [ -n "$IP" ]; then
    log "issue server cert (SAN: $IP${DOMAIN:+, $DOMAIN})"
    pki --gen --type rsa --size 3072 --outform pem > "$PKI/server.key" 2>>"$LOG" \
        || log "server key FAILED"
    # shellcheck disable=SC2086
    pki --pub --in "$PKI/server.key" 2>>"$LOG" | pki --issue --lifetime 3650 \
        --cacert "$PKI/ca.crt" --cakey "$PKI/ca.key" \
        --dn "CN=$IP" --san "$IP" ${DOMAIN:+--san "$DOMAIN"} \
        --flag serverAuth --flag ikeIntermediate \
        --outform pem > "$PKI/server.crt" 2>>"$LOG" \
        || log "server cert FAILED"
fi
chmod 600 "$PKI/ca.key" "$PKI/server.key" 2>/dev/null

# swanctl подхватывает креды из стандартных каталогов — кладём копии
# (идемпотентно, каждый старт).
cp -f "$PKI/ca.crt"     /etc/swanctl/x509ca/ca.crt     2>>"$LOG" || log "MISSING ca.crt"
cp -f "$PKI/server.crt" /etc/swanctl/x509/server.crt   2>>"$LOG" || log "MISSING server.crt"
cp -f "$PKI/server.key" /etc/swanctl/private/server.key 2>>"$LOG" || log "MISSING server.key"

# ─── secrets.conf: PSK + EAP-юзеры (правит бот) ──────────────────────────
# Формат swanctl. Начальный файл — только PSK; дальше бот РЕГЕНЕРИРУЕТ файл
# целиком из users_ikev2.json (секции eap-1, eap-2, … c id = юзер).
# Создаём только если нет — иначе затёрли бы юзеров бота.
if [ ! -f "$CONF/secrets.conf" ]; then
    log "create secrets.conf"
    cat > "$CONF/secrets.conf" <<EOF
# Managed by vpnbot — do not edit section markers by hand.
secrets {
    ike-l2tp {
        secret = "$PSK"
    }
#eap-users
}
EOF
    chmod 600 "$CONF/secrets.conf" 2>/dev/null
fi

# ─── swanctl.conf (правится редко; создаём только если нет) ──────────────
# conn l2tp: IKEv1 + PSK, transport mode на udp/1701 — поверх ходит xl2tpd.
# conn ikev2: cert-auth сервера + EAP-MSCHAPv2, пул адресов, IKE-фрагментация
# ОБЯЗАТЕЛЬНА (nft на хосте дропает IP-фрагменты).
# Гейт на непустой $IP: `id = ` без значения — синтаксическая ошибка, из-за
# которой swanctl --load-all не поднимет ОБА конна (и l2tp тоже).
if [ ! -f "$CONF/swanctl.conf" ] && [ -z "$IP" ]; then
    log "swanctl.conf SKIPPED: env IP is empty — fill IP in .env and restart"
fi
if [ ! -f "$CONF/swanctl.conf" ] && [ -n "$IP" ]; then
    log "create swanctl.conf"
    cat > "$CONF/swanctl.conf" <<EOF
connections {
    l2tp {
        version = 1
        local_addrs = %any
        proposals = aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048
        rekey_time = 8h
        local {
            auth = psk
        }
        remote {
            auth = psk
        }
        children {
            l2tp {
                local_ts = dynamic[udp/1701]
                remote_ts = dynamic
                mode = transport
                esp_proposals = aes256-sha256,aes256-sha1,aes128-sha1
                rekey_time = 1h
            }
        }
    }
    ikev2 {
        version = 2
        proposals = aes256-sha256-ecp256,aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha256-modp2048,default
        fragmentation = yes
        dpd_delay = 30s
        pools = ikev2-pool
        # rekey инициируют клиенты: серверный rekey ломает нативный
        # Windows-клиент (он не отвечает и сессия рвётся).
        rekey_time = 0s
        local {
            auth = pubkey
            certs = server.crt
            id = $IP # managed-server-id
        }
        remote {
            auth = eap-mschapv2
            eap_id = %any
        }
        children {
            ikev2 {
                local_ts = 0.0.0.0/0
                esp_proposals = aes256-sha256,aes256-sha1,aes128-sha256,default
                dpd_action = clear
                rekey_time = 0s
            }
        }
    }
}
pools {
    ikev2-pool {
        addrs = $IKEV2_SUBNET
        dns = $DNS
    }
}
include /config/ipsec/secrets.conf
EOF
fi
# Миграция: при смене IP сервера серт выше перевыпускается автоматически,
# но `id` в conn ikev2 остался бы старым — клиенты рвали бы соединение на
# несовпадении IDr с SAN. Правим только строку с маркером managed-server-id.
if [ -f "$CONF/swanctl.conf" ] && [ -n "$IP" ]; then
    sed -i "s|^\([[:space:]]*\)id = .* # managed-server-id\$|\1id = $IP # managed-server-id|" "$CONF/swanctl.conf"
fi
rm -f /etc/swanctl/swanctl.conf
ln -s "$CONF/swanctl.conf" /etc/swanctl/swanctl.conf

# ─── charon logging → /logs/ipsec.log (переписываем всегда) ──────────────
mkdir -p /etc/strongswan.d
cat > /etc/strongswan.d/vpnbot-logging.conf <<EOF
charon {
    filelog {
        vpnbot {
            path = $LOG
            time_format = %Y-%m-%d %H:%M:%S
            ike_name = yes
            default = 1
        }
    }
    syslog {
        daemon {
            default = -1
        }
    }
}
EOF

# ─── xl2tpd + pppd (переписываем всегда) ─────────────────────────────────
mkdir -p /etc/xl2tpd /etc/ppp
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701
ipsec saref = no

[lns default]
ip range = $L2TP_BASE.100-$L2TP_BASE.199
local ip = $L2TP_BASE.1
require chap = yes
refuse pap = yes
require authentication = yes
name = vpnbot-l2tp
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

# mtu/mru 1280: IPsec(NAT-T)+L2TP+PPP съедают ~120 байт заголовков; c
# дефолтными 1500 крупные пакеты фрагментируются, а фрагменты nft хоста
# дропает. Дополнительно клампим MSS (iptables ниже).
cat > /etc/ppp/options.xl2tpd <<EOF
ipcp-accept-local
ipcp-accept-remote
ms-dns $DNS
noccp
auth
mtu 1280
mru 1280
lcp-echo-failure 4
lcp-echo-interval 30
connect-delay 5000
require-mschap-v2
EOF

# chap-secrets живёт на bind mount (бот добавляет/блокирует юзеров); pppd
# перечитывает файл на каждом коннекте — reload не нужен.
[ -f "$CONF/chap-secrets" ] || { : > "$CONF/chap-secrets"; chmod 600 "$CONF/chap-secrets"; }
rm -f /etc/ppp/chap-secrets
ln -s "$CONF/chap-secrets" /etc/ppp/chap-secrets

# ─── ppp ip-up/ip-down: журнал подключений + карта живых сессий ──────────
# pppd вызывает их автоматически (env: PEERNAME, IPREMOTE, BYTES_*;
# $PPID = pid pppd — по нему бот кикает юзера).
cat > /etc/ppp/ip-up <<'HOOKEOF'
#!/bin/sh
LOG=/logs/ipsec-connections.log
SESS=/var/run/l2tp-sessions
TS=$(date '+%Y-%m-%d %H:%M:%S')
mkdir -p "$SESS"
printf '%s UP   %-20s l2tp %s if=%s\n' \
    "$TS" "${PEERNAME:-unknown}" "${IPREMOTE:-$5}" "$1" >> "$LOG"
printf '%s %s\n' "${IPREMOTE:-$5}" "$PPID" > "$SESS/${PEERNAME:-unknown}"
exit 0
HOOKEOF
cat > /etc/ppp/ip-down <<'HOOKEOF'
#!/bin/sh
LOG=/logs/ipsec-connections.log
SESS=/var/run/l2tp-sessions
TS=$(date '+%Y-%m-%d %H:%M:%S')
printf '%s DOWN %-20s l2tp %s rx=%s tx=%s\n' \
    "$TS" "${PEERNAME:-unknown}" "${IPREMOTE:-$5}" \
    "${BYTES_RCVD:-0}" "${BYTES_SENT:-0}" >> "$LOG"
rm -f "$SESS/${PEERNAME:-unknown}"
exit 0
HOOKEOF
chmod +x /etc/ppp/ip-up /etc/ppp/ip-down

# ─── NAT + MSS clamp ─────────────────────────────────────────────────────
iptables -t nat -A POSTROUTING -s "$L2TP_SUBNET"  -o "$INTERFACE" -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -s "$IKEV2_SUBNET" -o "$INTERFACE" -j MASQUERADE 2>/dev/null || true
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

# ─── Запуск демонов ──────────────────────────────────────────────────────
# Отдельный скрипт, чтобы бот мог рестартовать демоны без пересоздания
# контейнера: ssh ipsec 'pkill -9 charon; pkill -9 xl2tpd; sh /etc/run_ipsec_daemons.sh'
CHARON=""
for c in /usr/lib/ipsec/charon /usr/lib/strongswan/charon /usr/libexec/ipsec/charon; do
    [ -x "$c" ] && CHARON="$c" && break
done
[ -n "$CHARON" ] || log "MISSING charon binary — strongswan package broken?"

cat > /etc/run_ipsec_daemons.sh <<EOF
#!/bin/sh
# Generated by start_ipsec.sh — (re)start charon + xl2tpd.
rm -f /var/run/charon.vici /var/run/charon.pid /var/run/xl2tpd.pid
[ -n "$CHARON" ] && "$CHARON" >/dev/null 2>&1 &
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    [ -S /var/run/charon.vici ] && break
    sleep 0.3
done
if [ -S /var/run/charon.vici ]; then
    swanctl --load-all >> "$LOG" 2>&1
else
    echo "[run_ipsec \$(date +%H:%M:%S)] charon.vici did not appear — charon failed to start" >> "$LOG"
fi
xl2tpd -D >>/logs/l2tp.log 2>&1 &
EOF
chmod +x /etc/run_ipsec_daemons.sh

sh /etc/run_ipsec_daemons.sh

tail -f /dev/null
