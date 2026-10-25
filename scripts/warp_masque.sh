#!/bin/sh
# WARP через MASQUE — второй режим контейнера wp рядом с WireGuard.
#
# В этом режиме туннель держит сам прокси (Xray 26.10.10+): HTTP/3 или HTTP/2
# на порт 443 узла Cloudflare вместо WireGuard. Интерфейса и маршрутов в
# контейнере нет, поэтому start_wp.sh строит защиту от утечки иначе: процессу
# прокси разрешён только адрес узла, который печатает команда endpoint.
#
# Устройство MASQUE — отдельная регистрация в Cloudflare (каталог masque в томе
# warp). Аккаунт WireGuard при этом не трогается: один и тот же ключ устройства
# не может работать в обоих протоколах, а с двумя устройствами режимы
# переключаются без обращений к Cloudflare.
#
# Регистрацию (POST /reg) выполняет wgcf: Cloudflare отклоняет её, если
# TLS-отпечаток клиента не совпадает с их приложением, и wgcf это обходит.
# Привязка ключа MASQUE (PATCH /reg/<id>) идёт обычным запросом — на 2026-10
# отпечаток там не проверяется. Версия API и заголовки ниже взяты из wgcf
# v2.3.1: при обновлении wgcf сверить cloudflare/api.go.
set -eu

DIR="${WARP_MASQUE_DIR:-/etc/warp/masque}"
PAC="${WARP_PAC:-/config/pac.json}"
RUN="${WARP_RUN_DIR:-/run}"
API='https://api.cloudflareclient.com/v0a5641'
API_USER_AGENT='1.1.1.1/6.38.9-5641 (Android 16.0.0)'
API_CLIENT_VERSION='a-6.38.9-5641'
SNI='consumer-masque.cloudflareclient.com'
# Первое ядро с WARP в MASQUE-клиенте (XTLS/Xray-core #6878).
MIN_CORE='26.10.10'
CHECK_PORT=1081

fail() {
    echo "$1" >&2
    exit 1
}

# Версии сравниваются числами по частям: sort -V есть не в каждом busybox.
version_ge() {
    awk -v have="$1" -v need="$2" 'BEGIN {
        split(have, a, "."); split(need, b, ".");
        for (i = 1; i <= 3; i++) {
            if ((a[i] + 0) > (b[i] + 0)) exit 0;
            if ((a[i] + 0) < (b[i] + 0)) exit 1;
        }
        exit 0;
    }'
}

# Чего не хватает образу для режима. Печатает ok либо причину.
supported() {
    for tool in wgcf curl jq openssl warp-socks; do
        command -v "$tool" >/dev/null 2>&1 || { echo "missing:$tool"; return 1; }
    done
    core=$(warp-socks version 2>/dev/null | awk 'NR == 1 { print $2 }')
    version_ge "$core" "$MIN_CORE" || { echo "core:${core:-unknown}"; return 1; }
    echo ok
}

# Ключ WARP+: из окружения (бот передаёт новый ключ до сохранения настроек)
# либо из pac.json. Пустая строка — бесплатный тариф.
license() {
    if [ "${WARP_LICENSE_KEY+set}" = set ]; then
        printf '%s' "$WARP_LICENSE_KEY"
    else
        jq -r '.warp // empty' "$PAC" 2>/dev/null || true
    fi
}

license_mark() {
    printf '%s' "$1" | sha256sum | cut -c1-64
}

exists() {
    [ -s "$DIR/device.json" ] && [ -s "$DIR/key.pem" ]
}

# Аккаунт есть и зарегистрирован с действующим ключом WARP+.
current() {
    exists && [ "$(cat "$DIR/license.sha256" 2>/dev/null)" = "$(license_mark "$(license)")" ]
}

account_value() {
    awk -F"[ ='\"]+" -v key="$2" '$1 == key { print $2 }' "$1"
}

# Адрес узла из ответа Cloudflare попадает в правило iptables и в конфиг ядра:
# принимается только обычный публичный IPv4.
public_ipv4() {
    printf '%s\n' "$1" | awk -F. '
        NF != 4 { exit 1 }
        {
            for (i = 1; i <= 4; i++) if ($i !~ /^[0-9]+$/ || length($i) > 3 || $i > 255) exit 1;
            if ($1 == 0 || $1 == 10 || $1 == 127 || $1 >= 224) exit 1;
            if ($1 == 100 && $2 >= 64 && $2 <= 127) exit 1;
            if ($1 == 169 && $2 == 254) exit 1;
            if ($1 == 172 && $2 >= 16 && $2 <= 31) exit 1;
            if ($1 == 192 && $2 == 168) exit 1;
            if ($1 == 198 && ($2 == 18 || $2 == 19)) exit 1;
            exit 0;
        }'
}

endpoint_of() {
    address=$(jq -r '.endpoint_v4 // empty' "$1" 2>/dev/null) || return 1
    address=${address%:*}
    public_ipv4 "$address" || return 1
    printf '%s\n' "$address"
}

endpoint() {
    exists || return 1
    endpoint_of "$DIR/device.json"
}

# Конфиг прокси: SOCKS на входе, выход в WARP по MASQUE.
#   config <порт> [h3|h2] [fwmark] [адрес прослушивания]
# fwmark нужен только пробному подключению (check): при поднятом WireGuard он
# выводит пакеты мимо туннеля, как это делает wg-quick для своих.
config() {
    port=${1:-1080}
    alpn=${2:-h3}
    mark=${3:-}
    listen=${4:-0.0.0.0}
    exists || fail 'no MASQUE account'
    case "$port" in ''|*[!0-9]*) fail 'bad port' ;; esac
    case "$mark" in *[!0-9]*) fail 'bad mark' ;; esac
    address=$(endpoint) || fail 'bad endpoint'
    local4=$(jq -r '.address_v4 // empty' "$DIR/device.json")
    case "$local4" in ''|*[!0-9.]*) fail 'bad address' ;; esac
    # IPv4-адрес внутри туннеля: IPv6 не передаём, как и в режиме WireGuard
    # (warp_fixup.sh вырезает его из профиля).
    jq -n \
        --arg listen "$listen" --argjson port "$port" --arg address "$address" \
        --rawfile key "$DIR/key.pem" --arg public "$(jq -r '.endpoint_public_key' "$DIR/device.json")" \
        --arg local4 "$local4" --arg alpn "$alpn" --arg mark "$mark" --arg sni "$SNI" '
        {
            log: {loglevel: "warning", access: "none"},
            inbounds: [{
                listen: $listen, port: $port, protocol: "socks",
                settings: {auth: "noauth", udp: true}
            }],
            outbounds: [{
                protocol: "masque",
                settings: {address: $address, port: 443, remoteDNS: ["1.1.1.1", "1.0.0.1"]},
                streamSettings: ({
                    method: "masque",
                    # Пустой User-Agent, как у официального клиента WARP: с 26.10.17
                    # ядро без этого поля подставляет User-Agent Chrome.
                    masqueSettings: {warp: {privateKey: $key, publicKey: $public, address: [$local4 + "/32"]},
                        headers: {"User-Agent": ""}},
                    security: "tls",
                    tlsSettings: ({serverName: $sni} + (if $alpn == "h2" then {alpn: ["h2"]} else {} end))
                } + (if $mark != "" then {sockopt: {mark: ($mark | tonumber)}} else {} end))
            }]
        }'
}

# Новое устройство: wgcf регистрирует, затем ключ устройства заменяется на
# P-256 с типом туннеля masque. Собирается в соседнем каталоге и подменяет
# прежний аккаунт целиком; прежний хранится до commit — rollback его вернёт.
register() {
    reason=$(supported) || fail "$reason"
    key=$(license)
    case "$key" in *[!A-Za-z0-9-]*) fail 'bad license key' ;; esac
    umask 077
    new="$DIR.new"
    rm -rf "$new"
    mkdir -p "$new"
    trap 'rm -rf "$new"' EXIT
    cd "$new"
    wgcf register --accept-tos --config "$new/wgcf-account.toml" --name vpnbot-masque >/dev/null 2>&1 \
        || fail 'registration failed'
    applied=''
    if [ -n "$key" ]; then
        # Та же подстановка, что в start_wp.sh: awk, а не sed — значение не
        # попадает в текст выражения и в аргументы процесса.
        if LK="$key" awk '
                /^license_key/ { printf "license_key = \"%s\"\n", ENVIRON["LK"]; next }
                { print }
            ' wgcf-account.toml > wgcf-account.toml.tmp && [ -s wgcf-account.toml.tmp ] \
            && cat wgcf-account.toml.tmp > wgcf-account.toml && rm -f wgcf-account.toml.tmp \
            && wgcf update --config "$new/wgcf-account.toml" >/dev/null 2>&1; then
            applied=$key
        elif [ "${WARP_LICENSE_STRICT:-0}" = 1 ]; then
            # Бот меняет ключ по просьбе администратора: молча остаться на
            # бесплатном тарифе нельзя.
            fail 'license was not applied'
        else
            # Автозапуск контейнера: как и в режиме WireGuard, продолжаем на
            # бесплатном тарифе, иначе каждый перезапуск регистрировал бы
            # новое устройство и упирался в тот же отказ.
            echo '[warp] MASQUE: license key NOT applied, continuing free tier' >&2
        fi
    fi
    id=$(account_value wgcf-account.toml device_id)
    token=$(account_value wgcf-account.toml access_token)
    [ -n "$id" ] && [ -n "$token" ] || fail 'registration gave no device'
    case "$id" in *[!A-Za-z0-9-]*) fail 'bad device id' ;; esac

    openssl ecparam -name prime256v1 -genkey -noout -out sec1.pem 2>/dev/null || fail 'key generation failed'
    openssl pkcs8 -topk8 -nocrypt -in sec1.pem -out key.pem 2>/dev/null || fail 'key generation failed'
    rm -f sec1.pem
    public=$(openssl pkey -in key.pem -pubout -outform DER 2>/dev/null | base64 | tr -d '\n')
    [ -n "$public" ] || fail 'key generation failed'

    # warp_enabled: после регистрации через wgcf он выключен, а узел MASQUE
    # по словам авторов клиента в ядре может отказывать таким устройствам.
    body=$(jq -cn --arg key "$public" '{key: $key, key_type: "secp256r1", tunnel_type: "masque", warp_enabled: true}')
    # Токен передаётся через stdin (-K -), а не в аргументах curl.
    status=$(printf 'header = "Authorization: Bearer %s"\n' "$token" | curl -sS -m 30 -K - -X PATCH "$API/reg/$id" \
        -A "$API_USER_AGENT" -H "CF-Client-Version: $API_CLIENT_VERSION" \
        -H 'Content-Type: application/json; charset=UTF-8' -H 'Connection: Keep-Alive' -H 'Accept:' \
        -d "$body" -o response.json -w '%{http_code}' 2>/dev/null) || fail 'enrollment request failed'
    [ "$status" = 200 ] || fail "enrollment rejected: HTTP $status"
    jq -e --arg key "$public" '
        .tunnel_type == "masque" and .key_type == "secp256r1" and .key == $key
        and (.config.peers[0].public_key | type == "string")
        and (.config.peers[0].endpoint.v4 | type == "string")
        and (.config.interface.addresses.v4 | type == "string")' response.json >/dev/null 2>&1 \
        || fail 'enrollment answer is not a MASQUE device'
    jq -r '.config.peers[0].public_key' response.json | openssl pkey -pubin -noout 2>/dev/null \
        || fail 'endpoint key is not a public key'
    # Сохраняется только нужное для туннеля: ответ содержит и ключ лицензии.
    jq '{
        id,
        endpoint_v4: .config.peers[0].endpoint.v4,
        endpoint_v6: (.config.peers[0].endpoint.v6 // ""),
        endpoint_public_key: .config.peers[0].public_key,
        address_v4: .config.interface.addresses.v4,
        address_v6: (.config.interface.addresses.v6 // ""),
        account_type: (.account.account_type // ""),
        warp_plus: (.account.warp_plus // false),
        registered: (now | floor)
    }' response.json > device.json
    rm -f response.json
    endpoint_of device.json >/dev/null || fail 'endpoint is not a public address'
    license_mark "$applied" > license.sha256
    : > .pending

    if [ -e "$DIR/.pending" ] && [ -e "$DIR.old" ]; then
        # Прошлая регистрация так и осталась неподтверждённой (бот оборвался
        # до commit): откат должен вернуть не её, а последнее подтверждённое
        # устройство, которое всё ещё лежит рядом.
        rm -rf "$DIR"
    else
        rm -rf "$DIR.old"
        if [ -e "$DIR" ]; then
            mv "$DIR" "$DIR.old"
        fi
    fi
    mv "$new" "$DIR"
    trap - EXIT
    echo VPNBOT_MASQUE_REGISTERED
}

# Регистрация подтверждена: прежний аккаунт больше не нужен.
commit() {
    rm -rf "$DIR.old"
    rm -f "$DIR/.pending"
}

# Вернуть аккаунт, бывший до последней неподтверждённой регистрации.
rollback() {
    [ -e "$DIR/.pending" ] || return 0
    rm -rf "$DIR"
    if [ -e "$DIR.old" ]; then
        mv "$DIR.old" "$DIR"
    fi
}

# Пробное подключение, не затрагивающее работающий режим: временный прокси на
# петле от root (ограничение по UID на него не действует), один запрос trace.
# Имя процесса своё, чтобы его не приняли за основной прокси и не остановили
# вместе с ним (pkill -x warp-socks).
check() {
    alpn=${1:-h3}
    exists || fail 'no MASQUE account'
    mark=''
    wgmark=$(wg show wgcf-profile fwmark 2>/dev/null || true)
    case "$wgmark" in ''|off) ;; *) mark=$((wgmark)) ;; esac
    umask 077
    probe="$RUN/warp-masque-check"
    # Имя оканчивается на .json: ядро определяет формат конфига по расширению.
    conf="$RUN/warp-masque-check.json"
    rm -f "$conf"
    ln -sf "$(command -v warp-socks)" "$probe"
    result=1
    pid=''
    reply=''
    trap 'if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; fi
        if [ -n "$reply" ]; then iptables -t mangle -D $reply 2>/dev/null || true; fi
        rm -f "$conf" "$probe"' EXIT
    # wg-quick возвращает метку только ответам UDP (CONNMARK). Ответ узла по TCP
    # (HTTP/2) приходит без неё, и при строгом rp_filter ядро его отбрасывает:
    # обратный путь без метки ведёт в туннель. На время пробы помечаем такие
    # ответы сами; пакеты из самого туннеля правило не трогает.
    if [ -n "$mark" ] && [ "$alpn" = h2 ]; then
        node=$(endpoint) || fail 'bad endpoint'
        reply="PREROUTING ! -i wgcf-profile -p tcp -s $node --sport 443 -j MARK --set-mark $mark"
        # shellcheck disable=SC2086
        iptables -t mangle -I $reply 2>/dev/null || reply=''
    fi
    if config "$CHECK_PORT" "$alpn" "$mark" 127.0.0.1 > "$conf" && "$probe" run -test -config "$conf" >/dev/null 2>&1; then
        "$probe" run -config "$conf" >/dev/null 2>&1 &
        pid=$!
        attempt=0
        while [ "$attempt" -lt 4 ]; do
            sleep 1
            if curl -m 8 -s -x "socks5h://127.0.0.1:$CHECK_PORT" https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null \
                | grep -qE '^warp=(on|plus)'; then
                result=0
                break
            fi
            attempt=$((attempt + 1))
        done
    fi
    return "$result"
}

# Сведения для меню бота, без секретов.
status() {
    exists || { echo '{}'; return 0; }
    jq -c '{id: (.id[0:8]), endpoint_v4, address_v4, account_type, warp_plus, registered}' "$DIR/device.json"
}

case "${1:-}" in
    supported) supported ;;
    exists) exists ;;
    current) current ;;
    endpoint) endpoint ;;
    config) shift; config "$@" ;;
    register) register ;;
    commit) commit ;;
    rollback) rollback ;;
    check) shift; check "$@" ;;
    status) status ;;
    *) fail 'usage: warp_masque.sh supported|exists|current|endpoint|config|register|commit|rollback|check|status' ;;
esac
