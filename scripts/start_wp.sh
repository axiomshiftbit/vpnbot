#!/bin/bash
set -e
mkdir -p /logs
exec >>/logs/warp 2>&1

cat /ssh/key.pub > /root/.ssh/authorized_keys
# Ключ узла выдаёт контейнер php (ssh/hosts/<сервис>): бот сверяет его
# отпечаток перед каждой командой. Случайный ключ бот не примет.
# Каталог подключён, а ключа ещё нет — php не успел его создать: ждём.
hostkey_wait=0; while [ -d /hostkey ] && [ ! -s /hostkey/ssh_host_ed25519_key.pub ] && [ "$hostkey_wait" -lt 60 ]; do sleep 1; hostkey_wait=$((hostkey_wait + 1)); done
cp -p /hostkey/ssh_host_ed25519_key /hostkey/ssh_host_ed25519_key.pub /etc/ssh/ 2>/dev/null || ssh-keygen -A
# Без exec: `exec cmd &` порождает подоболочку, которую exec собой и заменяет,
# т.е. работает как обычный фоновый запуск, но читается как «заменить текущий
# процесс» — и сбивает с толку при чтении скрипта.
/usr/sbin/sshd -D -e "$@" &

WGCF_DIR="/etc/warp"
WGCF_CONF="$WGCF_DIR/wgcf-profile.conf"
WGCF_TOML="$WGCF_DIR/wgcf-account.toml"
SOCKS_PORT="${SOCKS_PORT:-1080}"
# Xray выдаёт отдельный UDP relay для каждой SOCKS5-ассоциации. Диапазон
# закреплён sysctl в compose и разрешён в Bot::WARP_SOCKS_UDP_PORTS.
SOCKS_UDP_PORTS=20000:29999

# Повреждённый или ещё не записанный pac.json не должен ронять контейнер в
# цикл перезапусков (set -e): без ключа поднимаемся на бесплатном тарифе.
WARP_LICENSE_KEY=$(jq -r '.warp // empty' /config/pac.json 2>/dev/null || true)

# Режим туннеля: WireGuard (wgcf) либо MASQUE (warp_masque.sh — там же описано
# устройство режима). Флаг пишет бот в pac.json, сторож перечитывает его на
# каждом проходе и переключает режим без перезапуска контейнера. Без скрипта
# режима (контейнер создан прежним compose) остаётся WireGuard.
warp_mode() {
    if [ -f /warp_masque.sh ] && [ "$(jq -r '.warp_mode // empty' /config/pac.json 2>/dev/null)" = masque ]; then
        echo masque
    else
        echo wireguard
    fi
}
# До узла MASQUE — HTTP/3 (UDP 443) либо HTTP/2 (TCP 443).
masque_alpn() {
    if [ "$(jq -r '.warp_masque_h2 // empty' /config/pac.json 2>/dev/null)" = 1 ]; then echo h2; else echo h3; fi
}
MODE=$(warp_mode)
ALPN=$(masque_alpn)
# /run переживает перезапуск контейнера: отметка прошлого запуска уверяла бы
# бота, что прокси уже работает в этом режиме.
rm -f /run/warp-mode

# Кто имеет право пользоваться SOCKS'ом (см. блок фильтра ниже). Резолвим
# ИМЕННО ЗДЕСЬ: ниже мы перепишем /etc/resolv.conf на 1.1.1.1 и docker-DNS
# (127.0.0.11), который знает имена контейнеров, станет недоступен.
# Единственный легитимный потребитель прокси — xray (outbound tag "warp" и
# проверка статуса в боте). Он ходит сюда с адреса своего интерфейса в
# сети проекта; docker-DNS на имя сервиса отдаёт именно его. Берём ВСЕ
# адреса: у xray их два (вторая сеть 10.10.1.0/24), и хотя маршрут до нас
# идёт через первую, лишний ACCEPT ничего не ослабляет.
XRAY_IPS=$(getent hosts xr 2>/dev/null | awk '{print $1}' | tr '\n' ' ')
SOCKS_ALLOW="${WARP_SOCKS_ALLOW:-${XRAY_IPS:-10.10.0.9}}"
if [ "$(jq -r '.settings.egress // empty' /config/protocols/anytls/desired.json 2>/dev/null)" = warp ]; then
    SOCKS_ALLOW="$SOCKS_ALLOW 10.10.0.22"
fi
if [ "$(jq -r '.settings.egress // empty' /config/protocols/mieru/desired.json 2>/dev/null)" = warp ]; then
    SOCKS_ALLOW="$SOCKS_ALLOW 10.10.0.23"
fi
if [ "$(jq -r '.settings.egress // empty' /config/protocols/tuic/desired.json 2>/dev/null)" = warp ]; then
    SOCKS_ALLOW="$SOCKS_ALLOW 10.10.0.24"
fi
if [ "$(jq -r '.settings.egress // empty' /config/protocols/shadowtls/desired.json 2>/dev/null)" = warp ]; then
    SOCKS_ALLOW="$SOCKS_ALLOW 10.10.0.25"
fi

if [ "$(jq -r '.settings.egress // empty' /config/protocols/masque/desired.json 2>/dev/null)" = warp ]; then
    SOCKS_ALLOW="$SOCKS_ALLOW 10.10.0.27"
fi

# Второй легитимный потребитель — контейнер ss, но только когда админ включил
# тумблер «ss через warp» (меню SS). Состояние живёт там же, где его читает
# демон: ключ outbound_proxy в ssserver.json — отдельного флага в pac.json нет,
# чтобы нечему было разъезжаться с конфигом. Резолвим тут же, по той же
# причине, что и xr: ниже мы перепишем resolv.conf, и docker-DNS исчезнет.
# Тумблер вставляет это же правило вживую (Bot::warpSocksAllowCmd), здесь оно
# нужно, чтобы пережить пересоздание wp.
if [ -n "$(jq -r '.outbound_proxy // empty' /config/ssserver.json 2>/dev/null)" ]; then
    SS_IPS=$(getent hosts ss 2>/dev/null | awk '{print $1}' | tr '\n' ' ')
    SOCKS_ALLOW="$SOCKS_ALLOW ${SS_IPS:-10.10.0.6}"
    echo "[warp] ss через warp включён — пускаем ${SS_IPS:-10.10.0.6} в SOCKS"
fi

mkdir -p "$WGCF_DIR"
cd "$WGCF_DIR"

# wgcf ходит в API Cloudflare, а сеть на старте контейнера может быть ещё не
# готова — все вызовы wgcf идут с ретраями (4 попытки, бэкофф 5/15/30с).
retry() {
    local delay
    for delay in 5 15 30; do
        "$@" && return 0
        echo "[warp] '$*' failed, retry in ${delay}s..."
        sleep "$delay"
    done
    "$@"
}

# Профиль wgcf-profile.conf — единственное, что нужно wg-quick для подъёма
# туннеля. Аккаунт wgcf-account.toml нужен лишь чтобы СГЕНЕРИРОВАТЬ профиль.
# Раньше оба шага (register и generate) сидели под одним условием
# `[ ! -f profile.conf ]`. Когда аккаунт уже был, а профиль пропадал (частый
# кейс после ручной пересборки: named-volume vpnbot_warp сохраняет
# account.toml, но profile.conf в нём не оказывалось), скрипт всё равно шёл
# регистрироваться, `wgcf register` падал с "existing account detected", а
# из-за set -e умирал весь скрипт → контейнер в креш-луп (off/красный).
# Поэтому условия РАЗДЕЛЕНЫ и теперь независимы:
#   1) регистрируем аккаунт, только если его нет;
#   2) генерируем профиль, только если его нет (в т.ч. восстанавливаем
#      пропавший профиль из уже существующего аккаунта — чинит случай рабочего сервера).
# Аккаунт и профиль WireGuard. Функция, а не код верхнего уровня: в режиме
# MASQUE аккаунт WireGuard не нужен, и сбой его регистрации не должен ронять
# контейнер — он заводится позже, при первом переключении на WireGuard.
wg_bootstrap() {
    if [ ! -f "$WGCF_TOML" ]; then
        echo "[warp] Registering WARP account..."
        retry wgcf register --accept-tos || return 1
        if [ -n "$WARP_LICENSE_KEY" ]; then
            echo "[warp] Applying license key..."
            # Заменяем license_key в wgcf-account.toml на WARP_LICENSE_KEY.
            # Через awk с -v, а не через sed-интерполяцию: значение приходит из
            # pac.json (его вводит пользователь в боте) и попадало прямо в ТЕЛО
            # sed-выражения — символы /, & и \ ломали выражение или подставляли не
            # тот текст, причём код возврата не проверялся, и следующий
            # `wgcf update` тихо уходил со старым ключом. Плюс ключ переставал
            # светиться в argv (`ps` внутри контейнера).
            if grep -q '^license_key' "$WGCF_TOML"; then
                tmp_toml="$WGCF_TOML.tmp.$$"
                if LK="$WARP_LICENSE_KEY" awk '
                        /^license_key/ { printf "license_key = \"%s\"\n", ENVIRON["LK"]; next }
                        { print }
                    ' "$WGCF_TOML" > "$tmp_toml" && [ -s "$tmp_toml" ]; then
                    cat "$tmp_toml" > "$WGCF_TOML"
                else
                    echo "[warp] WARNING: не удалось подставить license key — оставляем прежний"
                fi
                rm -f "$tmp_toml"
            fi
            # Провал update (невалидный/исчерпанный ключ) НЕ фатален: иначе скрипт
            # умирал до generate, рестартился, на втором проходе блок пропускался
            # (toml уже есть) — и warp молча поднимался free-tier. Лучше явный
            # WARNING в лог и тот же free-tier без лишнего краш-цикла.
            retry wgcf update || \
                echo "[warp] WARNING: wgcf update failed — license key NOT applied, continuing free tier"
        fi
    fi

    if [ ! -f "$WGCF_CONF" ]; then
        echo "[warp] Generating WireGuard profile..."
        retry wgcf generate || return 1
    fi

    # wgcf кладёт account.toml с 0644, а в нём лежат private_key аккаунта и
    # access_token — им управляют подпиской WARP+. Профиль wg-quick и так требует
    # 0600, аккаунт приводим к тому же.
    chmod 600 "$WGCF_TOML" "$WGCF_CONF" 2>/dev/null || true

    # Фиксапы профиля (IPv6 из списков, DNS-строка, PersistentKeepalive) — общий
    # с кнопкой «set key» бота скрипт, правки только в warp_fixup.sh. Выполняется
    # БЕЗУСЛОВНО при каждом старте, а не при генерации: профиль обычно уже лежит
    # в named-volume, и блок генерации выше не выполняется.
    sh /warp_fixup.sh || return 1
}
if [ "$MODE" = wireguard ]; then
    wg_bootstrap
fi

# Кнопка «warp on/off» в боте пишет флаг warpoff в pac.json. Читаем его И на
# старте, И в watchdog'е: иначе сторож через три минуты поднял бы туннель
# обратно, и выключатель выглядел бы сломанным.
warp_disabled() {
    [ "$(jq -r '.warpoff // empty' /config/pac.json 2>/dev/null)" = "1" ]
}

# Kill-switch: SOCKS поднимается ТОЛЬКО при живом туннеле.
#
# Раньше прокси слушал :1080 независимо от состояния wgcf-profile, а правила
# iptables ниже ограничивают лишь ВХОД в прокси, не выход из контейнера. Когда
# туннеля нет, у контейнера остаётся обычный default route через docker-bridge,
# и весь трафик, отправленный xray в outbound «warp», уходил с ПУБЛИЧНОГО IP
# сервера. Молча: соединения проходят успешно, просто с другим адресом, в
# логах ничего. Для того, кто включил маршрут «через WARP» ради смены гео или
# сокрытия IP сервера, это тихая деанонимизация. Окон было три: bounce сторожа
# (down → up), неудачный up (код возврата не проверялся при set +e) и
# warpoff/сбой на старте.
#
# Теперь при отсутствии туннеля порт просто закрыт: соединение к прокси
# отвергается, xray помечает outbound нерабочим — отказ вместо утечки.
WGCF_IF="$(basename "$WGCF_CONF" .conf)"

# Остановка процесса сторожем не закрывает окно после внешнего удаления
# интерфейса или wg-quick down из бота. Прокси работает под отдельным UID:
# его исходящие соединения разрешены ядром только через WARP, даже если
# исчезли policy routes. Ответы уже подключённым SOCKS-клиентам сохраняем.
id warp-proxy >/dev/null 2>&1 || adduser -D -H -s /sbin/nologin warp-proxy
PROXY_UID=$(id -u warp-proxy)
case "$SOCKS_PORT" in ''|*[!0-9]*) echo "Invalid SOCKS_PORT" >&2; exit 1;; esac
# Адрес и протокол узла MASQUE; задаются в masque_up().
MASQUE_ENDPOINT=""
MASQUE_PROTO=udp
MS_PID=""
# Цепочка зависит от режима и перестраивается с нуля. Пока в ней нет
# завершающего REJECT, она пропускает всё, поэтому при работающем прокси
# функция отказывает: сначала socks_stop.
proxy_firewall() {
    if [ -n "$MS_PID" ] && kill -0 "$MS_PID" 2>/dev/null; then
        return 1
    fi
    for firewall in iptables ip6tables; do
        "$firewall" -N WARP_PROXY_OUT 2>/dev/null || "$firewall" -F WARP_PROXY_OUT
        "$firewall" -A WARP_PROXY_OUT -p tcp --sport "$SOCKS_PORT" -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN
        "$firewall" -A WARP_PROXY_OUT -p udp --sport "$SOCKS_UDP_PORTS" -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN
        if [ "$firewall" = iptables ]; then
            private_nets="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4"
        else
            private_nets="::/128 ::1/128 ::ffff:0:0/96 fc00::/7 fe80::/10 ff00::/8"
        fi
        for net in $private_nets; do
            "$firewall" -A WARP_PROXY_OUT -d "$net" -j REJECT
        done
        if [ "$MODE" = masque ]; then
            # Интерфейса туннеля нет: соединение с узлом Cloudflare держит сам
            # прокси. Ему разрешён только этот адрес и порт 443 — всё прикладное
            # идёт внутри туннеля. Узел IPv4, по IPv6 не разрешено ничего. Пока
            # адрес неизвестен, прокси не выпускается никуда.
            if [ "$firewall" = iptables ] && [ -n "$MASQUE_ENDPOINT" ]; then
                "$firewall" -A WARP_PROXY_OUT -d "$MASQUE_ENDPOINT" -p "$MASQUE_PROTO" --dport 443 -j RETURN || return 1
            fi
        else
            "$firewall" -A WARP_PROXY_OUT -o "$WGCF_IF" -j RETURN
        fi
        "$firewall" -A WARP_PROXY_OUT -j REJECT || return 1
    done
}
proxy_firewall

# Конфиг не содержит учётных данных. Сам процесс и все его дочерние процессы
# работают без root; UID-фильтр действует и на DNS, и на UDP, и на TCP.
# Диапазон задаётся только в сетевом namespace контейнера wp, не на хосте.
# ash читает builtin read по байту; некоторые proc/sys-файлы при следующем
# чтении уже возвращают EOF. С set -e это прерывало штатный запуск через sh.
udp_range=$(awk '{print $1 ":" $2}' /proc/sys/net/ipv4/ip_local_port_range)
if [ "$udp_range" != "$SOCKS_UDP_PORTS" ]; then
    echo "[warp] Incorrect UDP relay range; recreate wp with current compose" >&2
    exit 1
fi
cat > /run/warp-socks.json <<EOF
{
  "log": {"loglevel": "warning", "access": "none"},
  "inbounds": [{
    "listen": "0.0.0.0", "port": $SOCKS_PORT, "protocol": "socks",
    "settings": {"auth": "noauth", "udp": true}
  }],
  "outbounds": [{"protocol": "freedom", "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4"}}}]
}
EOF
chmod 644 /run/warp-socks.json

tunnel_up() {
    wg show "$WGCF_IF" >/dev/null 2>&1
}

# Поднять туннель и дождаться РЕАЛЬНОГО рукопожатия: `wg-quick up` возвращает
# успех, даже когда endpoint не отвечает.
warp_up() {
    wg-quick up "$WGCF_CONF" || return 1
    # Служебный порт WireGuard отделён от SOCKS relay и не опубликован.
    # Это нужно до handshake, в том числе при повторном подъёме watchdog.
    if ! wg set "$WGCF_IF" listen-port 51820; then
        wg-quick down "$WGCF_CONF" 2>/dev/null || true
        return 1
    fi
    i=0
    while [ "$i" -lt 15 ]; do
        hs=$(wg show "$WGCF_IF" latest-handshakes 2>/dev/null | awk '{print $2}' | sort -n | tail -1)
        if [ -n "$hs" ] && [ "$hs" -gt 0 ] 2>/dev/null; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    # Интерфейс создаётся до handshake. Не оставляем его после неудачи:
    # tunnel_up() иначе принял бы его за готовый туннель на следующем тике.
    wg-quick down "$WGCF_CONF" 2>/dev/null || true
    return 1
}

# MASQUE: аккаунт (при первом включении регистрируется сам, как и аккаунт
# WireGuard), конфиг прокси с проверкой ядром и правило для адреса узла.
# Туннель прокси устанавливает при первом запросе, поэтому его живость
# подтверждает уже проба сторожа, а не эта функция.
MASQUE_READY=0
MASQUE_ACCOUNT=""
# Авторегистрация устройства повторяется с растущей паузой: 2, 4, 8… минут, но
# не реже раза в 6 часов. Попытка, дошедшая до Cloudflare, создаёт там новое
# устройство, а сторож возвращается сюда каждую минуту: без паузы отказ
# привязки ключа давал бы сотни регистраций в сутки и упирался в лимит
# Cloudflare, общий с режимом WireGuard. Отметка «число отказов и время
# последнего» лежит в томе warp и переживает перезапуск контейнера. Бот
# регистрирует устройство по команде администратора и паузы не ждёт.
MASQUE_RETRY="$WGCF_DIR/masque.retry"
MASQUE_WAITING=0
masque_register_fails() {
    fails=0
    if [ -f "$MASQUE_RETRY" ]; then read -r fails _ < "$MASQUE_RETRY" || true; fi
    # Число с ведущим нулём оболочка прочла бы как восьмеричное.
    case "$fails" in ''|*[!0-9]*|0?*|???????*) fails=0 ;; esac
    echo "$fails"
}
# Сколько секунд осталось до следующей попытки; 0 — можно пробовать.
masque_register_wait() {
    fails=$(masque_register_fails)
    [ "$fails" -gt 0 ] || { echo 0; return 0; }
    last=0
    read -r _ last < "$MASQUE_RETRY" || true
    case "$last" in ''|*[!0-9]*|0?*|????????????*) last=0 ;; esac
    pause=120
    n=1
    while [ "$n" -lt "$fails" ] && [ "$pause" -lt 21600 ]; do
        pause=$((pause * 2))
        n=$((n + 1))
    done
    [ "$pause" -le 21600 ] || pause=21600
    left=$((last + pause - $(date +%s)))
    # Часы ушли назад дальше самой паузы — такой отметке не верим.
    if [ "$left" -le 0 ] || [ "$left" -gt "$pause" ]; then echo 0; else echo "$left"; fi
}
masque_up() {
    MASQUE_READY=0
    if ! sh /warp_masque.sh exists; then
        left=$(masque_register_wait)
        if [ "$left" -gt 0 ]; then
            # Одна строка на всю паузу, а не каждую минуту.
            [ "$MASQUE_WAITING" = 1 ] || echo "[warp] MASQUE: no device, next registration attempt in $(((left + 59) / 60)) min"
            MASQUE_WAITING=1
            return 1
        fi
        MASQUE_WAITING=0
        echo "[warp] MASQUE: registering device..."
        if ! sh /warp_masque.sh register >/dev/null; then
            echo "$(($(masque_register_fails) + 1)) $(date +%s)" > "$MASQUE_RETRY"
            echo "[warp] MASQUE: registration failed, next attempt in $((($(masque_register_wait) + 59) / 60)) min"
            MASQUE_WAITING=1
            return 1
        fi
        sh /warp_masque.sh commit
    fi
    MASQUE_WAITING=0
    rm -f "$MASQUE_RETRY"
    MASQUE_ENDPOINT=$(sh /warp_masque.sh endpoint) || { echo "[warp] MASQUE: no valid endpoint in the account"; return 1; }
    if [ "$ALPN" = h2 ]; then MASQUE_PROTO=tcp; else MASQUE_PROTO=udp; fi
    # Имя оканчивается на .json: ядро определяет формат конфига по расширению.
    (umask 077; sh /warp_masque.sh config "$SOCKS_PORT" "$ALPN" > /run/warp-socks-masque.new.json) || return 1
    if ! warp-socks run -test -config /run/warp-socks-masque.new.json >/dev/null 2>&1; then
        echo "[warp] MASQUE: proxy config rejected by the core"
        rm -f /run/warp-socks-masque.new.json
        return 1
    fi
    # В этом конфиге закрытый ключ устройства: читать его может только прокси.
    chown root:warp-proxy /run/warp-socks-masque.new.json || return 1
    chmod 640 /run/warp-socks-masque.new.json || return 1
    mv /run/warp-socks-masque.new.json /run/warp-socks-masque.json || return 1
    proxy_firewall || return 1
    echo "[warp] MASQUE: endpoint $MASQUE_ENDPOINT $MASQUE_PROTO/443 ($ALPN)"
    MASQUE_ACCOUNT=$(masque_account)
    MASQUE_READY=1
}

# Общие для обоих режимов «поднять», «опустить» и «готов ли» — ими пользуются
# запуск и сторож.
link_ready() {
    if [ "$MODE" = masque ]; then [ "$MASQUE_READY" = 1 ]; else tunnel_up; fi
}
link_up() {
    if [ "$MODE" = masque ]; then
        masque_up
    else
        [ -f "$WGCF_CONF" ] || wg_bootstrap || return 1
        warp_up
    fi
}
link_down() {
    MASQUE_READY=0
    # Конфиг с закрытым ключом устройства не оставляем после выхода из режима.
    rm -f /run/warp-socks-masque.json /run/warp-socks-masque.new.json
    wg-quick down "$WGCF_CONF" 2>/dev/null || true
}
# Отметка «прокси работает в таком-то режиме»: по ней бот узнаёт, что сторож
# уже выполнил переключение.
mode_name() {
    if [ "$1" = masque ]; then echo "masque $2"; else echo wireguard; fi
}
mode_mark() {
    mode_name "$MODE" "$ALPN" > /run/warp-mode
}
# Отпечаток аккаунта MASQUE: бот мог перерегистрировать устройство (смена
# ключа WARP+), и тогда конфиг прокси нужно собрать заново.
masque_account() {
    cksum /etc/warp/masque/device.json 2>/dev/null || true
}

socks_running() {
    [ -n "$MS_PID" ] && kill -0 "$MS_PID" 2>/dev/null
}
socks_start() {
    # WireGuard сохраняет владельца исходного сокета у зашифрованного UDP
    # пакета. Его выпускаем по fwmark wg-quick; непривилегированный процесс
    # SOCKS сам выставить этот mark не может. Без исключения UID-фильтр
    # блокировал бы и настоящий туннель, а не только прямой выход.
    # В режиме MASQUE туннеля WireGuard и его метки нет: прокси выходит
    # только к узлу, правило для которого ставит masque_up().
    if [ "$MODE" = masque ]; then
        [ "$MASQUE_READY" = 1 ] || return 1
        socks_config=/run/warp-socks-masque.json
    else
        socks_config=/run/warp-socks.json
        tunnel_mark=$(wg show "$WGCF_IF" fwmark) || return 1
        case "$tunnel_mark" in ''|off|0|0x0|*[!0-9a-fx]*) return 1;; esac
        for firewall in iptables ip6tables; do
            "$firewall" -C WARP_PROXY_OUT -p udp -m mark --mark "$tunnel_mark" -j RETURN 2>/dev/null \
                || "$firewall" -I WARP_PROXY_OUT 1 -p udp -m mark --mark "$tunnel_mark" -j RETURN \
                || return 1
        done
    fi
    if socks_running; then
        mode_mark
        return 0
    fi
    echo "[warp] Starting Xray SOCKS5 TCP:$SOCKS_PORT UDP:$SOCKS_UDP_PORTS ($MODE)..."
    su -s /bin/sh -c "exec warp-socks run -config $socks_config" warp-proxy &
    MS_PID=$!
    mode_mark
}
socks_stop() {
    rm -f /run/warp-mode
    socks_running || return 0
    echo "[warp] Stopping SOCKS: туннеля нет, выпускать трафик мимо WARP нельзя"
    pkill -x warp-socks 2>/dev/null || true
    wait "$MS_PID" 2>/dev/null || true
    MS_PID=""
}

# best-effort down: чистит хвосты (интерфейс/маршруты) после нештатного рестарта
wg-quick down "$WGCF_CONF" 2>/dev/null || true
if warp_disabled; then
    echo "[warp] disabled via warpoff in pac.json — tunnel not started"
else
    echo "[warp] Starting WARP ($MODE)..."
    link_up || echo "[warp] tunnel did NOT come up — SOCKS остаётся закрытым до восстановления"
fi

# DNS контейнера — через туннель. Пишем напрямую, без resolvconf (он в docker
# не работает, см. выше). 1.1.1.1 доступен и БЕЗ туннеля, поэтому резолв
# endpoint'а (engage.cloudflareclient.com) при пере-поднятии не ломается.
printf 'nameserver 1.1.1.1\nnameserver 1.0.0.1\n' > /etc/resolv.conf

# SOCKS слушает 0.0.0.0, а в docker-сети проекта он виден
# КАЖДОМУ контейнеру. Клиент любого VPN тоже попадает сюда: его трафик
# маскируется под адрес своего контейнера (например 10.8.0.0/24 -> 10.10.0.19
# у openvpn), то есть выглядит как обычный внутренний источник. В итоге прокси
# работал как открытый SOCKS5 без пароля: и выход наружу через WARP, и доступ
# к внутренним сервисам проекта (проверено — adguard отвечал через него).
# Пускаем только петлю (warp_probe.sh + healthcheck) и xray, ради outbound
# которого прокси и существует. Список xray переопределяется WARP_SOCKS_ALLOW
# (адреса через пробел) — на случай нестандартной адресации в override.
# Адрес ss (блок в начале файла) в это переопределение НЕ входит: он
# дописывается поверх, когда включён тумблер «ss через warp», иначе тумблер
# молча ломался бы на каждом хосте с заданным WARP_SOCKS_ALLOW.
echo "[warp] Restricting SOCKS $SOCKS_PORT to: lo $SOCKS_ALLOW"
echo "[warp] (WARP_SOCKS_ALLOW=\"ip1 ip2\" overrides the xray part if xray lives elsewhere)"
if iptables -N WARP_SOCKS 2>/dev/null; then :; else iptables -F WARP_SOCKS; fi
iptables -C INPUT -p tcp --dport "$SOCKS_PORT" -j WARP_SOCKS 2>/dev/null \
    || iptables -I INPUT -p tcp --dport "$SOCKS_PORT" -j WARP_SOCKS
# Ответы внешних UDP-серверов приходят через wgcf-profile. ACL ограничивает
# только клиентскую сторону relay: пакеты, пришедшие НЕ через туннель.
iptables -C INPUT ! -i "$WGCF_IF" -p udp --dport "$SOCKS_UDP_PORTS" -j WARP_SOCKS 2>/dev/null \
    || iptables -I INPUT ! -i "$WGCF_IF" -p udp --dport "$SOCKS_UDP_PORTS" -j WARP_SOCKS
iptables -A WARP_SOCKS -i lo -j ACCEPT
# Служебные UDP-запросы контейнера (например DNS при выключенном WARP)
# используют тот же ephemeral-диапазон. Пропускаем только ответы на них:
# новые запросы к SOCKS relay по-прежнему ограничены списком клиентов.
iptables -A WARP_SOCKS -p udp -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT
for ip in $SOCKS_ALLOW; do
    iptables -A WARP_SOCKS -s "$ip" -j ACCEPT
done
iptables -A WARP_SOCKS -j DROP

# Вторая половина того же ограничения — по НАЗНАЧЕНИЮ. Фильтр выше закрывает
# только вход в прокси, но пускать туда xray обязаны: sing-box-шаблоны заводят
# outbound warpSOCKS5 на 10.10.0.13:1080 с detour через VLESS, поэтому Xray
# видит этот адрес как клиентское назначение и гейт в боте (Bot::WARP_SOCKS_IP)
# держит для него точечное direct-правило. Убрать ту дырку нельзя — у клиента
# сразу отваливаются все сайты, идущие через WARP.
#
# Ограничиваем и ВЫХОД: SOCKS принимает назначения от клиента, включая
# внутренние адреса проекта. Без этого
# блока любой клиент VPN, дозвонившись до прокси, ходил бы через него в
# docker-сеть (панель, AdGuard, sshd контейнеров, socks-inbound'ы xray) в обход
# гейта. Выход в интернет через туннель WARP — назначения публичные — не задет.
WARP_SOCKS_DENY_OUT="${WARP_SOCKS_DENY_OUT:-10.10.0.0/16}"
if iptables -N WARP_SOCKS_OUT 2>/dev/null; then :; else iptables -F WARP_SOCKS_OUT; fi
iptables -C OUTPUT -j WARP_SOCKS_OUT 2>/dev/null \
    || iptables -I OUTPUT -j WARP_SOCKS_OUT
# Петля (warp_probe.sh, healthcheck, docker-DNS 127.0.0.11) и ответы на уже
# установленные сессии — ssh бота в этот контейнер, ответы самого прокси в xray
# — обязаны проходить. Матчер состояния критичен: без него REJECT ниже оборвал
# бы и ответные пакеты. Поэтому при отсутствии conntrack/state правило DENY НЕ
# ставим вовсе (лучше прежнее поведение, чем оборванный ssh и мёртвый WARP).
iptables -A WARP_SOCKS_OUT -o lo -j ACCEPT
if iptables -A WARP_SOCKS_OUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
    || iptables -A WARP_SOCKS_OUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
    echo "[warp] Blocking SOCKS egress to: $WARP_SOCKS_DENY_OUT"
    echo "[warp] (override with WARP_SOCKS_DENY_OUT=\"net1 net2\", empty value disables)"
    for net in $WARP_SOCKS_DENY_OUT; do
        iptables -A WARP_SOCKS_OUT -d "$net" -j REJECT --reject-with icmp-port-unreachable \
            2>/dev/null || iptables -A WARP_SOCKS_OUT -d "$net" -j DROP
    done
else
    echo "[warp] WARN: нет conntrack/state match — egress-ACL прокси НЕ установлен" >&2
fi

# Строго ПЕРЕД общей WARP_SOCKS_OUT: её ACCEPT для loopback и established
# нужен служебным процессам, но не должен обходить ограничения SOCKS.
for firewall in iptables ip6tables; do
    "$firewall" -D OUTPUT -m owner --uid-owner "$PROXY_UID" -j WARP_PROXY_OUT 2>/dev/null || true
    "$firewall" -I OUTPUT 1 -m owner --uid-owner "$PROXY_UID" -j WARP_PROXY_OUT
done

if link_ready; then
    socks_start || echo "[warp] SOCKS не запущен: нет fwmark туннеля или не встало правило фильтра"
else
    echo "[warp] SOCKS не запущен: нет туннеля WARP (см. kill-switch выше)"
fi

# ---- watchdog ----
# Раз в 60с — warp_probe.sh (общий с healthcheck'ом): trace Cloudflare через
# socks5h должен ответить warp=on|plus, а при отсутствии curl в образе
# (stale/апстримный) — fallback на возраст handshake. 3 подряд провала →
# пере-поднимаем туннель (свежий handshake + пере-резолв endpoint). Если и
# после 3 пере-поднятий подряд не ожил — exit 1: контейнер перезапустит
# restart-политика (unless-stopped в compose), это чинит и умерший sshd/т.п.
# Профиль и аккаунт НЕ трогаем: авто-перегенерация при ложном срабатывании
# потеряла бы аккаунт с license key.
# Пауза между проходами прерывается ботом (touch /run/warp-kick после кнопок
# «включить» и «set key»): иначе туннель уже поднят, а SOCKS ждал бы следующего
# прохода до минуты, и всё это время маршруты «через WARP» не работали бы.
# Файл при запуске не удаляется: сигнал мог прийти, пока скрипт ещё стартовал,
# и тогда первый проход просто случится сразу.
wait_tick() {
    waited=0
    while [ "$waited" -lt 60 ]; do
        if [ -e /run/warp-kick ]; then
            rm -f /run/warp-kick
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done
}
set +e
FAILS=0
BOUNCES=0
while true; do
    wait_tick
    # Бот сменил режим или транспорт MASQUE: прокси гасим первым, прежний
    # туннель убираем, фильтр перестраиваем под новый режим — и дальше обычный
    # путь «туннеля нет → поднять».
    want_mode=$(warp_mode)
    want_alpn=$(masque_alpn)
    if [ "$want_mode" != "$MODE" ] || { [ "$MODE" = masque ] && [ "$want_alpn" != "$ALPN" ]; } \
        || { [ "$MODE" = masque ] && [ "$MASQUE_READY" = 1 ] && [ "$(masque_account)" != "$MASQUE_ACCOUNT" ]; }; then
        echo "[warp] switching mode: $(mode_name "$MODE" "$ALPN") -> $(mode_name "$want_mode" "$want_alpn")"
        socks_stop
        link_down
        MODE=$want_mode
        ALPN=$want_alpn
        MASQUE_ENDPOINT=""
        proxy_firewall || echo "[warp] kill-switch chain was NOT rebuilt"
        FAILS=0
        BOUNCES=0
    fi
    # Выключен намеренно — туннеля быть не должно, а значит и прокси тоже.
    if warp_disabled; then
        socks_stop
        FAILS=0
        BOUNCES=0
        continue
    fi
    # Туннель лежит (не поднялся на старте или сдох): пробу гонять бесполезно,
    # она идёт ЧЕРЕЗ прокси, а прокси мы держим закрытым. Сначала поднимаем.
    if ! link_ready; then
        if link_up; then
            socks_start || echo "[warp] SOCKS не запущен: нет fwmark туннеля или не встало правило фильтра"
            FAILS=0
            # Прокси только что запущен и ещё не слушает порт: проба в этом же
            # проходе дала бы ложный отказ. Проверим на следующем.
            continue
        else
            # Пауза перед повторной регистрацией MASQUE — не сбой туннеля:
            # перезапуск контейнера её не сократит.
            if [ "$MODE" = masque ] && [ "$MASQUE_WAITING" = 1 ]; then
                continue
            fi
            BOUNCES=$((BOUNCES + 1))
            echo "[warp] tunnel still down (attempt $BOUNCES/3)"
            if [ "$BOUNCES" -gt 3 ]; then
                echo "[warp] tunnel did not recover after 3 restarts — exiting for container restart"
                exit 1
            fi
            continue
        fi
    fi
    if ! socks_running; then
        echo "[warp] SOCKS is not running — starting..."
        socks_start || echo "[warp] SOCKS не запущен: нет fwmark туннеля или не встало правило фильтра"
        continue
    fi
    if sh /warp_probe.sh; then
        FAILS=0
        BOUNCES=0
        continue
    fi
    FAILS=$((FAILS + 1))
    echo "[warp] health check failed ($FAILS/3)"
    if [ "$FAILS" -ge 3 ]; then
        BOUNCES=$((BOUNCES + 1))
        if [ "$BOUNCES" -gt 3 ]; then
            echo "[warp] tunnel did not recover after 3 restarts — exiting for container restart"
            exit 1
        fi
        echo "[warp] restarting tunnel (bounce $BOUNCES/3)..."
        # Прокси гасим НА ВРЕМЯ пере-поднятия: именно в это окно трафик уходил
        # мимо туннеля с публичного IP сервера.
        socks_stop
        link_down
        if link_up; then
            socks_start || echo "[warp] SOCKS не запущен: нет fwmark туннеля или не встало правило фильтра"
        else
            echo "[warp] bounce failed — SOCKS остаётся закрытым"
        fi
        FAILS=0
    fi
done
