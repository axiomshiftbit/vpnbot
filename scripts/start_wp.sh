#!/bin/bash
set -e
mkdir -p /logs
exec >>/logs/warp 2>&1

cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
# Без exec: `exec cmd &` порождает подоболочку, которую exec собой и заменяет,
# т.е. работает как обычный фоновый запуск, но читается как «заменить текущий
# процесс» — и сбивает с толку при чтении скрипта.
/usr/sbin/sshd -D -e "$@" &

WGCF_DIR="/etc/warp"
WGCF_CONF="$WGCF_DIR/wgcf-profile.conf"
WGCF_TOML="$WGCF_DIR/wgcf-account.toml"
SOCKS_PORT="${SOCKS_PORT:-1080}"

WARP_LICENSE_KEY=$(cat /config/pac.json | jq -r '.warp // empty')

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
if [ ! -f "$WGCF_TOML" ]; then
    echo "[warp] Registering WARP account..."
    retry wgcf register --accept-tos
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
    retry wgcf generate
fi

# wgcf кладёт account.toml с 0644, а в нём лежат private_key аккаунта и
# access_token — им управляют подпиской WARP+. Профиль wg-quick и так требует
# 0600, аккаунт приводим к тому же.
chmod 600 "$WGCF_TOML" "$WGCF_CONF" 2>/dev/null || true

# Фиксапы профиля (IPv6 из списков, DNS-строка, PersistentKeepalive) — общий
# с кнопкой «set key» бота скрипт, правки только в warp_fixup.sh. Выполняется
# БЕЗУСЛОВНО при каждом старте, а не при генерации: профиль обычно уже лежит
# в named-volume, и блок генерации выше не выполняется.
sh /warp_fixup.sh

# Кнопка «warp on/off» в боте пишет флаг warpoff в pac.json. Читаем его И на
# старте, И в watchdog'е: иначе сторож через три минуты поднял бы туннель
# обратно, и выключатель выглядел бы сломанным.
warp_disabled() {
    [ "$(jq -r '.warpoff // empty' /config/pac.json 2>/dev/null)" = "1" ]
}

# Kill-switch: microsocks поднимается ТОЛЬКО при живом туннеле.
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
for firewall in iptables ip6tables; do
    "$firewall" -N WARP_PROXY_OUT 2>/dev/null || "$firewall" -F WARP_PROXY_OUT
    "$firewall" -A WARP_PROXY_OUT -p tcp --sport "$SOCKS_PORT" -m conntrack --ctstate ESTABLISHED -j RETURN
    if [ "$firewall" = iptables ]; then
        private_nets="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4"
    else
        private_nets="::/128 ::1/128 ::ffff:0:0/96 fc00::/7 fe80::/10 ff00::/8"
    fi
    for net in $private_nets; do
        "$firewall" -A WARP_PROXY_OUT -d "$net" -j REJECT
    done
    "$firewall" -A WARP_PROXY_OUT -o "$WGCF_IF" -j RETURN
    "$firewall" -A WARP_PROXY_OUT -j REJECT
done

tunnel_up() {
    wg show "$WGCF_IF" >/dev/null 2>&1
}

# Поднять туннель и дождаться РЕАЛЬНОГО рукопожатия: `wg-quick up` возвращает
# успех, даже когда endpoint не отвечает.
warp_up() {
    wg-quick up "$WGCF_CONF" || return 1
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

MS_PID=""
socks_running() {
    [ -n "$MS_PID" ] && kill -0 "$MS_PID" 2>/dev/null
}
socks_start() {
    # WireGuard сохраняет владельца исходного сокета у зашифрованного UDP
    # пакета. Его выпускаем по fwmark wg-quick; непривилегированный процесс
    # microsocks сам выставить этот mark не может. Без исключения UID-фильтр
    # блокировал бы и настоящий туннель, а не только прямой выход.
    tunnel_mark=$(wg show "$WGCF_IF" fwmark) || return 1
    case "$tunnel_mark" in ''|off|0|0x0|*[!0-9a-fx]*) return 1;; esac
    for firewall in iptables ip6tables; do
        "$firewall" -C WARP_PROXY_OUT -p udp -m mark --mark "$tunnel_mark" -j RETURN 2>/dev/null \
            || "$firewall" -I WARP_PROXY_OUT 1 -p udp -m mark --mark "$tunnel_mark" -j RETURN \
            || return 1
    done
    socks_running && return 0
    echo "[warp] Starting microsocks on port $SOCKS_PORT..."
    su -s /bin/sh -c "exec microsocks -p $SOCKS_PORT" warp-proxy &
    MS_PID=$!
}
socks_stop() {
    socks_running || return 0
    echo "[warp] Stopping microsocks: туннеля нет, выпускать трафик мимо WARP нельзя"
    kill "$MS_PID" 2>/dev/null
    MS_PID=""
}

# best-effort down: чистит хвосты (интерфейс/маршруты) после нештатного рестарта
wg-quick down "$WGCF_CONF" 2>/dev/null || true
if warp_disabled; then
    echo "[warp] disabled via warpoff in pac.json — tunnel not started"
else
    echo "[warp] Starting WireGuard (WARP)..."
    warp_up || echo "[warp] tunnel did NOT come up — SOCKS остаётся закрытым до восстановления"
fi

# DNS контейнера — через туннель. Пишем напрямую, без resolvconf (он в docker
# не работает, см. выше). 1.1.1.1 доступен и БЕЗ туннеля, поэтому резолв
# endpoint'а (engage.cloudflareclient.com) при пере-поднятии не ломается.
printf 'nameserver 1.1.1.1\nnameserver 1.0.0.1\n' > /etc/resolv.conf

# microsocks не умеет ACL и слушает 0.0.0.0, а в docker-сети проекта он виден
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
iptables -A WARP_SOCKS -i lo -j ACCEPT
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
# Значит режем не вход, а ВЫХОД: microsocks не умеет ACL по назначению и
# выполняет CONNECT куда попросят, включая внутренние адреса проекта. Без этого
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
# нужен служебным процессам, но не должен обходить ограничения microsocks.
for firewall in iptables ip6tables; do
    "$firewall" -D OUTPUT -m owner --uid-owner "$PROXY_UID" -j WARP_PROXY_OUT 2>/dev/null || true
    "$firewall" -I OUTPUT 1 -m owner --uid-owner "$PROXY_UID" -j WARP_PROXY_OUT
done

if tunnel_up; then
    socks_start
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
set +e
FAILS=0
BOUNCES=0
while true; do
    sleep 60
    # Выключен намеренно — туннеля быть не должно, а значит и прокси тоже.
    if warp_disabled; then
        socks_stop
        FAILS=0
        BOUNCES=0
        continue
    fi
    # Туннель лежит (не поднялся на старте или сдох): пробу гонять бесполезно,
    # она идёт ЧЕРЕЗ прокси, а прокси мы держим закрытым. Сначала поднимаем.
    if ! tunnel_up; then
        if warp_up; then
            socks_start
            FAILS=0
        else
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
        echo "[warp] microsocks died — restarting..."
        socks_start
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
        wg-quick down "$WGCF_CONF" 2>/dev/null
        if warp_up; then
            socks_start
        else
            echo "[warp] bounce failed — SOCKS остаётся закрытым"
        fi
        FAILS=0
    fi
done
