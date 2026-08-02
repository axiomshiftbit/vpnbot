#!/bin/bash
set -e

cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
exec /usr/sbin/sshd -D -e "$@" &

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
        # Заменяем license_key в wgcf-account.toml на WARP_LICENSE_KEY
        if grep -q '^license_key' "$WGCF_TOML"; then
            sed -i "s/^license_key.*/license_key = \"$WARP_LICENSE_KEY\"/" "$WGCF_TOML"
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

# best-effort down: чистит хвосты (интерфейс/маршруты) после нештатного рестарта
wg-quick down "$WGCF_CONF" 2>/dev/null || true
if warp_disabled; then
    echo "[warp] disabled via warpoff in pac.json — tunnel not started"
else
    echo "[warp] Starting WireGuard (WARP)..."
    wg-quick up "$WGCF_CONF"
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
# которого прокси и существует. Список переопределяется WARP_SOCKS_ALLOW
# (адреса через пробел) — на случай нестандартной адресации в override.
echo "[warp] Restricting SOCKS $SOCKS_PORT to: lo $SOCKS_ALLOW"
echo "[warp] (override with WARP_SOCKS_ALLOW=\"ip1 ip2\" if xray lives elsewhere)"
if iptables -N WARP_SOCKS 2>/dev/null; then :; else iptables -F WARP_SOCKS; fi
iptables -C INPUT -p tcp --dport "$SOCKS_PORT" -j WARP_SOCKS 2>/dev/null \
    || iptables -I INPUT -p tcp --dport "$SOCKS_PORT" -j WARP_SOCKS
iptables -A WARP_SOCKS -i lo -j ACCEPT
for ip in $SOCKS_ALLOW; do
    iptables -A WARP_SOCKS -s "$ip" -j ACCEPT
done
iptables -A WARP_SOCKS -j DROP

echo "[warp] Starting microsocks on port $SOCKS_PORT..."
microsocks -p "$SOCKS_PORT" &
MS_PID=$!

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
    if ! kill -0 "$MS_PID" 2>/dev/null; then
        echo "[warp] microsocks died — restarting..."
        microsocks -p "$SOCKS_PORT" &
        MS_PID=$!
    fi
    # Выключен намеренно — сторожу тут делать нечего.
    if warp_disabled; then
        FAILS=0
        BOUNCES=0
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
        wg-quick down "$WGCF_CONF" 2>/dev/null
        wg-quick up "$WGCF_CONF"
        FAILS=0
    fi
done
