#!/usr/bin/env bash

set -euo pipefail

REPO_URL="https://github.com/axiomshiftbit/vpnbot.git"
INSTALL_DIR="/root/vpnbot"
ARCHIVE_NAME="vpnbot.zip"

MODE="${VPNBOT_MODE:-full}"
if [ "${1:-}" = --mode ]; then
    MODE="${2:-}"
    shift 2
fi
case "$MODE" in full|node) ;; *) echo 'Режим установки: --mode full или --mode node' >&2; exit 1;; esac

if [ "$MODE" = node ]; then
    BRANCH="${1:-master}"
else

# Ключ бота предпочтительно передавать окружением: позиционный аргумент виден
# в `ps` ВСЕМ процессам хоста на всё время работы скрипта и остаётся в
# ~/.bash_history root'а. Форма с аргументом сохранена для совместимости с уже
# опубликованными командами установки, но предупреждает.
# Стабильный релиз живёт в master, разработка — в dev. Поддерживаются только
# эти две ветки — и для установки из git, и для установки из архива.
KEY="${VPNBOT_KEY:-}"
# Заданная, но пустая переменная — пустой файл ключа
# (VPNBOT_KEY="$(cat /root/.vpnbot-key)"): иначе имя ветки ушло бы в ключ.
if [ "${VPNBOT_KEY+set}" = set ] && [ -z "$KEY" ]; then
    echo "VPNBOT_KEY пуст: положите токен бота в /root/.vpnbot-key (права 600) и запустите установку снова" >&2
    exit 1
fi
if [ -n "$KEY" ]; then
    BRANCH="${1:-master}"
else
    KEY="${1:-}"
    BRANCH="${2:-master}"
    if [ -n "$KEY" ]; then
        echo "WARN: ключ бота передан аргументом — он виден в ps и остаётся в history." >&2
        echo "      Предпочтительно:  VPNBOT_KEY=<key> bash init.sh [BRANCH]" >&2
    fi
fi
if [ -z "$KEY" ]; then
    echo "usage: sudo VPNBOT_KEY=<TG_BOT_KEY> bash init.sh [BRANCH]" >&2
    exit 1
fi
fi

# Ключ бота уходит в app/config.php внутри PHP-строки в одинарных кавычках и в
# каждый запрос к Telegram. Пробелы и \r — частый след копирования из Windows и
# мессенджеров: Telegram отвечает на такой ключ 401, php остаётся unhealthy, и
# установка падала с невнятным «dependency php failed to start». Значение
# ключа в сообщениях не печатается.
normalize_bot_key() {
    KEY="$(printf '%s' "$KEY" | tr -d ' \t\r\n')"
    if ! [[ "$KEY" =~ ^[0-9]{5,15}:[A-Za-z0-9_-]{30,64}$ ]]; then
        echo "ключ бота не похож на токен Telegram (ожидается вид 123456789:AA…): скопируйте его у @BotFather заново" >&2
        exit 1
    fi
}

# getMe до записи config.php: явный отказ Telegram (401) останавливает
# установку понятным сообщением. Недоступный Telegram — не повод отказывать:
# бот работает и без него (веб-панель), поэтому только предупреждение.
# URL с ключом передаётся curl через stdin (-K -), а не аргументом: аргументы
# видны в ps всем процессам хоста.
check_bot_key() {
    local reply api
    local api_re='^https://([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*|\[[0-9A-Fa-f:.]{2,45}\])(:[1-9][0-9]{0,4})?(/[A-Za-z0-9._~-]{1,64}){0,8}$'
    # TELEGRAM_API — имя хоста Bot API (api.telegram.org или своё зеркало),
    # можно с портом и путём ретранслятора: host[:port][/путь]. Схема всегда
    # https: без неё curl ушёл бы по http и передал ключ бота открытым текстом;
    # явный http:// не принимается. Формат — как у TelegramApi::normalize().
    api="${TELEGRAM_API:-api.telegram.org}"
    [[ "$api" == *://* ]] || api="https://$api"
    while [[ "$api" == */ ]]; do api="${api%/}"; done
    if [[ ${#api} -gt 255 || ! "$api" =~ $api_re || "$api/" == *"/./"* || "$api/" == *"/../"* ]] \
        || { [[ "$api" =~ ^https://[^/]*:([0-9]+)(/|$) ]] && (( 10#${BASH_REMATCH[1]} > 65535 )); }; then
        echo "TELEGRAM_API должен быть адресом Bot API вида api.telegram.org или домен[:порт][/путь], запрос идёт только по https" >&2
        exit 1
    fi
    if ! reply="$(printf 'url = "%s/bot%s/getMe"\n' "$api" "$KEY" \
            | curl -sS --max-time 15 -K - 2>/dev/null)"; then
        echo "WARN: Telegram недоступен — ключ бота не проверен; бот запустится и будет ждать Telegram" >&2
        return 0
    fi
    case "$reply" in
        *'"ok":true'*) echo "ключ бота принят Telegram" ;;
        *'"error_code":401'*)
            echo "Telegram отверг ключ бота (401 Unauthorized): проверьте токен у @BotFather (/token) и запустите установку снова" >&2
            exit 1
            ;;
        *) echo "WARN: неожиданный ответ Telegram на getMe — ключ бота не проверен" >&2 ;;
    esac
}

# Автозапуск после перезагрузки. У большинства контейнеров restart: "no", их
# поднимает только make: без этого шага после ребута чистого сервера работали
# одни php/nginx/upstream/service/warp, а Xray, WireGuard и остальное — нет.
# Служба vpnbot.service (scripts/install_as_service.sh), если включена, уже
# делает это сама — тогда cron не добавляется, иначе старт был бы двойным.
install_autostart() {
    if systemctl is-enabled --quiet vpnbot.service 2>/dev/null; then
        echo "autostart: vpnbot.service"
    elif make cron; then
        echo "autostart: cron @reboot make r"
    else
        echo "WARN: автозапуск не установлен — выполните make cron вручную" >&2
    fi
}

if [ "$MODE" = full ]; then normalize_bot_key; fi

case "$BRANCH" in
    master|dev) ;;
    *)
        echo "unsupported branch: '$BRANCH' (allowed: master, dev)" >&2
        exit 1
        ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root" >&2
    exit 1
fi

# Репозиторий приватный: установка из git и последующие обновления (update.sh
# и бот делают git fetch) ходят в axiomshiftbit/vpnbot по deploy-ключу ТОЛЬКО ДЛЯ
# ЧТЕНИЯ. Ключ создаётся на сервере и не покидает его; в GitHub добавляется
# лишь публичная половина (Settings → Deploy keys, без права записи).
# При установке из архива ключ не нужен.
#
# Ключ и настройки ssh лежат внутри .git, пути в них относительные: каталог
# .git смонтирован в контейнеры php и service как /.git, и `git -C / fetch`
# оттуда находит те же файлы. Порт 443 узла ssh.github.com — на случай
# закрытого наружу порта 22.
DEPLOY_DIR=".git/vpnbot-readonly-ssh"
# Файл токена прежней схемы (credential.helper store) — удаляется при переходе.
CRED_FILE="/root/.vpnbot-git-credentials"

setup_deploy_key() {
    local dir="$INSTALL_DIR/$DEPLOY_DIR"
    ( umask 077; mkdir -p "$dir" )
    chmod 700 "$dir"
    if [ ! -f "$dir/id_ed25519" ]; then
        ( umask 077; ssh-keygen -q -t ed25519 -N '' -C "vpnbot-$(hostname)-readonly" -f "$dir/id_ed25519" )
    elif [ ! -f "$dir/id_ed25519.pub" ]; then
        ssh-keygen -y -f "$dir/id_ed25519" > "$dir/id_ed25519.pub"
    fi
    ( umask 077
      cat > "$dir/config" <<EOF
Host axiomshiftbit
    HostName ssh.github.com
    User git
    Port 443
    IdentityFile $DEPLOY_DIR/id_ed25519
    IdentitiesOnly yes
    BatchMode yes
    ConnectTimeout 10
    ServerAliveInterval 15
    ServerAliveCountMax 2
    StrictHostKeyChecking yes
    UserKnownHostsFile $DEPLOY_DIR/known_hosts
EOF
      # Публичные ключи узла GitHub (https://api.github.com/meta, ssh_keys).
      cat > "$dir/known_hosts" <<'EOF'
github.com,[ssh.github.com]:443 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
github.com,[ssh.github.com]:443 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=
github.com,[ssh.github.com]:443 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=
EOF
    )
}

# Переключение origin на ключ — только после проверки доступа: до этого
# установка, работающая по токену, продолжает получать обновления.
use_deploy_key() {
    git -C "$INSTALL_DIR" config core.sshCommand "ssh -F $DEPLOY_DIR/config"
    # set-url заодно лечит установки, где в origin остался вшитый PAT.
    if git -C "$INSTALL_DIR" remote get-url origin >/dev/null 2>&1; then
        git -C "$INSTALL_DIR" remote set-url origin "$REPO_URL"
    else
        git -C "$INSTALL_DIR" remote add origin "$REPO_URL"
    fi
    git -C "$INSTALL_DIR" config --unset-all credential.helper || true
    rm -f "$CRED_FILE"
}

# Публичный репозиторий (REPO_URL вида https://…) читается без ключа:
# клон, обновления из бота и ноды идут по HTTPS, deploy-ключ не создаётся.
repo_is_public() {
    case "$REPO_URL" in https://*) return 0 ;; *) return 1 ;; esac
}

use_public_origin() {
    git -C "$INSTALL_DIR" config --unset-all core.sshCommand || true
    if git -C "$INSTALL_DIR" remote get-url origin >/dev/null 2>&1; then
        git -C "$INSTALL_DIR" remote set-url origin "$REPO_URL"
    else
        git -C "$INSTALL_DIR" remote add origin "$REPO_URL"
    fi
    git -C "$INSTALL_DIR" config --unset-all credential.helper || true
    rm -f "$CRED_FILE"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ARCHIVE=""
for candidate in \
    "${VPNBOT_ARCHIVE:-}" \
    "$PWD/$ARCHIVE_NAME" \
    "$SCRIPT_DIR/$ARCHIVE_NAME" \
    "$SCRIPT_DIR/../$ARCHIVE_NAME" \
    "/root/$ARCHIVE_NAME" \
    "/tmp/$ARCHIVE_NAME"; do
    if [ -n "$candidate" ] && [ -f "$candidate" ]; then
        ARCHIVE="$(readlink -f "$candidate")"
        break
    fi
done

export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    make \
    python3 \
    git \
    openssh-client \
    unzip \
    rsync \
    iptables \
    nftables \
    rsyslog \
    logrotate \
    cron \
    util-linux \
    iproute2

# xt_ipp2p — модуль ЯДРА ХОСТА, а не контейнера. Один xtables-addons-dkms
# без заголовков работающего ядра может оставить только сборку для старого.
install_ipp2p() {
    local kernel image header status
    kernel="$(uname -r)"
    local -a headers=("linux-headers-$kernel")
    # Следуем уже выбранной ветке ядра: Debian cloud/обычная, Ubuntu HWE,
    # generic и т. п. Не устанавливаем другое ядро ради его заголовков.
    while read -r image status; do
        [ "$status" = installed ] || continue
        image="${image%:*}"
        case "$image" in linux-image-[0-9]*|linux-image-unsigned-*) continue;; esac
        header="${image/linux-image-/linux-headers-}"
        # Обновление уже установленного headers-meta на Ubuntu через
        # linux-generic может заодно обновить image-meta и установить ядро.
        [ "$(dpkg-query -W -f='${db:Status-Status}' "$header" 2>/dev/null)" = installed ] && continue
        if apt-cache show "$header" >/dev/null 2>&1; then headers+=("$header"); fi
    done < <(dpkg-query -W -f='${binary:Package} ${db:Status-Status}\n' 'linux-image-*' 2>/dev/null || true)
    if ! apt install -y --no-install-recommends xtables-addons-common xtables-addons-dkms "${headers[@]}"; then
        echo "ERROR: нет заголовков для работающего ядра $kernel; xt_ipp2p не готов." >&2
        echo "Установите соответствующие linux-headers из репозитория вашего ядра и повторите установку." >&2
        return 1
    fi
    if ! dkms autoinstall -k "$kernel" || ! modprobe xt_ipp2p; then
        echo "ERROR: xt_ipp2p не собран или не загружается для $kernel. Проверьте журнал DKMS и политику подписи модулей." >&2
        return 1
    fi
    printf 'xt_ipp2p\n' > /etc/modules-load.d/vpnbot-ipp2p.conf
    echo "kernel module xt_ipp2p loaded (torrent signatures ready)"
}
if [ "$MODE" = full ]; then
install_ipp2p

# L2TP/IPsec (сервис ipsec) требует на ХОСТЕ модуль l2tp_ppp — контейнер его
# загрузить не может (только NET_ADMIN, без /lib/modules). Тянет за собой
# l2tp_core, l2tp_netlink, pppox, ppp_generic. Не критично для остальных
# протоколов, поэтому НЕ роняем установку (set -e активен) — только
# предупреждаем. IKEv2 работает и без модуля, он нужен исключительно для L2TP.
if modprobe l2tp_ppp 2>/dev/null; then
    # автозагрузка после перезагрузки хоста
    echo 'l2tp_ppp' > /etc/modules-load.d/vpnbot-l2tp.conf
    echo "kernel module l2tp_ppp loaded (L2TP/IPsec ready)"
else
    echo "WARN: kernel module l2tp_ppp unavailable — L2TP won't work; IKEv2 still fine" >&2
fi

# wg-quick в WARP использует comment, mark и CONNMARK в правилах netfilter.
# Контейнер не может загрузить модули: без них iptables-restore обрывает up.
if modprobe -a xt_comment xt_mark xt_connmark 2>/dev/null; then
    printf 'xt_comment\nxt_mark\nxt_connmark\n' > /etc/modules-load.d/vpnbot-warp.conf
else
    echo "WARN: netfilter modules unavailable — WARP wg-quick may fail" >&2
fi

# strongSwan при запуске проверяет, умеет ли ядро интерфейсы XFRM, и без
# модуля пишет в журнал ipsec «failed to create XFRM interface». Самому боту
# эти интерфейсы не нужны, модуль загружается ради чистого журнала. Он
# зависит от IPv6: на ядре с ipv6.disable=1 не загружается вовсе — это не
# ошибка, IKEv2 и L2TP работают и без него.
if modprobe xfrm_interface 2>/dev/null; then
    echo 'xfrm_interface' > /etc/modules-load.d/vpnbot-xfrm.conf
else
    echo "NOTE: kernel module xfrm_interface unavailable (IPv6 disabled in the kernel?) — IPsec works without it"
fi
fi

if [ "$MODE" = node ]; then
    apt install -y --no-install-recommends openssh-server sudo openssl certbot
fi

# Docker ставим из официального apt-репозитория с проверкой ключа, а не
# `curl https://get.docker.com | sh`. Тот скрипт исполнялся root'ом без сверки
# подписи или контрольной суммы (-f защищает только от HTTP-ошибок), то есть
# компрометация домена, MITM с доверенным CA или подмена DNS давали мгновенный
# root-RCE на каждой новой инсталляции. Установка и так рассчитана на
# Debian/Ubuntu — выше безусловный apt.
if ! command -v docker >/dev/null 2>&1; then
    # Отпечаток официального ключа Docker. Сверяем ЯВНО: без этого «ключ из
    # интернета» проверяет сам себя и смысла в подписи нет.
    DOCKER_GPG_FPR='9DC858229FC7DD38854AE2D88D81803C0EBFCD88'
    install -m 0755 -d /etc/apt/keyrings
    distro_id="$(. /etc/os-release && echo "$ID")"
    distro_codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}")"
    case "$distro_id" in
        ubuntu|debian) ;;
        *)
            echo "WARN: неизвестный дистрибутив '$distro_id' — ставим docker из репозитория debian" >&2
            distro_id=debian
            ;;
    esac
    curl -fsSL "https://download.docker.com/linux/$distro_id/gpg" -o /tmp/docker.asc
    gpg --dearmor < /tmp/docker.asc > /etc/apt/keyrings/docker.gpg
    got_fpr="$(gpg --show-keys --with-colons --fingerprint /tmp/docker.asc \
        | awk -F: '/^fpr:/ {print $10; exit}')"
    rm -f /tmp/docker.asc
    if [ "$got_fpr" != "$DOCKER_GPG_FPR" ]; then
        echo "FATAL: отпечаток ключа docker не совпал: $got_fpr" >&2
        rm -f /etc/apt/keyrings/docker.gpg
        exit 1
    fi
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$distro_id $distro_codename stable" \
        > /etc/apt/sources.list.d/docker.list
    apt update
    apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

install_from_archive() {
    echo "installing from archive: $ARCHIVE"
    local tmp src nested
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN

    unzip -q -o "$ARCHIVE" -d "$tmp"

    src="$tmp"
    if [ ! -f "$src/makefile" ] && [ ! -f "$src/Makefile" ] && [ ! -d "$src/app" ]; then
        nested="$(find "$tmp" -mindepth 1 -maxdepth 1 -type d | head -n1 || true)"
        if [ -n "$nested" ] && { [ -f "$nested/makefile" ] || [ -f "$nested/Makefile" ] || [ -d "$nested/app" ]; }; then
            src="$nested"
        fi
    fi

    if [ ! -d "$src/app" ] && [ ! -f "$src/makefile" ] && [ ! -f "$src/Makefile" ]; then
        echo "archive $ARCHIVE does not look like a vpnbot project (missing app/ or makefile)" >&2
        exit 1
    fi

    if [ -d "$INSTALL_DIR/.git" ]; then
        echo "removing old .git from $INSTALL_DIR"
        rm -rf "$INSTALL_DIR/.git"
    fi

    mkdir -p "$INSTALL_DIR"
    rsync -a --exclude='app/config.php' "$src"/ "$INSTALL_DIR"/

    if [ -d "$INSTALL_DIR/.git" ]; then
        local cur
        cur="$(git -C "$INSTALL_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")"
        if [ "$cur" != "$BRANCH" ]; then
            echo "switching archive checkout to branch: $BRANCH"
            git -C "$INSTALL_DIR" checkout "$BRANCH"
        else
            echo "archive already on branch: $BRANCH"
        fi
    else
        echo "archive does not contain .git; skipping branch switch"
    fi
}

install_from_git() {
    echo "installing from git: $REPO_URL ($BRANCH)"
    if [ ! -d "$INSTALL_DIR/.git" ]; then
        if [ -d "$INSTALL_DIR" ] && [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]; then
            echo "$INSTALL_DIR exists without .git and no $ARCHIVE_NAME found" >&2
            echo "place $ARCHIVE_NAME next to this script for archive-mode update, or remove $INSTALL_DIR" >&2
            exit 1
        fi
        # Пустой репозиторий вместо clone: ключу нужно место ещё до первой
        # загрузки, а повторный запуск продолжает с того же места.
        git init -q "$INSTALL_DIR"
    fi
    if repo_is_public; then
        if ! git -C "$INSTALL_DIR" ls-remote --exit-code "$REPO_URL" "refs/heads/$BRANCH" >/dev/null 2>&1; then
            echo "Не удалось прочитать $REPO_URL (ветка $BRANCH): проверьте доступ к github.com и запустите установку ещё раз." >&2
            exit 1
        fi
        use_public_origin
    else
        setup_deploy_key
        if ! GIT_SSH_COMMAND="ssh -F $DEPLOY_DIR/config" git -C "$INSTALL_DIR" \
                ls-remote --exit-code "$REPO_URL" "refs/heads/$BRANCH" >/dev/null 2>&1; then
            echo "GitHub не принял deploy-ключ этого сервера (или недоступен ssh.github.com:443)." >&2
            echo "Добавьте публичный ключ в axiomshiftbit/vpnbot: Settings → Deploy keys → Add deploy key," >&2
            echo "БЕЗ галочки «Allow write access», затем запустите установку ещё раз:" >&2
            echo >&2
            cat "$INSTALL_DIR/$DEPLOY_DIR/id_ed25519.pub" >&2
            exit 1
        fi
        use_deploy_key
    fi
    git -C "$INSTALL_DIR" fetch origin "$BRANCH"
    if [ -f "$INSTALL_DIR/update/image-bundle.json" ]; then
        # Рабочая установка: код и образы переключает вместе только обновление
        # из бота. Сдвиг кода здесь разошёлся бы с активным комплектом образов.
        echo "installation is active: code stays as is, update it from the bot"
        return 0
    fi
    # Код берём из коммита ОПУБЛИКОВАННОГО комплекта образов, а не с вершины
    # ветки: пока вершина не прошла сборку и стенд, make u отказал бы
    # («code does not match the tested image set»).
    local channel=dev released
    [ "$BRANCH" != master ] || channel=latest
    git -C "$INSTALL_DIR" checkout -q --detach "origin/$BRANCH"
    ( cd "$INSTALL_DIR" && python3 scripts/image_bundle.py fetch "$channel" update/image-bundle.pending.json )
    released="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["source"])' \
        "$INSTALL_DIR/update/image-bundle.pending.json")"
    git -C "$INSTALL_DIR" merge-base --is-ancestor "$released" "origin/$BRANCH"
    if git -C "$INSTALL_DIR" show-ref --verify --quiet "refs/heads/$BRANCH"; then
        git -C "$INSTALL_DIR" checkout -q "$BRANCH"
        git -C "$INSTALL_DIR" merge -q --ff-only "$released"
    else
        git -C "$INSTALL_DIR" checkout -q -b "$BRANCH" "$released"
    fi
    git -C "$INSTALL_DIR" branch -q --set-upstream-to="origin/$BRANCH" "$BRANCH"
}

if [ -n "$ARCHIVE" ]; then
    install_from_archive
else
    install_from_git
fi

cd "$INSTALL_DIR"

# Защита хоста для обоих режимов; сбой не прерывает установку.
bash scripts/host_hardening.sh || echo 'WARN: host hardening was not fully applied' >&2
# Сетевые параметры ядра (BBR, буферы, TCP, conntrack; полный бот — ip_forward=1).
bash scripts/host_sysctl.sh "$MODE" || echo 'WARN: host sysctl was not fully applied' >&2

# Журналы nftables в /var/log/nftables (rsyslog + logrotate) — только при
# профиле VPNBot и при первой установке; сбой не прерывает установку.
install_nft_logging() {
    [ ! -s /etc/rsyslog.d/10-nftables.conf ] || return 0
    head -5 /etc/nftables.conf 2>/dev/null | grep -q '^# VPNBot:' || return 0
    systemctl enable --now rsyslog.service cron.service >/dev/null 2>&1 || true
    bash "nftables/logging/$1" || echo 'WARN: журналирование nftables не настроено (см. nftables/logging/)' >&2
}

# Профиль nftables из каталога nftables/: вопросы об адресах, WAN и SSH,
# применение с подтверждением нового SSH-входа и автоматическим откатом.
# Ноде профиль обязателен; полный бот без него работает, но без защиты хоста.
if ! python3 -I scripts/nft_profile_install.py --mode "$MODE"; then
    if [ "$MODE" = node ]; then
        echo 'Профиль nftables ноды не установлен; установка остановлена (см. readme, раздел о ноде).' >&2
        exit 1
    fi
    echo 'WARN: профиль nftables не установлен; бот будет работать без защиты хоста (см. readme).' >&2
fi

if [ "$MODE" = node ]; then
    channel=dev
    [ "$BRANCH" != master ] || channel=latest
    node_args=(--channel "$channel")
    if [ -n "${VPNBOT_NODE_CONFIG:-}" ]; then node_args+=(--config "$VPNBOT_NODE_CONFIG"); fi
    if [ -s update/image-bundle.pending.json ]; then
        node_args+=(--bundle update/image-bundle.pending.json)
    elif [ -s update/image-bundle.json ]; then
        node_args+=(--bundle update/image-bundle.json)
    fi
    # Журналы — после установщика ноды: ACTION берётся из уже загруженных правил.
    if python3 -I scripts/node_setup.py "${node_args[@]}"; then
        install_nft_logging noda.sh
        exit 0
    else
        exit $?
    fi
fi
install_nft_logging nftables.sh

mkdir -p ./app
if [ -s ./app/config.php ]; then
    # Здесь же бот хранит администратора: перезапись сбросила бы привязку.
    echo "app/config.php already exists — kept as is (edit it to change the bot key)"
else
    check_bot_key
    cat > ./app/config.php <<EOF
<?php

\$c = ['key' => '$KEY'];
EOF
fi

make u
install_autostart
