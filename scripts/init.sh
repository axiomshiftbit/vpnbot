#!/usr/bin/env bash

set -euo pipefail

REPO_URL="https://github.com/axiomshiftbit/vpnbot.git"
INSTALL_DIR="/root/vpnbot"
ARCHIVE_NAME="vpnbot.zip"

# Ключ бота предпочтительно передавать окружением: позиционный аргумент виден
# в `ps` ВСЕМ процессам хоста на всё время работы скрипта и остаётся в
# ~/.bash_history root'а. Форма с аргументом сохранена для совместимости с уже
# опубликованными командами установки, но предупреждает.
# Стабильный релиз живёт в master, разработка — в dev. Поддерживаются только
# эти две ветки — и для установки из git, и для установки из архива.
KEY="${VPNBOT_KEY:-}"
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
# делает git fetch/pull) требуют GitHub-токена с read-доступом к axiomshiftbit/vpnbot.
# Токен передаётся через переменную окружения GH_TOKEN (или VPNBOT_TOKEN).
# При установке из архива токен не нужен.
TOKEN="${GH_TOKEN:-${VPNBOT_TOKEN:-}}"

# Токен НЕ вшивается в URL origin. Раньше origin выглядел как
# https://x-access-token:<pat>@github.com/... — и это значило: PAT в открытом
# виде навсегда в /root/vpnbot/.git/config (его показывает любой `git remote -v`
# и любой бэкап каталога), PAT в argv на время clone/fetch/pull (виден в `ps`
# всем процессам хоста), PAT в сообщениях об ошибках git.
# Вместо этого — стандартный credential.helper store с файлом 0600 вне репозитория:
# origin остаётся чистым, а update.sh продолжает тянуть обновления без ввода.
CRED_FILE="/root/.vpnbot-git-credentials"

setup_git_credentials() {
    [ -n "$TOKEN" ] || return 0
    ( umask 077; printf 'https://x-access-token:%s@github.com\n' "$TOKEN" > "$CRED_FILE" )
    chmod 600 "$CRED_FILE"
}

git_cred_opt() {
    if [ -n "$TOKEN" ]; then
        printf 'credential.helper=store --file=%s' "$CRED_FILE"
    else
        printf 'credential.helper='
    fi
}

repo_clone_url() {
    printf '%s' "$REPO_URL"
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
    unzip \
    rsync \
    iptables \
    iproute2 \
    xtables-addons-common \
    xtables-addons-dkms

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
    if [ -z "$TOKEN" ]; then
        echo "private repo: set GH_TOKEN (read access to axiomshiftbit/vpnbot) for git install" >&2
        echo "or place $ARCHIVE_NAME next to this script for offline archive install" >&2
        exit 1
    fi
    setup_git_credentials
    if [ -d "$INSTALL_DIR/.git" ]; then
        echo "repo already exists at $INSTALL_DIR, pulling latest..."
        # Чистый origin + credential.helper в конфиге репозитория. set-url здесь
        # ещё и ЛЕЧИТ установки, где в origin остался вшитый PAT.
        git -C "$INSTALL_DIR" remote set-url origin "$(repo_clone_url)"
        if [ -n "$TOKEN" ]; then
            git -C "$INSTALL_DIR" config credential.helper "store --file=$CRED_FILE"
        fi
        git -C "$INSTALL_DIR" fetch origin "$BRANCH"
        git -C "$INSTALL_DIR" checkout "$BRANCH"
        git -C "$INSTALL_DIR" pull --ff-only origin "$BRANCH"
    elif [ -d "$INSTALL_DIR" ] && [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]; then
        echo "$INSTALL_DIR exists without .git and no $ARCHIVE_NAME found" >&2
        echo "place $ARCHIVE_NAME next to this script for archive-mode update, or remove $INSTALL_DIR" >&2
        exit 1
    else
        # -c ...=store --file=… в argv — это путь, а не секрет; сам токен лежит
        # в файле 0600. После клона тот же helper прописывается в конфиг репо,
        # чтобы update.sh тянул обновления приватного репозитория без ввода.
        git -c "$(git_cred_opt)" clone --branch "$BRANCH" "$(repo_clone_url)" "$INSTALL_DIR"
        if [ -n "$TOKEN" ]; then
            git -C "$INSTALL_DIR" config credential.helper "store --file=$CRED_FILE"
        fi
    fi
}

if [ -n "$ARCHIVE" ]; then
    install_from_archive
else
    install_from_git
fi

cd "$INSTALL_DIR"

mkdir -p ./app
cat > ./app/config.php <<EOF
<?php

\$c = ['key' => '$KEY'];
EOF

make u
