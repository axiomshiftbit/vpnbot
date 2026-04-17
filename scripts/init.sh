#!/usr/bin/env bash

set -euo pipefail

REPO_URL="https://github.com/axiomshiftbit/vpnbot.git"
INSTALL_DIR="/root/vpnbot"
ARCHIVE_NAME="vpnbot.zip"

KEY="${1:?usage: sudo bash init.sh <TG_BOT_KEY> [BRANCH]}"
BRANCH="${2:-Trojan-gRPC}"

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root" >&2
    exit 1
fi

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
    git \
    unzip \
    rsync \
    iptables \
    iproute2 \
    xtables-addons-common \
    xtables-addons-dkms

if ! command -v docker >/dev/null 2>&1; then
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh
    rm -f /tmp/get-docker.sh
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
    if [ -d "$INSTALL_DIR/.git" ]; then
        echo "repo already exists at $INSTALL_DIR, pulling latest..."
        git -C "$INSTALL_DIR" fetch origin "$BRANCH"
        git -C "$INSTALL_DIR" checkout "$BRANCH"
        git -C "$INSTALL_DIR" pull --ff-only origin "$BRANCH"
    elif [ -d "$INSTALL_DIR" ] && [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]; then
        echo "$INSTALL_DIR exists without .git and no $ARCHIVE_NAME found" >&2
        echo "place $ARCHIVE_NAME next to this script for archive-mode update, or remove $INSTALL_DIR" >&2
        exit 1
    else
        git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
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
