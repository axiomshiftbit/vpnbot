#!/usr/bin/env bash

set -euo pipefail

REPO_URL="https://github.com/axiomshiftbit/vpnbot.git"
INSTALL_DIR="/opt/vpnbot"

KEY="${1:?usage: sudo bash init.sh <TG_BOT_KEY> [BRANCH]}"
BRANCH="${2:-Trojan-gRPC}"

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    make \
    git \
    iptables \
    iproute2 \
    xtables-addons-common \
    xtables-addons-dkms

if ! command -v docker >/dev/null 2>&1; then
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh
    rm -f /tmp/get-docker.sh
fi

if [ -d "$INSTALL_DIR/.git" ]; then
    echo "repo already exists at $INSTALL_DIR, pulling latest..."
    git -C "$INSTALL_DIR" pull
else
    git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

cat > ./app/config.php <<EOF
<?php

\$c = ['key' => '$KEY'];
EOF

make u
