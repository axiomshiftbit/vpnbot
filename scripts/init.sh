#!/usr/bin/env bash

set -euo pipefail

KEY="${1:?usage: init.sh <TG_BOT_KEY> [REPO_PATH]}"
REPO_PATH="${2:-$(pwd)}"

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root" >&2
    exit 1
fi

if [ ! -d "$REPO_PATH" ]; then
    echo "repo path not found: $REPO_PATH" >&2
    exit 1
fi
cd "$REPO_PATH"

if [ ! -f "./makefile" ] && [ ! -f "./Makefile" ]; then
    echo "not a vpnbot repo (no makefile in $REPO_PATH)" >&2
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

cat > ./app/config.php <<EOF
<?php

\$c = ['key' => '$KEY'];
EOF

make u
