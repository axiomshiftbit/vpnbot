ARG image=alpine:3.24
FROM $image

# Версия релиза ocserv (https://gitlab.com/openconnect/ocserv/-/releases).
# С 1.4.2 апстрим собирается только meson'ом (autotools удалены из дерева),
# поэтому сборка идёт из релизного тарболла, а не из git master.
# Задаётся в .env (OCSERV_VERSION=…) и пробрасывается через args в compose.
ARG OCSERV_VERSION=1.5.0

# Инвалидация кеша apk-слоя: передайте новое значение, чтобы пересборка
# реально сходила в edge за свежими gnutls/openssh без --no-cache.
#   docker compose build --build-arg APK_REFRESH=$(date +%F) oc
# Дефолт статичный — обычный build переиспользует кеш.
ARG APK_REFRESH=2026-07-04

RUN set -eux; \
    echo "apk refresh token: $APK_REFRESH"; \
    printf '%s\n' \
        'https://dl-cdn.alpinelinux.org/alpine/edge/main' \
        'https://dl-cdn.alpinelinux.org/alpine/edge/community' \
        > /etc/apk/repositories; \
    apk update; \
    apk upgrade --no-cache --available; \
    # постоянные пакеты: -dev тянут за собой runtime-библиотеки ocserv/occtl,
    # openssh/iptables нужны боту и start_oc.sh
    apk add --no-cache \
        openssh \
        iptables \
        gnutls-dev \
        libev-dev \
        linux-pam-dev \
        lz4-dev \
        libseccomp-dev \
        readline-dev \
        libnl3-dev \
        protobuf-c-dev \
        talloc-dev; \
    apk add --no-cache --virtual .build-deps \
        meson \
        samurai \
        gcc \
        musl-dev \
        pkgconf \
        linux-headers \
        curl \
        tar \
        protobuf-c-compiler \
        gperf; \
    curl -fsSL "https://gitlab.com/openconnect/ocserv/-/archive/${OCSERV_VERSION}/ocserv-${OCSERV_VERSION}.tar.gz" \
        | tar xz -C /tmp; \
    cd /tmp/ocserv-${OCSERV_VERSION}; \
    meson setup build -Dbuildtype=release -Dstrip=true -Dfirewall-script=iptables; \
    ninja -C build; \
    meson install -C build; \
    cd /; \
    rm -rf /tmp/ocserv-*; \
    apk del .build-deps; \
    mkdir -p /root/.ssh; \
    # sanity: все нужные боту бинарники на месте, и ocserv запускается
    # (без пайпа — код возврата не маскируется, set -e уронит сборку)
    command -v ocpasswd; \
    command -v occtl; \
    ocserv --version 2>&1
