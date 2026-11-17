ARG image=alpine:3.24
FROM $image

# Версия релиза ocserv (https://gitlab.com/openconnect/ocserv/-/releases).
# С 1.4.2 апстрим собирается только meson'ом (autotools удалены из дерева),
# поэтому сборка идёт из релизного тарболла, а не из git master.
# Задаётся в .env (OCSERV_VERSION=…) и пробрасывается через args в compose.
ARG OCSERV_VERSION=1.6.0

# Инвалидация кеша apk-слоя: передайте новое значение, чтобы пересборка
# обновила пакеты стабильной ветки: gnutls/openssh без --no-cache.
#   docker compose build --build-arg APK_REFRESH=$(date +%F) oc
# Дефолт статичный — обычный build переиспользует кеш.
ARG APK_REFRESH=2026-10-05

COPY dockerfile/sources.sha256 /sources.sha256
COPY dockerfile/download-file.sh /build-tools/download-file.sh
# Бэкпорт апстримного 996bc83e (ещё не в выпуске 1.6.0): стек сигналов не меньше
# 64 КиБ. С постоянным SIGSTKSZ musl ядро на CPU с большим кадром сигнала (AMX)
# отвечает ENOMEM, worker завершается, и клиент видит обрыв TLS. Убрать патч,
# когда исправление войдёт в выпуск; на другой версии он не применится — сборка
# остановится, а не соберёт ocserv без исправления.
COPY dockerfile/ocserv-sigaltstack.patch /build-tools/ocserv-sigaltstack.patch

RUN set -eux; \
    echo "apk refresh token: $APK_REFRESH"; \
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
        gperf \
        patch; \
    sh /build-tools/download-file.sh "https://gitlab.com/openconnect/ocserv/-/archive/${OCSERV_VERSION}/ocserv-${OCSERV_VERSION}.tar.gz" /tmp/ocserv.tar.gz; \
    awk -v key="ocserv/${OCSERV_VERSION}" '$2 == key {print $1 "  /tmp/ocserv.tar.gz"}' /sources.sha256 | sha256sum -c -; \
    tar xzf /tmp/ocserv.tar.gz -C /tmp; \
    rm /tmp/ocserv.tar.gz; \
    cd /tmp/ocserv-${OCSERV_VERSION}; \
    patch -p1 < /build-tools/ocserv-sigaltstack.patch; \
    meson setup build -Dbuildtype=release -Dstrip=true -Dfirewall-script=iptables; \
    ninja -C build; \
    meson install -C build; \
    cd /; \
    rm -rf /tmp/ocserv-* /sources.sha256 /build-tools/download-file.sh /build-tools/ocserv-sigaltstack.patch; \
    apk del .build-deps; \
    mkdir -p /root/.ssh; \
    # sanity: все нужные боту бинарники на месте, и ocserv запускается
    # (без пайпа — код возврата не маскируется, set -e уронит сборку)
    command -v ocpasswd; \
    command -v occtl; \
    ocserv --version 2>&1
