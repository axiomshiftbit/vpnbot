ARG image=alpine:3.24
FROM $image

# Инвалидация кеша apk-слоя: передайте новое значение, чтобы пересборка
# обновила пакеты стабильной ветки: xl2tpd/openssl без --no-cache.
#   docker compose build --build-arg APK_REFRESH=$(date +%F) ipsec
# Дефолт статичный — обычный build переиспользует кеш.
ARG APK_REFRESH=2026-10-05
ARG STRONGSWAN_VERSION=6.1.0
# Архив проверен по PGP-подписи upstream (DF42C170B34DBA77).
ARG STRONGSWAN_SHA256=fe6c97481298767213cfc2e9a1da29fdd8018d481ff4cb9cf0283099654f20d4
COPY dockerfile/download-file.sh /build-tools/download-file.sh

# В Alpine пока strongSwan 6.0.7 без исправлений безопасности 6.1.0.
# Собираем проверенный upstream; IKEv1 с 6.1 нужно включать явно для L2TP.
# procps-ng сохраняет pgrep -x по имени charon при запуске по полному пути:
# BusyBox стабильной Alpine иначе даёт ложный отказ проверки backup/restore.
RUN set -eux; \
    echo "apk refresh token: $APK_REFRESH"; \
    apk update; \
    apk upgrade --no-cache --available; \
    apk add --no-cache \
        openssh \
        bash \
        python3 \
        procps-ng \
        xl2tpd \
        ppp \
        iptables \
        iproute2 \
        openssl \
        netcat-openbsd \
        libcurl; \
    apk add --no-cache --virtual .build-deps \
        build-base linux-headers openssl-dev curl-dev curl bzip2; \
    sh /build-tools/download-file.sh "https://download.strongswan.org/strongswan-${STRONGSWAN_VERSION}.tar.bz2" /tmp/strongswan.tar.bz2; \
    echo "${STRONGSWAN_SHA256}  /tmp/strongswan.tar.bz2" | sha256sum -c -; \
    mkdir /tmp/strongswan; \
    tar -xjf /tmp/strongswan.tar.bz2 -C /tmp/strongswan --strip-components=1; \
    cd /tmp/strongswan; \
    ./configure --prefix=/usr --sysconfdir=/etc --libexecdir=/usr/lib \
        --with-ipsecdir=/usr/lib/strongswan \
        --enable-ikev1 --enable-eap-identity --enable-eap-mschapv2 \
        --enable-curl --enable-counters; \
    make -j2; \
    make install; \
    cd /; \
    rm -rf /tmp/strongswan /tmp/strongswan.tar.bz2; \
    apk del .build-deps; \
    mkdir -p /root/.ssh /etc/swanctl /config/ipsec; \
    # Санити-гейт: без vici-демона `swanctl --version` падает (exit 2), поэтому
    # проверяем НАЛИЧИЕ критичных бинарей — сборка честно валится, если alpine
    # перестанет класть charon/pki/swanctl/xl2tpd по ожидаемым путям.
    command -v swanctl; \
    command -v xl2tpd; \
    command -v pki; \
    { ls /usr/lib/ipsec/charon || ls /usr/lib/strongswan/charon || ls /usr/libexec/ipsec/charon; }; \
    openssl version

# pppd 2.5.5 исправляет MPPE, проверку кадров RADIUS и запуск ip-up/ip-down.
# У выпуска пока нет готового tarball с configure: закрепляем архив тега
# и генерируем configure из проверенных исходников штатным autoreconf.
ARG PPP_VERSION=2.5.5
ARG PPP_SHA256=c75b2ee2cbc6f16407e2a908f5ae5802a2f8717d19a8faf0262d1bfa3cc4ba27
RUN set -eux; \
    apk del ppp; \
    apk add --no-cache --virtual .ppp-build-deps \
        build-base linux-headers openssl-dev libpcap-dev curl autoconf automake libtool pkgconf; \
    sh /build-tools/download-file.sh "https://codeload.github.com/ppp-project/ppp/tar.gz/refs/tags/v${PPP_VERSION}" /tmp/ppp.tar.gz; \
    echo "${PPP_SHA256}  /tmp/ppp.tar.gz" | sha256sum -c -; \
    mkdir /tmp/ppp; \
    tar -xzf /tmp/ppp.tar.gz -C /tmp/ppp --strip-components=1; \
    cd /tmp/ppp; \
    autoreconf -fi; \
    ./configure --prefix=/usr --sysconfdir=/etc --disable-eaptls --disable-peap; \
    make -j2; \
    make install-strip; \
    cd /; \
    rm -rf /tmp/ppp /tmp/ppp.tar.gz /build-tools/download-file.sh; \
    apk del .ppp-build-deps; \
    pppd --version; \
    test -f /usr/lib/pppd/${PPP_VERSION}/pppol2tp.so
