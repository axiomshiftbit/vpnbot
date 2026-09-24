ARG image=alpine:3.23
FROM $image

# Инвалидация кеша apk-слоя: передайте новое значение, чтобы пересборка
# реально сходила в edge за свежими xl2tpd/openssl без --no-cache.
#   docker compose build --build-arg APK_REFRESH=$(date +%F) ipsec
# Дефолт статичный — обычный build переиспользует кеш.
ARG APK_REFRESH=2026-09-16
ARG STRONGSWAN_VERSION=6.1.0
# Архив проверен по PGP-подписи upstream (DF42C170B34DBA77).
ARG STRONGSWAN_SHA256=fe6c97481298767213cfc2e9a1da29fdd8018d481ff4cb9cf0283099654f20d4

# В Alpine пока strongSwan 6.0.7 без исправлений безопасности 6.1.0.
# Собираем проверенный upstream; IKEv1 с 6.1 нужно включать явно для L2TP.
RUN set -eux; \
    echo "apk refresh token: $APK_REFRESH"; \
    printf '%s\n' \
        'https://dl-cdn.alpinelinux.org/alpine/edge/main' \
        'https://dl-cdn.alpinelinux.org/alpine/edge/community' \
        > /etc/apk/repositories; \
    apk update; \
    apk upgrade --no-cache --available; \
    apk add --no-cache \
        openssh \
        bash \
        python3 \
        xl2tpd \
        ppp \
        iptables \
        iproute2 \
        openssl \
        netcat-openbsd \
        libcurl; \
    apk add --no-cache --virtual .build-deps \
        build-base linux-headers openssl-dev curl-dev curl bzip2; \
    curl -fsSL "https://download.strongswan.org/strongswan-${STRONGSWAN_VERSION}.tar.bz2" -o /tmp/strongswan.tar.bz2; \
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

# pppd 2.5.4 исправляет в том числе переполнение LCP до CHAP-аутентификации
# (CVE-2026-85495). Alpine пока поставляет 2.5.3; digest взят из Releases.
ARG PPP_VERSION=2.5.4
ARG PPP_SHA256=379a630a40d858a1347f6592d671791dde12101697a743ef9900012f3765be31
RUN set -eux; \
    apk del ppp; \
    apk add --no-cache --virtual .ppp-build-deps \
        build-base linux-headers openssl-dev libpcap-dev curl; \
    curl -fsSL "https://github.com/ppp-project/ppp/releases/download/v${PPP_VERSION}/ppp-${PPP_VERSION}.tar.gz" -o /tmp/ppp.tar.gz; \
    echo "${PPP_SHA256}  /tmp/ppp.tar.gz" | sha256sum -c -; \
    mkdir /tmp/ppp; \
    tar -xzf /tmp/ppp.tar.gz -C /tmp/ppp --strip-components=1; \
    cd /tmp/ppp; \
    ./configure --prefix=/usr --sysconfdir=/etc --disable-eaptls --disable-peap; \
    make -j2; \
    make install-strip; \
    cd /; \
    rm -rf /tmp/ppp /tmp/ppp.tar.gz; \
    apk del .ppp-build-deps; \
    pppd --version; \
    test -f /usr/lib/pppd/${PPP_VERSION}/pppol2tp.so
