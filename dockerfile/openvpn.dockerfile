ARG image=alpine:3.24
FROM $image

ARG OPENVPN_VERSION=2.7.9
ARG EASYRSA_VERSION=3.2.7
ARG EASYRSA_SHA256=308743bc9fe871b902d47dbe98d749daff3a05b27531684f02625ce7208d4598

# Инвалидация кеша apk-слоя: передайте новое значение, чтобы пересборка
# обновила пакеты стабильной ветки: openvpn/openssl без --no-cache.
#   docker compose build --build-arg APK_REFRESH=$(date +%F) ovpn
# Дефолт статичный — обычный build переиспользует кеш.
ARG APK_REFRESH=2026-10-05

# OpenVPN собирается из официального архива с проверкой суммы: пакет Alpine
# отстаёт от исправлений безопасности (2.7.8 закрывает CVE-2026-84790 и
# CVE-2026-84964, а в Alpine 3.24 и edge на 2026-10-10 лежит 2.7.7). Параметры
# configure те же, что у пакета Alpine. Когда пакет догонит, можно вернуться
# к установке пакетом. Easy-RSA ставится из официального релиза.
COPY dockerfile/sources.sha256 /sources.sha256
COPY dockerfile/download-file.sh /build-tools/download-file.sh

RUN set -eux; \
    echo "apk refresh token: $APK_REFRESH"; \
    apk update; \
    apk upgrade --no-cache --available; \
    # постоянные пакеты: библиотеки, с которыми слинкован openvpn, и то, что
    # нужно боту и start_ovpn.sh
    apk add --no-cache \
        openssh \
        bash \
        iptables \
        iproute2 \
        openssl \
        netcat-openbsd \
        libcap-ng \
        libnl3 \
        lz4-libs \
        lzo \
        pkcs11-helper; \
    apk add --no-cache --virtual .build-deps \
        build-base curl jq \
        linux-headers \
        openssl-dev \
        libcap-ng-dev \
        libnl3-dev \
        lz4-dev \
        lzo-dev \
        pkcs11-helper-dev; \
    sh /build-tools/download-file.sh "https://github.com/OpenVPN/openvpn/releases/download/v${OPENVPN_VERSION}/openvpn-${OPENVPN_VERSION}.tar.gz" /tmp/openvpn.tar.gz; \
    awk -v key="openvpn/${OPENVPN_VERSION}" '$2 == key {print $1 "  /tmp/openvpn.tar.gz"}' /sources.sha256 | sha256sum -c -; \
    tar -xzf /tmp/openvpn.tar.gz -C /tmp; \
    rm /tmp/openvpn.tar.gz; \
    cd /tmp/openvpn-${OPENVPN_VERSION}; \
    # Плагин auth-pam в Alpine вынесен в отдельный пакет, и образ его не ставил.
    ./configure --prefix=/usr --sysconfdir=/etc/openvpn --enable-dco --enable-pkcs11 --disable-dns-updown-by-default \
        --disable-plugin-auth-pam; \
    make -j"$(nproc)"; \
    make install-strip; \
    cd /; \
    rm -rf /tmp/openvpn-* /sources.sha256 /usr/share/man /usr/share/doc/openvpn /usr/include/openvpn /usr/lib/openvpn/plugins/*.la; \
    sh /build-tools/download-file.sh "https://github.com/OpenVPN/easy-rsa/releases/download/v${EASYRSA_VERSION}/EasyRSA-${EASYRSA_VERSION}.tgz" /tmp/easyrsa.tgz; \
    echo "${EASYRSA_SHA256}  /tmp/easyrsa.tgz" | sha256sum -c -; \
    mkdir -p /usr/share/easy-rsa; \
    tar -xzf /tmp/easyrsa.tgz --strip-components=1 -C /usr/share/easy-rsa; \
    rm /tmp/easyrsa.tgz /build-tools/download-file.sh; \
    apk del .build-deps; \
    ln -s /usr/share/easy-rsa/easyrsa /usr/bin/easyrsa; \
    mkdir -p /root/.ssh /etc/openvpn/ccd /etc/openvpn/clients; \
    openvpn --version | head -n1 | grep -F "OpenVPN ${OPENVPN_VERSION} "; \
    /usr/share/easy-rsa/easyrsa --version | grep -F "${EASYRSA_VERSION}"; \
    openssl version
