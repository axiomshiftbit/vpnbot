ARG image=alpine:3.24
FROM $image

ARG OPENVPN_VERSION=2.7.7
ARG EASYRSA_VERSION=3.2.7
ARG EASYRSA_SHA256=308743bc9fe871b902d47dbe98d749daff3a05b27531684f02625ce7208d4598

# Инвалидация кеша apk-слоя: передайте новое значение, чтобы пересборка
# реально сходила в edge за свежими openvpn/openssl без --no-cache.
#   docker compose build --build-arg APK_REFRESH=$(date +%F) ovpn
# Дефолт статичный — обычный build переиспользует кеш.
ARG APK_REFRESH=2026-10-04

# OpenVPN берём из edge, фиксируя upstream-версию; ревизии пакета -rN
# допускаются. Easy-RSA ставится из официального релиза: пакет Alpine отстаёт.
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
        "openvpn~${OPENVPN_VERSION}" \
        iptables \
        iproute2 \
        openssl \
        netcat-openbsd; \
    wget -O /tmp/easyrsa.tgz "https://github.com/OpenVPN/easy-rsa/releases/download/v${EASYRSA_VERSION}/EasyRSA-${EASYRSA_VERSION}.tgz"; \
    echo "${EASYRSA_SHA256}  /tmp/easyrsa.tgz" | sha256sum -c -; \
    mkdir -p /usr/share/easy-rsa; \
    tar -xzf /tmp/easyrsa.tgz --strip-components=1 -C /usr/share/easy-rsa; \
    rm /tmp/easyrsa.tgz; \
    ln -s /usr/share/easy-rsa/easyrsa /usr/bin/easyrsa; \
    mkdir -p /root/.ssh /etc/openvpn/ccd /etc/openvpn/clients; \
    openvpn --version | head -n1 | grep -F "OpenVPN ${OPENVPN_VERSION} "; \
    /usr/share/easy-rsa/easyrsa --version | grep -F "${EASYRSA_VERSION}"; \
    openssl version
