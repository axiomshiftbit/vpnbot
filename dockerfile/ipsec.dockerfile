ARG image
FROM $image

# Инвалидация кеша apk-слоя: передайте новое значение, чтобы пересборка
# реально сходила в edge за свежими strongswan/xl2tpd/openssl без --no-cache.
#   docker compose build --build-arg APK_REFRESH=$(date +%F) ipsec
# Дефолт статичный — обычный build переиспользует кеш.
ARG APK_REFRESH=2026-07-03

# edge/main + edge/community дают свежие strongswan 5.9.x (IKEv1 для
# L2TP/IPsec + IKEv2 EAP-MSCHAPv2) и openssl 3.5.x LTS.
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
        strongswan \
        xl2tpd \
        ppp \
        iptables \
        iproute2 \
        openssl \
        netcat-openbsd; \
    mkdir -p /root/.ssh /etc/swanctl /config/ipsec; \
    /usr/sbin/ipsec version || true; \
    swanctl --version; \
    xl2tpd --version 2>&1 | head -n1 || true; \
    openssl version
