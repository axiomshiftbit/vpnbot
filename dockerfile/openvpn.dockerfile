ARG image
FROM $image

# edge/main + edge/community дают свежайшие openvpn 2.6.x и openssl 3.5.x
# (LTS-ветка). Пин через repositories-файл — apk upgrade поднимет обе
# библиотеки при каждой пересборке образа.
RUN set -eux; \
    printf '%s\n' \
        'https://dl-cdn.alpinelinux.org/alpine/edge/main' \
        'https://dl-cdn.alpinelinux.org/alpine/edge/community' \
        > /etc/apk/repositories; \
    apk update; \
    apk upgrade --no-cache --available; \
    apk add --no-cache \
        openssh \
        bash \
        openvpn \
        easy-rsa \
        iptables \
        iproute2 \
        openssl \
        netcat-openbsd; \
    mkdir -p /root/.ssh /etc/openvpn/ccd /etc/openvpn/clients; \
    openvpn --version | head -n1; \
    openssl version
