ARG image
FROM $image
RUN apk add --no-cache \
        openssh \
        bash \
        openvpn \
        easy-rsa \
        iptables \
        iproute2 \
        openssl \
        netcat-openbsd \
    && mkdir -p /root/.ssh /etc/openvpn/ccd /etc/openvpn/clients
