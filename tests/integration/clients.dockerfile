# Disposable client tools, never published as a VPNBot installation image.
ARG GO_IMAGE
ARG WG_IMAGE
ARG PHP_IMAGE
ARG SS_IMAGE
ARG IPSEC_IMAGE
FROM ${GO_IMAGE} AS clients
ARG MIERU_VERSION
ARG MIERU_SOURCE_SHA256
ARG DNSTT_REF
RUN apk add --no-cache git curl tar \
    && curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 "https://codeload.github.com/enfein/mieru/tar.gz/refs/tags/${MIERU_VERSION}" -o /tmp/mieru.tar.gz \
    && echo "${MIERU_SOURCE_SHA256}  /tmp/mieru.tar.gz" | sha256sum -c - \
    && mkdir /mieru && tar -xf /tmp/mieru.tar.gz -C /mieru --strip-components=1 \
    && cd /mieru && CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /out/mieru ./cmd/mieru \
    # Клонирование само не повторяется при сетевом сбое, в отличие от загрузок выше.
    && for attempt in 1 2 3 4 5; do \
         git clone https://www.bamsoftware.com/git/dnstt.git /dnstt && break; \
         rm -rf /dnstt; sleep 10; \
       done \
    && cd /dnstt && git checkout --detach "$DNSTT_REF" \
    && CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /out/dnstt-client ./dnstt-client
FROM ${IPSEC_IMAGE} AS native_clients
# Alpine's OpenConnect 9.12 misses the upstream DTLS/OpenSSL 3.1+ fix.
# This is a test client only; the ocserv installation image is unchanged.
ARG OPENCONNECT_VERSION=9.21
ARG OPENCONNECT_SHA256=5b32369467db6e5f317aa1ed12cfcbb81ed00bdbc765450b6bfcbdc300944a58
ARG SINGBOX_VERSION
ARG SINGBOX_SHA256
RUN apk add --no-cache build-base linux-headers pkgconf curl tar openssl-dev libxml2-dev zlib-dev lz4-dev \
    && curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 "https://www.infradead.org/openconnect/download/openconnect-${OPENCONNECT_VERSION}.tar.gz" -o /tmp/openconnect.tar.gz \
    && echo "${OPENCONNECT_SHA256}  /tmp/openconnect.tar.gz" | sha256sum -c - \
    && mkdir /openconnect && tar -xf /tmp/openconnect.tar.gz -C /openconnect --strip-components=1 \
    && cd /openconnect && ./configure --without-gnutls --disable-shared --disable-nls \
       --with-vpnc-script=/etc/vpnc/vpnc-script \
       --without-libproxy --without-stoken --without-libpskc --without-libpcsclite --without-gssapi \
    && make -j2 openconnect \
    && install -Dm755 openconnect /out/openconnect \
    && strip /out/openconnect \
    && /out/openconnect --version
# The bot's small sing-box utility lacks Naive outbound. Exercise exports with
# the pinned official musl client, which includes that outbound on Alpine.
RUN curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 "https://github.com/SagerNet/sing-box/releases/download/${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION#v}-linux-amd64-musl.tar.gz" -o /tmp/sing-box.tar.gz \
    && echo "${SINGBOX_SHA256}  /tmp/sing-box.tar.gz" | sha256sum -c - \
    && tar -xf /tmp/sing-box.tar.gz -C /out --strip-components=1 "sing-box-${SINGBOX_VERSION#v}-linux-amd64-musl/sing-box" \
    && /out/sing-box version | grep with_naive_outbound
FROM ${WG_IMAGE} AS wg
FROM ${PHP_IMAGE} AS php
FROM ${SS_IMAGE} AS ss
FROM ${IPSEC_IMAGE}
RUN apk add --no-cache curl python3 py3-cryptography openssl openssh-client sshpass \
      openvpn vpnc bind-tools wireguard-tools iproute2 iptables bash procps-ng libgcc libstdc++ libxml2 lz4-libs
COPY --from=wg /usr/bin/awg /usr/bin/awg-quick /usr/bin/amneziawg-go /usr/bin/
COPY --from=php /usr/bin/mihomo /usr/bin/
COPY --from=ss /usr/bin/sslocal /usr/bin/v2ray-plugin /usr/bin/ck-client /usr/bin/simple-tls /usr/bin/
COPY --from=clients /out/ /usr/bin/
COPY --from=native_clients /out/ /usr/bin/
ENTRYPOINT ["sleep", "infinity"]
CMD []
