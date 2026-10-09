ARG image=alpine:3.24
ARG PROTOCOL_GO_VERSION=1.27.2
FROM golang:${PROTOCOL_GO_VERSION}-alpine AS cores
ARG XRAY_VERSION=""
ARG XRAY_VERSION_2=""
ARG XRAY_VERSION_3=""
ARG XRAY_FORK_VERSION=""
RUN apk add --no-cache ca-certificates curl git jq
COPY dockerfile/go-*.sh dockerfile/go-sources.sha256 /build-tools/
COPY dockerfile/build-xray.sh /build-tools/build-xray.sh
RUN sh /build-tools/build-xray.sh XTLS/Xray-core "$XRAY_VERSION" /out/xray \
    && { [ -z "$XRAY_VERSION_2" ] || sh /build-tools/build-xray.sh XTLS/Xray-core "$XRAY_VERSION_2" /out/xray-2; } \
    && { [ -z "$XRAY_VERSION_3" ] || sh /build-tools/build-xray.sh XTLS/Xray-core "$XRAY_VERSION_3" /out/xray-3; } \
    && sh /build-tools/build-xray.sh Jolymmiles/Xray-core "$XRAY_FORK_VERSION" /out/xray-smux http2legacy \
        './testing/release/... ./transport/internet/reality/... ./infra/conf/... ./common/mux/... ./transport/internet/splithttp/... ./common/singmux/... ./proxy/vless/...'

FROM $image
RUN apk upgrade --no-cache \
    && apk add --no-cache openssh openssl jq curl grep \
    && mkdir -p /root/.ssh /usr/local/bin \
    && ln -sf /usr/bin/xray /usr/local/bin/xray
COPY --from=cores /out/ /usr/bin/
ENV ENV="/root/.ashrc"
