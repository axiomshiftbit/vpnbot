ARG image=alpine:3.24
ARG PROTOCOL_GO_VERSION=1.27.4
FROM golang:${PROTOCOL_GO_VERSION}-alpine AS cores
ARG XRAY_VERSION=""
ARG XRAY_VERSION_2=""
ARG XRAY_VERSION_3=""
ARG XRAY_FORK_VERSION=""
RUN apk add --no-cache ca-certificates curl git jq
COPY dockerfile/go-*.sh dockerfile/download-file.sh dockerfile/go-sources.sha256 /build-tools/
COPY dockerfile/build-xray.sh /build-tools/build-xray.sh
RUN sh /build-tools/build-xray.sh XTLS/Xray-core "$XRAY_VERSION" /out/xray \
    && { [ -z "$XRAY_VERSION_2" ] || sh /build-tools/build-xray.sh XTLS/Xray-core "$XRAY_VERSION_2" /out/xray-2; } \
    && { [ -z "$XRAY_VERSION_3" ] || sh /build-tools/build-xray.sh XTLS/Xray-core "$XRAY_VERSION_3" /out/xray-3; } \
    && sh /build-tools/build-xray.sh Jolymmiles/Xray-core "$XRAY_FORK_VERSION" /out/xray-smux http2legacy \
        './testing/release/... ./transport/internet/reality/... ./infra/conf/... ./common/mux/... ./transport/internet/splithttp/... ./common/singmux/... ./proxy/vless/...'

FROM golang:${PROTOCOL_GO_VERSION}-alpine AS amnezia
RUN apk add --no-cache ca-certificates curl git
COPY dockerfile/go-*.sh dockerfile/download-file.sh dockerfile/go-sources.sha256 dockerfile/wireproxy-node.patch /build-tools/
RUN sh /build-tools/go-source.sh artem-russkikh/wireproxy-awg node-84f4795 /source
WORKDIR /source
RUN git apply --check /build-tools/wireproxy-node.patch \
    && git apply /build-tools/wireproxy-node.patch \
    && sh /build-tools/go-retry.sh go get github.com/amnezia-vpn/amneziawg-go/v3@v3.1.20261116 \
    && sh /build-tools/go-security.sh \
    && CGO_ENABLED=0 sh /build-tools/go-retry.sh go test ./... \
    && CGO_ENABLED=0 sh /build-tools/go-retry.sh go build -trimpath -ldflags '-s -w' -o /out/wireproxy-node ./cmd/wireproxy

FROM $image
RUN apk upgrade --no-cache \
    && apk add --no-cache openssh openssl jq curl grep python3 \
    && mkdir -p /root/.ssh /usr/local/bin \
    && ln -sf /usr/bin/xray /usr/local/bin/xray
COPY --from=cores /out/ /usr/bin/
COPY --from=amnezia /out/ /usr/bin/
ENV ENV="/root/.ashrc"
