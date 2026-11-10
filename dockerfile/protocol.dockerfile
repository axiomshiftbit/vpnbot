ARG PROTOCOL_GO_VERSION=1.27.4
ARG SINGBOX_VERSION=v1.14.4
ARG SINGBOX_SOURCE_SHA256=0958ccd23b1ea9a141d715d15478b1e040fd04bcca19d8ff5529636b1b753e18
FROM golang:${PROTOCOL_GO_VERSION}-alpine AS build
ARG SINGBOX_VERSION
ARG SINGBOX_SOURCE_SHA256
RUN apk add --no-cache ca-certificates curl tar patch
WORKDIR /build
COPY download-file.sh /build-tools/download-file.sh
RUN sh /build-tools/download-file.sh "https://codeload.github.com/SagerNet/sing-box/tar.gz/refs/tags/v${SINGBOX_VERSION#v}" source.tar.gz \
    && echo "${SINGBOX_SOURCE_SHA256}  source.tar.gz" | sha256sum -c - \
    && tar -xf source.tar.gz --strip-components=1 && rm source.tar.gz
COPY protocol-stats/main.go ./cmd/protocol-stats/main.go
COPY protocol-policy/ /policy/
COPY go-retry.sh go-security.sh /build-tools/
RUN patch -p1 --fuzz=0 < /policy/hooks.patch \
    && cp /policy/*.go route/ \
    && cp /policy/tuic/*.go protocol/tuic/ \
    && cp /policy/anytls/*.go protocol/anytls/
RUN sh /build-tools/go-security.sh
RUN sh /build-tools/go-retry.sh go test -tags with_quic,with_utls,with_v2ray_api ./route ./protocol/tuic ./protocol/anytls -run TestVPNBot -count=1
RUN CGO_ENABLED=0 sh /build-tools/go-retry.sh go build -trimpath -tags with_quic,with_utls,with_v2ray_api \
      -ldflags "-s -w -X github.com/sagernet/sing-box/constant.Version=${SINGBOX_VERSION#v}" -o /sing-box ./cmd/sing-box \
    && CGO_ENABLED=0 sh /build-tools/go-retry.sh go build -trimpath -tags with_v2ray_api -ldflags '-s -w' -o /protocol-stats ./cmd/protocol-stats

FROM alpine:3.24
ARG SINGBOX_VERSION
ARG SINGBOX_SOURCE_SHA256
LABEL io.vpnbot.sing-box.version=$SINGBOX_VERSION io.vpnbot.sing-box.source-sha256=$SINGBOX_SOURCE_SHA256
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates python3 openssl
COPY --from=build /sing-box /protocol-stats /usr/local/bin/
COPY --from=build /build/LICENSE /usr/share/licenses/sing-box/LICENSE
ENTRYPOINT ["python3", "/protocol_service.py", "/state"]
