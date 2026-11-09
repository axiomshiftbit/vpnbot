ARG MASQUE_GO_VERSION=1.27.3
FROM golang:${MASQUE_GO_VERSION}-alpine AS build
ARG MASQUE_XRAY_VERSION=v26.11.9
ARG MASQUE_SOURCE_SHA256=d5a47bed1b85e1cdfe3cb2f88a02e2db7144f0f8bee541d20b84fafa8fdf6c8d
RUN apk add --no-cache ca-certificates curl tar patch
WORKDIR /build
COPY download-file.sh /build-tools/download-file.sh
RUN sh /build-tools/download-file.sh "https://codeload.github.com/XTLS/Xray-core/tar.gz/refs/tags/${MASQUE_XRAY_VERSION}" source.tar.gz \
    && echo "${MASQUE_SOURCE_SHA256}  source.tar.gz" | sha256sum -c - \
    && tar -xf source.tar.gz --strip-components=1 && rm source.tar.gz
COPY masque-isolation.patch /masque-isolation.patch
COPY go-retry.sh go-security.sh /build-tools/
# Общие минимальные версии уязвимых модулей, как в остальных Go-образах
# (иначе x/net и др. остаются версиями из go.mod Xray).
RUN patch -p1 --fuzz=0 < /masque-isolation.patch \
    && sh /build-tools/go-security.sh \
    && sh /build-tools/go-retry.sh go test ./proxy/masque ./transport/internet/finalmask/noise \
    && CGO_ENABLED=0 sh /build-tools/go-retry.sh go build -trimpath -buildvcs=false \
       -ldflags '-s -w -X github.com/xtls/xray-core/core.build=vpnbot-masque.1' -o /xray ./main

FROM alpine:3.24
ARG MASQUE_XRAY_VERSION=v26.11.9
ARG MASQUE_SOURCE_SHA256=d5a47bed1b85e1cdfe3cb2f88a02e2db7144f0f8bee541d20b84fafa8fdf6c8d
LABEL io.vpnbot.masque.version=$MASQUE_XRAY_VERSION io.vpnbot.masque.source-sha256=$MASQUE_SOURCE_SHA256
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates python3 openssl
COPY --from=build /xray /usr/local/bin/xray
COPY --from=build /build/LICENSE /usr/share/licenses/xray/LICENSE
ENTRYPOINT ["python3", "/masque_service.py", "/state"]
