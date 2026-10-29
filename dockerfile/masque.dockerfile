ARG MASQUE_GO_VERSION=1.27.3
FROM golang:${MASQUE_GO_VERSION}-alpine AS build
ARG MASQUE_XRAY_VERSION=v26.10.29
ARG MASQUE_SOURCE_SHA256=ee22c6f21855f70a52e19bff02fa71f4b28ce071d83ff9154fafcaa0f315a642
RUN apk add --no-cache ca-certificates curl tar patch
WORKDIR /build
RUN curl -fL --retry 3 "https://codeload.github.com/XTLS/Xray-core/tar.gz/refs/tags/${MASQUE_XRAY_VERSION}" -o source.tar.gz \
    && echo "${MASQUE_SOURCE_SHA256}  source.tar.gz" | sha256sum -c - \
    && tar -xf source.tar.gz --strip-components=1 && rm source.tar.gz
COPY masque-isolation.patch /masque-isolation.patch
COPY go-retry.sh /build-tools/go-retry.sh
RUN patch -p1 --fuzz=0 < /masque-isolation.patch \
    && sh /build-tools/go-retry.sh go test ./proxy/masque ./transport/internet/finalmask/noise \
    && CGO_ENABLED=0 sh /build-tools/go-retry.sh go build -trimpath -buildvcs=false \
       -ldflags '-s -w -X github.com/xtls/xray-core/core.build=vpnbot-masque.1' -o /xray ./main

FROM alpine:3.24
ARG MASQUE_XRAY_VERSION=v26.10.29
ARG MASQUE_SOURCE_SHA256=ee22c6f21855f70a52e19bff02fa71f4b28ce071d83ff9154fafcaa0f315a642
LABEL io.vpnbot.masque.version=$MASQUE_XRAY_VERSION io.vpnbot.masque.source-sha256=$MASQUE_SOURCE_SHA256
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates python3 openssl
COPY --from=build /xray /usr/local/bin/xray
COPY --from=build /build/LICENSE /usr/share/licenses/xray/LICENSE
ENTRYPOINT ["python3", "/masque_service.py", "/state"]
