ARG MASQUE_GO_VERSION=1.27.1
FROM golang:${MASQUE_GO_VERSION}-alpine AS build
ARG MASQUE_XRAY_VERSION=v26.9.30
ARG MASQUE_SOURCE_SHA256=85162fa61eb6d1adc9199afff7b41299e69dedd094907e9c56ef665c236b3ef0
RUN apk add --no-cache ca-certificates curl tar patch
WORKDIR /build
RUN curl -fL --retry 3 "https://codeload.github.com/XTLS/Xray-core/tar.gz/refs/tags/${MASQUE_XRAY_VERSION}" -o source.tar.gz \
    && echo "${MASQUE_SOURCE_SHA256}  source.tar.gz" | sha256sum -c - \
    && tar -xf source.tar.gz --strip-components=1 && rm source.tar.gz
COPY masque-isolation.patch /masque-isolation.patch
RUN patch -p1 --fuzz=0 < /masque-isolation.patch \
    && go test ./proxy/masque ./transport/internet/finalmask/noise \
    && CGO_ENABLED=0 go build -trimpath -buildvcs=false \
       -ldflags '-s -w -X github.com/xtls/xray-core/core.build=vpnbot-masque.1' -o /xray ./main

FROM alpine:3.24
ARG MASQUE_XRAY_VERSION=v26.9.30
ARG MASQUE_SOURCE_SHA256=85162fa61eb6d1adc9199afff7b41299e69dedd094907e9c56ef665c236b3ef0
LABEL io.vpnbot.masque.version=$MASQUE_XRAY_VERSION io.vpnbot.masque.source-sha256=$MASQUE_SOURCE_SHA256
RUN apk add --no-cache ca-certificates python3 openssl
COPY --from=build /xray /usr/local/bin/xray
COPY --from=build /build/LICENSE /usr/share/licenses/xray/LICENSE
ENTRYPOINT ["python3", "/masque_service.py", "/state"]
