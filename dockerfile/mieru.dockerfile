ARG PROTOCOL_GO_VERSION=1.27.1
ARG MIERU_VERSION=v3.38.0
ARG MIERU_SOURCE_SHA256=f81708e5c35d6ccd6fefce1d0d9b09cccade3517a5695fe58586de74bff16ec7
FROM golang:${PROTOCOL_GO_VERSION}-alpine AS build
ARG MIERU_VERSION
ARG MIERU_SOURCE_SHA256
RUN apk add --no-cache ca-certificates curl tar patch
WORKDIR /build
RUN curl -fL --retry 3 "https://codeload.github.com/enfein/mieru/tar.gz/refs/tags/v${MIERU_VERSION#v}" -o source.tar.gz \
    && echo "${MIERU_SOURCE_SHA256}  source.tar.gz" | sha256sum -c - \
    && tar -xf source.tar.gz --strip-components=1 && rm source.tar.gz
COPY mieru-control/main.go ./cmd/vpnbot-control/main.go
COPY mieru-policy/ /policy/
RUN patch -p1 --fuzz=0 < /policy/hooks.patch \
    && cp /policy/*.go pkg/socks5/
RUN go get google.golang.org/grpc@v1.83.2 golang.org/x/crypto@v0.56.0 \
      golang.org/x/net@v0.58.0 golang.org/x/text@v0.41.0
RUN go test -vet=off ./pkg/socks5 -run TestVPNBot -count=1
RUN CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /mita ./cmd/mita \
    && CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /mieru-control ./cmd/vpnbot-control

FROM alpine:3.23
ARG MIERU_VERSION
ARG MIERU_SOURCE_SHA256
LABEL io.vpnbot.mieru.version=$MIERU_VERSION io.vpnbot.mieru.source-sha256=$MIERU_SOURCE_SHA256
RUN apk add --no-cache ca-certificates python3 \
    && addgroup -S mita && adduser -S -G mita mita
COPY --from=build /mita /mieru-control /usr/local/bin/
COPY --from=build /build/LICENSE /usr/share/licenses/mieru/LICENSE
ENTRYPOINT ["python3", "/mieru_service.py", "/state"]
