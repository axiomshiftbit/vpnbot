ARG PROTOCOL_GO_VERSION=1.27.1
FROM golang:${PROTOCOL_GO_VERSION}-alpine AS build
ARG MIERU_VERSION=3.37.0
ARG MIERU_SHA256=7b57f1f8c8ad5f402cdc2603a686d46c218810f7bf9c501142df78f9bed5b413
RUN apk add --no-cache ca-certificates curl tar patch
WORKDIR /build
RUN curl -fL --retry 3 "https://codeload.github.com/enfein/mieru/tar.gz/refs/tags/v${MIERU_VERSION}" -o source.tar.gz \
    && echo "${MIERU_SHA256}  source.tar.gz" | sha256sum -c - \
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
RUN apk add --no-cache ca-certificates python3 \
    && addgroup -S mita && adduser -S -G mita mita
COPY --from=build /mita /mieru-control /usr/local/bin/
COPY --from=build /build/LICENSE /usr/share/licenses/mieru/LICENSE
ENTRYPOINT ["python3", "/mieru_service.py", "/state"]
