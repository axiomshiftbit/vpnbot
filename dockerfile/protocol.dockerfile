ARG PROTOCOL_GO_VERSION=1.27.1
FROM golang:${PROTOCOL_GO_VERSION}-alpine AS build
ARG PROTOCOL_SINGBOX_VERSION=1.14.1
ARG PROTOCOL_SINGBOX_SHA256=1ea41f7d06b0017fe3d3ba7ee30959048aa0ddde31cb0165dab9257edf673321
RUN apk add --no-cache ca-certificates curl tar patch
WORKDIR /build
RUN curl -fL --retry 3 "https://codeload.github.com/SagerNet/sing-box/tar.gz/refs/tags/v${PROTOCOL_SINGBOX_VERSION}" -o source.tar.gz \
    && echo "${PROTOCOL_SINGBOX_SHA256}  source.tar.gz" | sha256sum -c - \
    && tar -xf source.tar.gz --strip-components=1 && rm source.tar.gz
COPY protocol-stats/main.go ./cmd/protocol-stats/main.go
COPY protocol-policy/ /policy/
RUN patch -p1 --fuzz=0 < /policy/hooks.patch \
    && cp /policy/*.go route/ \
    && cp /policy/tuic/*.go protocol/tuic/
RUN go get google.golang.org/grpc@v1.83.2 golang.org/x/crypto@v0.56.0 \
      github.com/go-chi/chi/v5@v5.3.0 golang.org/x/mod@v0.40.0
RUN go test -tags with_quic,with_utls,with_v2ray_api ./route ./protocol/tuic -run TestVPNBot -count=1
RUN CGO_ENABLED=0 go build -trimpath -tags with_quic,with_utls,with_v2ray_api \
      -ldflags "-s -w -X github.com/sagernet/sing-box/constant.Version=${PROTOCOL_SINGBOX_VERSION}" -o /sing-box ./cmd/sing-box \
    && CGO_ENABLED=0 go build -trimpath -tags with_v2ray_api -ldflags '-s -w' -o /protocol-stats ./cmd/protocol-stats

FROM alpine:3.23
RUN apk add --no-cache ca-certificates python3 openssl
COPY --from=build /sing-box /protocol-stats /usr/local/bin/
COPY --from=build /build/LICENSE /usr/share/licenses/sing-box/LICENSE
ENTRYPOINT ["python3", "/protocol_service.py", "/state"]
