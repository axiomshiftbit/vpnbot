FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
ENV GOTOOLCHAIN=local GOWORK=off GOMAXPROCS=4
WORKDIR /src
ADD --checksum=sha256:0958ccd23b1ea9a141d715d15478b1e040fd04bcca19d8ff5529636b1b753e18 https://codeload.github.com/SagerNet/sing-box/tar.gz/refs/tags/v1.14.4 /tmp/source.tar.gz
RUN tar -xzf /tmp/source.tar.gz --strip-components=1
COPY go.mod go.sum /src/
COPY DEFAULT_BUILD_TAGS_WINDOWS LDFLAGS /inputs/
RUN cmp release/DEFAULT_BUILD_TAGS_WINDOWS /inputs/DEFAULT_BUILD_TAGS_WINDOWS \
    && cmp release/LDFLAGS /inputs/LDFLAGS \
    && sha256sum go.mod go.sum > /tmp/locks.sha256 \
    && go mod download all && sha256sum -c /tmp/locks.sha256
ENV CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOAMD64=v1 GOPROXY=off
RUN --network=none tags=$(cat release/DEFAULT_BUILD_TAGS_WINDOWS) \
    && flags="-X github.com/sagernet/sing-box/constant.Version=1.14.4+vpnbot.security.20261125 $(cat release/LDFLAGS) -s -w -buildid=" \
    && go build -mod=readonly -trimpath -tags "$tags" -ldflags "$flags" -o /out/sing-box.exe ./cmd/sing-box \
    && sha256sum -c /tmp/locks.sha256
FROM scratch
COPY --from=build /out/sing-box.exe /sing-box.exe
