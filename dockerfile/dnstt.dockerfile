ARG image=alpine:3.24
# Пин на коммит, как TT_REF у trusttunnel: без него каждая пересборка брала
# текущий master upstream, и два образа с одним тегом могли содержать разный
# dnstt. Обновлять — сменить DNSTT_REF в .env и закоммитить (CI пересоберёт)
# либо локально: DNSTT_REF=<sha> docker compose build dnstt
#
# 0c5c52a5 = тег v1.20260501.0, на нём же стоит master.
ARG DNSTT_REF=0c5c52a57d899c05428c116898941761a2ed83c2
# Мажор+минор, а не голый golang:alpine: плавающий тег означает, что
# еженедельная пересборка того же коммита берёт другой компилятор, и «откатить
# образ по sha» перестаёт что-либо значить. Digest'ы к базам проставляет
# renovate (pinDigests в renovate.json).
ARG PROTOCOL_GO_VERSION=1.27.2
FROM golang:${PROTOCOL_GO_VERSION}-alpine AS go
COPY dockerfile/go-security.sh dockerfile/go-retry.sh /build-tools/
ARG DNSTT_REF
# Приём trusttunnel (git init + fetch --depth 1 <sha>) здесь НЕ работает:
# bamsoftware отдаёт репозиторий по dumb http, а тот не умеет shallow —
# «fatal: dumb http transport does not support shallow capabilities».
# Поэтому обычный clone и checkout; репозиторий на 3 МБ, платить нечем.
RUN apk add --no-cache git \
    && git clone https://www.bamsoftware.com/git/dnstt.git \
    && cd /go/dnstt \
    && git checkout -q "${DNSTT_REF}" \
    && sh /build-tools/go-security.sh \
    && cd /go/dnstt/dnstt-server \
    && sh /build-tools/go-retry.sh go build -ldflags="-s -w" -trimpath \
    && rm -rf /go/dnstt/.git \
    && apk del git
FROM $image
COPY --from=go /go/dnstt/dnstt-server/dnstt-server /usr/local/bin/
RUN apk upgrade --no-cache \
    && apk add --no-cache openssh jq iptables procps \
    && mkdir -p /root/.ssh
ENV ENV="/root/.ashrc"
