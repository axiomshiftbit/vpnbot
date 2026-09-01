ARG image=alpine:3.23
FROM $image

# ── Версии (задаются в .env, пробрасываются через args в compose) ─────────────
# Раньше все четыре компонента тянулись через releases/latest: пересборка молча
# давала другой набор бинарей, откатиться было нельзя, а понять, что стоит в
# контейнере, можно было только зайдя в него руками.
#
# Пустое значение = releases/latest (прежнее поведение), конкретный тег —
# releases/tags/<tag>. Значения по умолчанию — то, что реально проверено в бою.
ARG SS_RUST_VERSION=v1.25.0
ARG V2RAY_PLUGIN_VERSION=v5.49.0
ARG CLOAK_VERSION=v2.12.0
ARG SIMPLE_TLS_VERSION=v0.8.0

# Хелпер: URL ассета релиза по тегу (или latest при пустом теге).
# grep/cut оставлены как были — jq в этот слой ещё не установлен.
RUN set -eux; \
    apk add --no-cache openssh git xz jq unzip; \
    mkdir /root/.ssh; \
    asset() { \
        repo="$1"; ver="$2"; pat="$3"; \
        if [ -z "$ver" ]; then api="https://api.github.com/repos/$repo/releases/latest"; \
        else api="https://api.github.com/repos/$repo/releases/tags/$ver"; fi; \
        wget -q -O - "$api" | grep browser_download_url | cut -d\" -f4 | egrep "$pat" | head -1; \
    }; \
    wget -O shadowsocks-rust.tar.xz "$(asset shadowsocks/shadowsocks-rust "$SS_RUST_VERSION" '\.x86_64-unknown-linux-musl\.tar\.xz$')"; \
    tar -xf shadowsocks-rust.tar.xz; \
    wget -O v2ray-plugin.tar.gz "$(asset teddysun/v2ray-plugin "$V2RAY_PLUGIN_VERSION" 'v2ray-plugin-linux-amd64')"; \
    tar -xf v2ray-plugin.tar.gz; \
    wget -O /usr/bin/ck-server "$(asset cbeuw/Cloak "$CLOAK_VERSION" 'ck-server-linux-amd64')"; \
    wget -O /usr/bin/ck-client "$(asset cbeuw/Cloak "$CLOAK_VERSION" 'ck-client-linux-amd64')"; \
    chmod +x /usr/bin/ck-server /usr/bin/ck-client; \
    wget -O simple-tls.zip "$(asset IrineSistiana/simple-tls "$SIMPLE_TLS_VERSION" 'simple-tls-linux-amd64\.zip$')"; \
    unzip -j -o simple-tls.zip -d /tmp/stls; \
    mv /tmp/stls/simple-tls /usr/bin/simple-tls; \
    chmod +x /usr/bin/simple-tls; \
    mv sslocal ssserver ssmanager ssservice ssurl /usr/bin/; \
    mv v2ray-plugin_linux_amd64 /usr/bin/v2ray-plugin; \
    rm -rf /tmp/stls simple-tls.zip v2ray-plugin.tar.gz shadowsocks-rust.tar.xz; \
    # sanity: все четыре бинаря на месте и запускаются — иначе битая сборка
    # всплыла бы только в рантайме (ср. `caddy version` в naive.dockerfile)
    ssserver --version; \
    v2ray-plugin -version | head -1; \
    ck-server -v; \
    simple-tls -v; \
    # git/xz/unzip нужны только распаковке выше — в рантайме их не зовёт ни
    # start_ss.sh, ни бот (там из этого списка живёт только jq). Сборочные
    # утилиты в рантайм-образе — лишняя поверхность у контейнера, который
    # терминирует недоверенный клиентский трафик.
    apk del git xz unzip
ENV ENV="/root/.ashrc"
