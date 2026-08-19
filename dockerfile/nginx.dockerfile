ARG image=alpine:3.23

# ── Версия nginx ──────────────────────────────────────────────────────────────
# alpine 3.23 держит в main nginx 1.28.x — это уже LEGACY-ветка по нумерации
# upstream (актуальная стабильная — 1.30.x). Пакет alpine при этом полностью
# пропатчен: в APKBUILD 1.28.3-r7 лежат бэкпорты ВСЕХ CVE вплоть до 1.30.4,
# то есть переход на 1.30 — это НЕ про безопасность, а про фиксы и фичи ветки
# 1.29/1.30 (proxy поверх HTTP/2, max_headers, 0-RTT в QUIC, совместимость с
# OpenSSL 4.0, десятки багфиксов в h2/h3 и proxy).
#
# Взять 1.30 из репозитория edge нельзя: пакет собран под библиотеки edge
# (openssl/pcre2 другой версии), apk потащил бы их в базу 3.23 — и edge к тому
# же плавающий, что противоречит пинам во всём остальном репозитории.
# Поэтому бинарь собирается из исходников с пином NGINX_VERSION в .env.
ARG NGINX_VERSION=1.30.4

FROM $image AS build
ARG NGINX_VERSION
RUN set -eux; \
    apk add --no-cache build-base linux-headers openssl-dev pcre2-dev zlib-dev; \
    wget -O nginx.tar.gz "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"; \
    tar -xzf nginx.tar.gz; \
    cd "nginx-${NGINX_VERSION}"; \
    # Флаги — копия конфигурации пакета alpine (main/nginx/APKBUILD), из неё
    # выброшены только модули, которые в ЭТОМ образе не установлены и не могут
    # быть загружены: xslt/image_filter/geoip/perl/mail и три десятка сторонних
    # (они у alpine живут в отдельных subpackages nginx-mod-*, а тут ставится
    # лишь nginx + nginx-mod-stream). Пути обязаны совпадать с пакетными:
    # config/upstream.conf грузит модуль по абсолютному пути
    # /usr/lib/nginx/modules/ngx_stream_module.so, а временные каталоги
    # /var/lib/nginx/tmp/* создаёт и раздаёт пользователю nginx сам пакет.
    #
    # --with-cc-opt=-Wno-error вместо патча no-werror.patch из aports: nginx сам
    # добавляет -Werror для gcc, а NGX_CC_OPT дописывается в CFLAGS последним и
    # перебивает его. Без этого сборка падает на первом же новом warning'е gcc.
    ./configure \
        --prefix=/var/lib/nginx \
        --sbin-path=/usr/sbin/nginx \
        --modules-path=/usr/lib/nginx/modules \
        --conf-path=/etc/nginx/nginx.conf \
        --pid-path=/run/nginx/nginx.pid \
        --lock-path=/run/nginx/nginx.lock \
        --http-client-body-temp-path=/var/lib/nginx/tmp/client_body \
        --http-proxy-temp-path=/var/lib/nginx/tmp/proxy \
        --http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi \
        --http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi \
        --http-scgi-temp-path=/var/lib/nginx/tmp/scgi \
        --user=nginx \
        --group=nginx \
        --with-threads \
        --with-file-aio \
        --with-compat \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-http_v3_module \
        --with-http_realip_module \
        --with-http_addition_module \
        --with-http_sub_module \
        --with-http_dav_module \
        --with-http_flv_module \
        --with-http_mp4_module \
        --with-http_gunzip_module \
        --with-http_gzip_static_module \
        --with-http_auth_request_module \
        --with-http_random_index_module \
        --with-http_secure_link_module \
        --with-http_degradation_module \
        --with-http_slice_module \
        --with-http_stub_status_module \
        --with-stream=dynamic \
        --with-stream_ssl_module \
        --with-stream_realip_module \
        --with-stream_ssl_preread_module \
        --with-cc-opt=-Wno-error; \
    make -j"$(nproc)"; \
    mkdir -p /out; \
    cp objs/nginx objs/ngx_stream_module.so /out/; \
    # sanity: собралась ровно запрошенная версия (ср. `caddy version | grep`
    # в naive.dockerfile) — иначе опечатка в пине всплыла бы только на сервере
    /out/nginx -v 2>&1 | grep -q "nginx/${NGINX_VERSION}$"

FROM $image
# Пакет alpine ставится НЕ ради бинаря — ради обвязки, которую иначе пришлось бы
# воспроизводить руками и рано или поздно разойтись: пользователь nginx с
# фиксированными uid/gid 100/101 (под ними лежат файлы в бинд-маунте /logs),
# группа www-data, /etc/nginx/mime.types (его include'ит config/nginx.conf),
# /var/lib/nginx/tmp/* с правами, /var/log/nginx, /run/nginx и рантайм-зависимости
# (libssl3, libcrypto3, pcre2, zlib) нужной версии. Бинарь и stream-модуль
# поверх заменяются на собранные выше — обе половины собраны против одних и тех
# же библиотек одного и того же базового образа, поэтому ABI сходится.
#
# ВАЖНО для будущих правок: в базе apk после этого остаётся запись nginx-1.28.3,
# хотя на диске лежит собранный бинарь. Любой `apk upgrade` (или переустановка
# nginx-mod-stream) в этом образе ВЕРНЁТ пакетные 1.28.3 поверх — молча, без
# ошибки сборки. Сейчас ни один слой этого не делает; если понадобится —
# ставить пакет ДО COPY и не трогать apk после.
RUN apk add --no-cache nginx-mod-stream openssh \
    && mkdir /root/.ssh \
    && mkdir /var/cache/nginx
COPY --from=build /out/nginx /usr/sbin/nginx
COPY --from=build /out/ngx_stream_module.so /usr/lib/nginx/modules/ngx_stream_module.so
ARG NGINX_VERSION
# Проверка на этапе сборки, а не на сервере: версия та, что просили, и
# ngx_stream_module.so реально грузится этим бинарём (несовпадение ABI модуля и
# ядра nginx иначе вылезло бы только при старте upstream-контейнера, где стрим и
# используется — ssl_preread, proxy_pass по SNI).
RUN set -eux; \
    nginx -v 2>&1 | grep -q "nginx/${NGINX_VERSION}$"; \
    printf '%s\n' \
        'load_module /usr/lib/nginx/modules/ngx_stream_module.so;' \
        'events {}' \
        'stream { server { listen 65000; ssl_preread on; proxy_pass 127.0.0.1:1; } }' \
        > /tmp/stream-check.conf; \
    nginx -t -c /tmp/stream-check.conf; \
    rm /tmp/stream-check.conf
ENV ENV="/root/.ashrc"
