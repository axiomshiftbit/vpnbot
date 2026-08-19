ARG image=alpine:3.23
FROM $image

# ── Версии Xray-core ──────────────────────────────────────────────────────────
# В образе живут ДВА ядра, и это осознанно: апстримный XTLS/Xray-core в
# /usr/bin/xray и форк Jolymmiles/Xray-core в /usr/bin/xray-smux. Форк умеет
# sing-mux (протоколы smux/h2mux) и TCP Brutal — с ним сервер принимает
# мультиплексированные соединения штатных sing-box и mihomo, чего апстрим не
# умеет вовсе (у него только свой mux.cool). Активное ядро выбирает симлинк
# /usr/local/bin/xray, который ставит start_xray.sh по маркеру /logs/xray_core,
# то есть переключение и откат — без пересборки образа.
#
# Каждая версия управляется СВОЕЙ переменной (build-arg). Допустимые значения
# у обеих одинаковы:
#
#   ""           → последний СТАБИЛЬНЫЙ релиз (releases/latest) — поведение по умолчанию
#   "prerelease" → последний релиз, СТРОГО помеченный как pre-release / beta
#   "vX.Y.Z"     → КОНКРЕТНАЯ версия по тегу, напр. "v1.8.24" (releases/tags/<tag>)
#
# Способ 1 — через .env / docker-compose (рекомендуется, ничего тут править не нужно):
#   build:
#     args:
#       XRAY_VERSION:      ${XRAY_VERSION}       # значение берётся из .env
#       XRAY_FORK_VERSION: ${XRAY_FORK_VERSION}
#
# Способ 2 — вручную: раскомментируйте РОВНО ОДНУ строку ниже (она переопределит default).
ARG XRAY_VERSION=""
# ARG XRAY_VERSION="prerelease"
# ARG XRAY_VERSION="v1.8.24"
ARG XRAY_FORK_VERSION=""

# .dat из архива не берём: geoip/geosite ядро получает из /logs/geodata
# (XRAY_LOCATION_ASSET), а свой geoip.dat в реестре конфликтовал со встроенным.
# Скачивание с ретраями: релизы тянутся с github, и «Resource temporarily
# unavailable» на одном из двух архивов роняло всю сборку образа (так упал
# прогон dev на 9684fb4). Четыре попытки с нарастающей паузой.
# Дефолтный симлинк — на апстрим: контейнер без маркера (или с маркером на форк,
# но со старым образом без второго бинаря) обязан вести себя ровно как раньше.
RUN fetch_xray() { \
        repo="$1"; ver="$2"; dest="$3"; \
        case "$ver" in \
          "")          api_url="https://api.github.com/repos/$repo/releases/latest" ;; \
          prerelease)  api_url="https://api.github.com/repos/$repo/releases" ;; \
          *)           api_url="https://api.github.com/repos/$repo/releases/tags/$ver" ;; \
        esac; \
        dl_url=$(curl -fsSL "$api_url" \
          | jq -r 'if type=="array" then (map(select(.prerelease==true)) | .[0]) else . end | .assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url'); \
        if [ -z "$dl_url" ] || [ "$dl_url" = null ]; then \
          echo "no Xray-linux-64.zip for $repo $ver" >&2; return 1; \
        fi; \
        rm -rf /tmp/xr && mkdir -p /tmp/xr; \
        n=0; \
        until wget -O /tmp/xr/Xray-linux-64.zip "$dl_url"; do \
          n=$((n+1)); \
          [ "$n" -ge 4 ] && { echo "download failed after $n tries: $dl_url" >&2; return 1; }; \
          echo "retry $n: $dl_url" >&2; sleep $((n*5)); \
        done; \
        unzip -o /tmp/xr/Xray-linux-64.zip -d /tmp/xr \
          && mv /tmp/xr/xray "$dest" \
          && chmod +x "$dest" \
          && rm -rf /tmp/xr; \
    }; \
    apk add --no-cache openssh openssl jq curl \
    && mkdir /root/.ssh \
    && fetch_xray XTLS/Xray-core       "$XRAY_VERSION"      /usr/bin/xray \
    && fetch_xray Jolymmiles/Xray-core "$XRAY_FORK_VERSION" /usr/bin/xray-smux \
    && mkdir -p /usr/local/bin \
    && ln -sf /usr/bin/xray /usr/local/bin/xray
ENV ENV="/root/.ashrc"
