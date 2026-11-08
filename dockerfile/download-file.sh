#!/bin/sh
# Только публичные файлы. Для архивов вызывающий код проверяет закреплённую
# SHA-256 после загрузки, до распаковки; несовпадение суммы не вызывает повтор.
set -eu
url=$1
output=$2
doh_url=

fetch() {
    if [ -n "$doh_url" ]; then
        set -- --doh-url "$doh_url" "$@"
    fi
    curl -fsSL --connect-timeout 20 --max-time 180 --retry 5 --retry-all-errors --retry-delay 15 --retry-max-time 300 "$@"
}

if fetch -o "$output" "$url"; then
    exit 0
fi

# Другой DNS-ответ может направить на доступный узел источника. Проверка TLS
# действует и для DoH, и для файла; системный DNS и адреса источников не меняем.
doh_url=https://cloudflare-dns.com/dns-query
echo 'download-file: повторяем через защищённый DNS Cloudflare' >&2
if fetch -o "$output" "$url"; then
    exit 0
fi
# Для GitHub releases есть ещё один официальный путь к тому же архиву.
# Другие источники не подменяем зеркалами или архивами с иной упаковкой.
case "$url" in
    https://github.com/*/*/releases/download/*/*) ;;
    *) exit 1 ;;
esac
repo=${url#https://github.com/}
repo=${repo%%/releases/download/*}
release=${url#https://github.com/"$repo"/releases/download/}
tag=${release%%/*}
api="https://api.github.com/repos/$repo"
metadata=$(mktemp)
trap 'rm -f "$metadata"' EXIT
echo 'download-file: основной адрес недоступен, проверяем официальный API' >&2
fetch -H 'Accept: application/vnd.github+json' -o "$metadata" "$api/releases/tags/$tag"
asset=$(jq -er --arg url "$url" \
    '[.assets[] | select(.browser_download_url == $url) | .url] | if length == 1 then .[0] else error("expected one release asset") end' "$metadata")
case "$asset" in
    "$api/releases/assets/"*) ;;
    *) echo 'download-file: недопустимый адрес архива' >&2; exit 1 ;;
esac
ident=${asset#"$api/releases/assets/"}
case "$ident" in
    ''|*[!0-9]*) echo 'download-file: недопустимый адрес архива' >&2; exit 1 ;;
esac
fetch -H 'Accept: application/octet-stream' -o "$output" "$asset"
