#!/bin/sh
# Публичные исходники закреплены тегом и SHA-256; новый тег требует проверки.
set -eu
repo=$1; tag=$2; destination=$3
checksum=${4:-$(awk -v key="$repo/$tag" '$2 == key {print $1}' /build-tools/go-sources.sha256)}
if [ "${#checksum}" != 64 ]; then
    echo "Нет проверенной контрольной суммы исходников $repo/$tag" >&2
    exit 1
fi
mkdir -p "$destination"
archive=$(mktemp)
trap 'rm -f "$archive"' EXIT
curl -fL --retry 3 "https://codeload.github.com/$repo/tar.gz/refs/tags/$tag" -o "$archive"
printf '%s  %s\n' "$checksum" "$archive" | sha256sum -c -
tar -xf "$archive" -C "$destination" --strip-components=1
