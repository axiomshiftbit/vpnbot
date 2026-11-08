#!/bin/sh
# Публичные исходники закреплены SHA-256; третий столбец фиксирует коммит,
# если upstream переписывает тег. Новые исходники требуют проверки.
set -eu
repo=$1; tag=$2; destination=$3
manifest=$(dirname "$0")/go-sources.sha256
checksum=${4:-$(awk -v key="$repo/$tag" '$2 == key {print $1}' "$manifest")}
if [ "${#checksum}" != 64 ]; then
    echo "Нет проверенной контрольной суммы исходников $repo/$tag" >&2
    exit 1
fi
reference=$(awk -v key="$repo/$tag" '$2 == key {print $3}' "$manifest")
if [ -n "$reference" ]; then
    printf '%s\n' "$reference" | grep -Eq '^[0-9a-f]{40}$' || exit 1
else
    reference="refs/tags/$tag"
fi
mkdir -p "$destination"
archive=$(mktemp)
trap 'rm -f "$archive"' EXIT
sh "$(dirname "$0")/download-file.sh" "https://codeload.github.com/$repo/tar.gz/$reference" "$archive"
printf '%s  %s\n' "$checksum" "$archive" | sha256sum -c -
tar -xf "$archive" -C "$destination" --strip-components=1
