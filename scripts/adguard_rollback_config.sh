#!/bin/sh
# Офлайн-переход со схемы AdGuard Home 1.0.0 к 0.107.80.
set -eu
umask 077
config=${1:?Укажите путь к AdGuardHome.yaml}
binary=/opt/adguardhome/AdGuardHome
case "$("$binary" --version 2>/dev/null)" in
    *'version v0.107.80') ;;
    *) echo 'Нужен проверяющий бинарник AdGuard Home v0.107.80' >&2; exit 1 ;;
esac
test -f "$config" && test ! -L "$config" || exit 1
dir=$(dirname "$config")
tmp=$(mktemp -d "$dir/.adguard-rollback.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' HUP INT TERM
cp -p "$config" "$tmp/original"
schema=$(awk '/^schema_version:/ { print $2 }' "$tmp/original")
case "$schema" in
    34) candidate=$tmp/original ;;
    35)
        candidate=$tmp/candidate
        sed -E 's/^(schema_version:[[:blank:]]+)35([[:blank:]]*(#.*)?)$/\134\2/' "$tmp/original" > "$candidate"
        ;;
    *) echo 'Поддерживаются только схемы 35 и 34' >&2; exit 1 ;;
esac
mkdir "$tmp/work"
if ! "$binary" --check-config -w "$tmp/work" -c "$candidate" > "$tmp/validation.log" 2>&1; then
    echo 'AdGuard Home 0.107.80 отклонил подготовленный YAML' >&2
    exit 1
fi
cmp -s "$config" "$tmp/original" || { echo 'Конфигурация изменилась во время проверки' >&2; exit 1; }
if [ "$schema" = 35 ]; then
    chown "$(stat -c '%u:%g' "$config")" "$candidate"
    chmod 600 "$candidate"
    mv "$candidate" "$config"
fi
echo 'Конфигурация готова для AdGuard Home v0.107.80'
