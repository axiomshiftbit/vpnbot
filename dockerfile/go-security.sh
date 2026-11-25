#!/bin/sh
# Обновляем только присутствующие уязвимые зависимости, без go get -u и
# понижения более новых версий upstream. Итоговый бинарник проверяет Trivy.
set -eu
export GOWORK=off
tools=$(dirname "$0")
while read -r module fixed; do
    modules=$(sh "$tools/go-retry.sh" go list -m -mod=mod -f '{{.Path}} {{.Version}}' all)
    current=$(printf '%s\n' "$modules" | awk -v name="$module" '$1 == name {print $2}')
    [ -n "$current" ] || continue
    oldest=$(printf '%s\n%s\n' "$current" "$fixed" | sort -V | head -1)
    if [ "$oldest" = "$current" ] && [ "$current" != "$fixed" ]; then
        # go get может поднять зависимые модули выше наших минимальных пинов.
        # Перечитываем граф перед следующим шагом, чтобы не понизить их и не
        # задать одновременно несовместимые точные версии.
        sh "$tools/go-retry.sh" go get "$module@$fixed"
    fi
done <<'PINS'
google.golang.org/grpc v1.85.0
golang.org/x/crypto v0.58.0
golang.org/x/net v0.62.0
golang.org/x/text v0.44.0
golang.org/x/mod v0.43.0
golang.org/x/sys v0.50.0
golang.org/x/sync v0.25.0
golang.org/x/tools v0.52.0
google.golang.org/protobuf v1.36.12
github.com/klauspost/compress v1.20.4
golang.org/x/crypto/x509roots/fallback v0.0.0-20261109165751-4e10f38b063d
github.com/go-jose/go-jose/v3 v3.0.5
github.com/go-jose/go-jose/v4 v4.1.9
github.com/smallstep/certificates v0.30.2
go.opentelemetry.io/otel v1.47.0
go.opentelemetry.io/otel/sdk v1.47.0
github.com/go-chi/chi/v5 v5.5.0
github.com/insomniacslk/dhcp v0.0.0-20260719225207-c76316d4aa82
PINS
