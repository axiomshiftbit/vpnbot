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
google.golang.org/grpc v1.83.2
golang.org/x/crypto v0.56.0
golang.org/x/net v0.60.0
golang.org/x/text v0.39.0
golang.org/x/mod v0.40.0
github.com/klauspost/compress v1.18.7
golang.org/x/crypto/x509roots/fallback v0.0.0-20261020153306-9f2b28d4331a
github.com/go-jose/go-jose/v3 v3.0.5
github.com/go-jose/go-jose/v4 v4.1.6
github.com/smallstep/certificates v0.30.0
go.opentelemetry.io/otel v1.43.0
go.opentelemetry.io/otel/sdk v1.43.0
github.com/go-chi/chi/v5 v5.4.0
PINS
