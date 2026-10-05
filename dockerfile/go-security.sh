#!/bin/sh
# Обновляем только присутствующие уязвимые зависимости, без go get -u и
# понижения более новых версий upstream. Итоговый бинарник проверяет Trivy.
set -eu
modules=$(go list -m -mod=mod -f '{{.Path}} {{.Version}}' all)
set --
while read -r module fixed; do
    current=$(printf '%s\n' "$modules" | awk -v name="$module" '$1 == name {print $2}')
    [ -n "$current" ] || continue
    oldest=$(printf '%s\n%s\n' "$current" "$fixed" | sort -V | head -1)
    if [ "$oldest" = "$current" ] && [ "$current" != "$fixed" ]; then
        set -- "$@" "$module@$fixed"
    fi
done <<'PINS'
golang.org/x/crypto v0.56.0
golang.org/x/net v0.56.0
golang.org/x/text v0.39.0
golang.org/x/mod v0.40.0
google.golang.org/grpc v1.83.2
github.com/go-jose/go-jose/v3 v3.0.5
github.com/go-jose/go-jose/v4 v4.1.4
github.com/smallstep/certificates v0.30.0
go.opentelemetry.io/otel v1.43.0
go.opentelemetry.io/otel/sdk v1.43.0
PINS
if [ "$#" -gt 0 ]; then
    go get "$@"
fi
