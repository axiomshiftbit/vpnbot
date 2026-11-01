#!/usr/bin/env bash
# Reports stay on the runner. Only a pass/fail status enters Actions artifacts.
set -euo pipefail
image=$1
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 -o "$work/trivy.tar.gz" https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-64bit.tar.gz
echo "c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0  $work/trivy.tar.gz" | sha256sum -c -
tar -xzf "$work/trivy.tar.gz" -C "$work" trivy
export TRIVY_CACHE_DIR="$work/cache"
retry=$(dirname "$0")/ci_retry.sh
sh "$retry" "$work/trivy" image --download-db-only --no-progress
# A cached/stale or incomplete DB must not silently admit a release.
python3 - "$work/cache/db/metadata.json" <<'PY'
import datetime,json,sys
d=json.load(open(sys.argv[1]))
now=datetime.datetime.now(datetime.timezone.utc)
updated=datetime.datetime.fromisoformat(d['UpdatedAt'].replace('Z','+00:00'))
assert datetime.timedelta(0) <= now-updated <= datetime.timedelta(hours=48), 'stale vulnerability DB'
assert d['Version']==2, 'unknown vulnerability DB schema'
PY
# Находки не меняют код возврата Trivy (их разбирает проверка ниже), поэтому
# повтор касается только сбоя загрузки образа из реестра.
sh "$retry" "$work/trivy" image --skip-db-update --no-progress --scanners vuln,secret \
    --pkg-types os,library --format json --output "$work/result.json" "$image"
python3 "$(dirname "$0")/ci_scan_gate.py" "$work/result.json"
