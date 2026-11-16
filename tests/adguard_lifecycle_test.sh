#!/bin/sh
# Real core, synthetic data, isolated disposable container only.
set -eu
[ "${VPNBOT_IMAGE_TEST:-}" = 1 ]
[ -f /control-under-test.sh ]
[ ! -e /config/AdGuardHome.yaml ]
mkdir -p /config /opt/adguardhome/work
cat > /config/AdGuardHome.yaml <<'YAML'
schema_version: 34
http:
  address: 127.0.0.1:80
users: []
dns:
  bind_hosts: [127.0.0.1]
  port: 53
  upstream_dns: [127.0.0.1:59999]
filtering:
  protection_enabled: true
  filtering_enabled: true
  rewrites:
    - domain: probe.example.test
      answer: 198.51.100.123
      enabled: true
YAML
# The supervisor record (PID + start time) is the source of truth; AdGuard's
# own --pidfile is only a hint that a duplicate start can overwrite.
core_pid() { read -r pid start < /run/vpnbot-services/adguard/pid && printf '%s' "$pid"; }
check_pid() {
    test "$(readlink "/proc/$(core_pid)/exe")" = /opt/adguardhome/AdGuardHome
}
control() { sh /control-under-test.sh "$1" >/dev/null; }
live_count() {
    count=0
    for proc in /proc/[0-9]*; do
        if [ "$(readlink "$proc/exe" 2>/dev/null)" = /opt/adguardhome/AdGuardHome ]; then
            count=$((count + 1))
        fi
    done
    printf '%s' "$count"
}
check_dns() {
    wget -q -O /dev/null http://127.0.0.1/control/status
    nslookup -type=A probe.example.test 127.0.0.1 2>/dev/null | grep -q '198.51.100.123'
}

# As start_ad.sh: the supervisor (guardian) owns the core and serves control.
[ -f /service_supervisor.sh ] && [ -f /service_daemon.sh ]
/bin/sh /service_supervisor.sh supervise ad >/tmp/supervisor.log 2>&1 &
guardian_wait=0
until [ -s /run/vpnbot-services/guardian ] || [ "$guardian_wait" -ge 50 ]; do
    sleep .2; guardian_wait=$((guardian_wait + 1))
done
control start
check_pid
check_dns
original_pid=$(core_pid)
control start
[ "$(core_pid)" = "$original_pid" ]
[ "$(live_count)" = 1 ]
printf 'PASS start is idempotent; DNS and HTTP respond\n'

# Reproduce the production failure: a failed duplicate replaces the pidfile.
if /opt/adguardhome/AdGuardHome --no-check-update --pidfile /opt/adguardhome/pid \
    -c /config/AdGuardHome.yaml -h 0.0.0.0 -w /opt/adguardhome/work >/tmp/duplicate.log 2>&1; then
    echo 'FAIL duplicate unexpectedly started'; exit 1
fi
if [ "$(readlink "/proc/$(cat /opt/adguardhome/pid)/exe" 2>/dev/null)" = /opt/adguardhome/AdGuardHome ]; then
    echo 'FAIL stale pidfile was not reproduced'; exit 1
fi
check_dns
control start
check_pid
[ "$(core_pid)" = "$original_pid" ]
[ "$(live_count)" = 1 ]
printf 'PASS failed duplicate reproduced; the running core and DNS are kept\n'

# A stale PID may have been reused by an unrelated process: never signal it.
sleep 60 & unrelated=$!
printf '%s\n' "$unrelated" > /opt/adguardhome/pid
control stop
[ "$(live_count)" = 0 ]
kill -0 "$unrelated"
kill "$unrelated"
wait "$unrelated" 2>/dev/null || true
control stop
printf 'PASS stale PID never kills another process; repeated stop succeeds\n'

# Concurrent starts must share a lock and keep exactly one live core.
pids=''
for iteration in 1 2 3 4; do
    control start & pids="$pids $!"
    printf 'Starting concurrent request %s\n' "$iteration"
done
for pid in $pids; do wait "$pid"; done
[ "$(live_count)" = 1 ]
check_pid
check_dns
printf 'PASS four concurrent starts keep one core\n'

# Delayed SIGTERM handling deterministically exposes the old stop/start race.
pid=$(core_pid)
kill -STOP "$pid"
(sleep 1; kill -CONT "$pid") & resume=$!
control stop
wait "$resume"
[ ! -e "/proc/$pid/exe" ]
[ "$(live_count)" = 0 ]
control start
check_pid
check_dns
printf 'PASS stop waits for a delayed shutdown before restart\n'

for iteration in 1 2 3 4 5; do
    control stop
    [ "$(live_count)" = 0 ]
    control start
    check_pid
    check_dns
    printf 'PASS restart %s\n' "$iteration"
done
printf 'PASS five consecutive restore-style restarts\n'
control stop
printf 'invalid: [\n' > /config/AdGuardHome.yaml
if control start; then echo 'FAIL invalid config accepted'; exit 1; fi
[ "$(live_count)" = 0 ]
printf 'PASS invalid config is reported as a failed start\n'
