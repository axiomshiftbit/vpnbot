#!/bin/sh
# Runs inside the AdGuard container. The pidfile can belong to a failed
# duplicate launch; trust the live executable instead of killing that PID.
set -eu
umask 077
exec 9>/opt/adguardhome/control.lock
# BusyBox flock has no -w option. Keep lock acquisition bounded as well.
lock_wait=0
until flock -n 9; do
    [ "$lock_wait" -lt 75 ] || exit 1
    sleep 0.2
    lock_wait=$((lock_wait + 1))
done

adguard_pids() {
    for proc in /proc/[0-9]*; do
        if [ "$(readlink "$proc/exe" 2>/dev/null)" = /opt/adguardhome/AdGuardHome ]; then
            printf '%s\n' "${proc##*/}"
        fi
    done
}

case "${1:-}" in
    stop)
        for pid in $(adguard_pids); do
            kill -TERM "$pid" 2>/dev/null || true
        done
        i=0
        while [ -n "$(adguard_pids)" ]; do
            [ "$i" -lt 50 ] || exit 1
            sleep 0.2
            i=$((i + 1))
        done
        rm -f /opt/adguardhome/pid
        printf VPNBOT_AD_STOPPED
        ;;
    start)
        # Only numeric /proc directory names are returned; split them into PIDs.
        # shellcheck disable=SC2046
        set -- $(adguard_pids)
        [ "$#" -le 1 ] || exit 1
        if [ "$#" -eq 1 ]; then
            # A duplicate start must not overwrite the PID with a doomed child.
            printf '%s\n' "$1" > /opt/adguardhome/pid
        else
            # Do not let the daemon inherit the lifecycle lock.
            nohup /opt/adguardhome/AdGuardHome --no-check-update \
                --pidfile /opt/adguardhome/pid -c /config/AdGuardHome.yaml \
                -h 0.0.0.0 -w /opt/adguardhome/work \
                9>&- </dev/null >/proc/1/fd/1 2>&1 &
            pid=$!
            # The binary writes its pidfile before opening the sessions DB.
            # Wait beyond that lock timeout before confirming the launch.
            sleep 1.2
            [ "$(readlink "/proc/$pid/exe" 2>/dev/null)" = /opt/adguardhome/AdGuardHome ] || exit 1
            [ "$(cat /opt/adguardhome/pid 2>/dev/null)" = "$pid" ] || exit 1
        fi
        printf VPNBOT_AD_STARTED
        ;;
    *) exit 2 ;;
esac
