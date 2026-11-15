#!/bin/sh
set -eu
umask 077
case "${1:-}" in
    start) action=start; expected=VPNBOT_SERVICE_READY:adguard; marker=VPNBOT_AD_STARTED;;
    stop) action=stop; expected=VPNBOT_SERVICE_STOPPED:adguard; marker=VPNBOT_AD_STOPPED;;
    *) exit 2;;
esac
result=$(/bin/sh /service_supervisor.sh "$action" adguard) || exit 1
[ "$result" = "$expected" ] || exit 1
printf '%s\n' "$marker"
