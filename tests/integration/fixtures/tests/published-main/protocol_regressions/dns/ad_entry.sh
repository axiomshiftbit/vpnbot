#!/bin/sh
set -eu
mkdir -p /run/sshd
/usr/sbin/sshd -D -e -f /ssh/ad_sshd_config &
exec /bin/sh /service_supervisor.sh supervise ad
