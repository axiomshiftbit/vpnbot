#!/bin/sh
set -eu
mkdir -p /run/sshd
/usr/sbin/sshd -D -e -f /ssh/ng_sshd_config &
exec nginx -g 'daemon off;'
