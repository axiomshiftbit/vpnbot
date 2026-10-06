#!/bin/sh
# Запускается только CI в одноразовом образе AdGuard без сети и host mounts.
set -eu
[ "${VPNBOT_IMAGE_TEST:-}" = 1 ]
[ -f /entrypoint-under-test.sh ]
[ ! -s /root/.ssh/authorized_keys ]

mkdir -p /tmp/route-test/bin /root/.ssh /ssh
printf 'test-public-key\n' > /ssh/key.pub
# Проверяем настоящий entrypoint; демоны в этом тесте не запускаются.
for path in /usr/sbin/sshd /opt/adguardhome/AdGuardHome \
    /tmp/route-test/bin/ssh-keygen /tmp/route-test/bin/tail; do
    printf '#!/bin/sh\nexit 0\n' > "$path"
    chmod +x "$path"
done
cat > /tmp/route-test/bin/getent <<'SH'
#!/bin/sh
case "$2" in
    wg) printf '10.10.0.4 wg\n' ;;
    wg1) printf '10.10.0.14 wg1\n' ;;
    oc) [ -n "$TEST_OC_IP" ] && printf '%s oc\n' "$TEST_OC_IP" ;;
    *) exit 2 ;;
esac
SH
cat > /tmp/route-test/bin/ip <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> /tmp/route-test/routes
SH
chmod +x /tmp/route-test/bin/getent /tmp/route-test/bin/ip
export PATH="/tmp/route-test/bin:$PATH"

for TEST_OC_IP in '' '10.10.0.23'; do
    export TEST_OC_IP
    : > /tmp/route-test/routes
    sh /entrypoint-under-test.sh
    grep -qx 'route replace 10.0.1.0/24 via 10.10.0.4' /tmp/route-test/routes
    grep -qx 'route replace 10.0.3.0/24 via 10.10.0.14' /tmp/route-test/routes
    grep -qx "route replace 10.0.2.0/24 via ${TEST_OC_IP:-10.10.0.11}" /tmp/route-test/routes
    [ "$(wc -l < /tmp/route-test/routes)" -eq 3 ]
    printf 'PASS AdGuard routes: OpenConnect %s\n' "${TEST_OC_IP:-not yet running}"
done
