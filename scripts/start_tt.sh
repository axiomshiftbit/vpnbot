cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
exec /usr/sbin/sshd -D -e "$@" &
CFG=/trusttunnel_endpoint
[ -f "$CFG/vpn.toml" ] && [ -f "$CFG/hosts.toml" ] && [ -f "$CFG/credentials.toml" ] && [ -f "$CFG/rules.toml" ] \
    && cd "$CFG" \
    && trusttunnel_endpoint vpn.toml hosts.toml >>/logs/trusttunnel.log 2>&1 &
tail -f /dev/null
