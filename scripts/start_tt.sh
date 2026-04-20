cat /ssh/key.pub > /root/.ssh/authorized_keys 2>/dev/null || true
ssh-keygen -A >/dev/null 2>&1 || true
/usr/sbin/sshd -D -e "$@" &

# /logs — bind-mount с хоста; создаём каталог и pre-touch лог, чтобы
# просмотр журнала в боте не падал на ENOENT, если конфиги TT ещё
# не разложены и демон не стартовал.
mkdir -p /logs
[ -f /logs/trusttunnel.log ] || : > /logs/trusttunnel.log

CFG=/trusttunnel_endpoint
[ -f "$CFG/vpn.toml" ] && [ -f "$CFG/hosts.toml" ] && [ -f "$CFG/credentials.toml" ] && [ -f "$CFG/rules.toml" ] \
    && cd "$CFG" \
    && trusttunnel_endpoint vpn.toml hosts.toml >>/logs/trusttunnel.log 2>&1 &
tail -f /dev/null
