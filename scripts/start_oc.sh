INTERFACE=$(route | grep '^default' | grep -o '[^ ]*$')
cat /ssh/key.pub > /root/.ssh/authorized_keys
ssh-keygen -A
exec /usr/sbin/sshd -D -e "$@" &
iptables -t nat -A POSTROUTING --destination 10.10.0.5 -j ACCEPT
iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
mkdir -p /logs
[ -f /logs/ocserv.log ] || : > /logs/ocserv.log
ocserv -f -c /etc/ocserv/ocserv.conf >>/logs/ocserv.log 2>&1 &
tail -f /dev/null
