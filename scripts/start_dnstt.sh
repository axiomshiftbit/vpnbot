#!/bin/sh
set -eu
umask 077

id vpnbot >/dev/null 2>&1 || adduser -D -s /bin/false vpnbot
mkdir -p /dnstt /logs
chmod 700 /dnstt

if [ "${1:-}" != "--reload" ]; then
    cat /ssh/key.pub > /root/.ssh/authorized_keys
    ssh-keygen -A
    if [ ! -s /dnstt/ssh_host_ed25519_key ]; then
        ssh-keygen -q -t ed25519 -N '' -f /dnstt/ssh_host_ed25519_key
    fi
    # Исключение только для SSH внутри dnstt-туннеля. MaxSessions=0 запрещает
    # shell/exec/SFTP; остаётся только локальный TCP/SOCKS forward.
    cat /etc/ssh/sshd_config > /tmp/sshd_dnstt.conf
    cat >> /tmp/sshd_dnstt.conf <<'SSH'

HostKey /dnstt/ssh_host_ed25519_key
Match User vpnbot Address 127.0.0.1
    PasswordAuthentication yes
    AuthenticationMethods password
    PubkeyAuthentication no
    AllowTcpForwarding local
    AllowStreamLocalForwarding no
    PermitTTY no
    PermitUserRC no
    MaxSessions 0
SSH
    /usr/sbin/sshd -t -f /tmp/sshd_dnstt.conf

    # DNS нужен самому SSH для разрешения имён. Остальные служебные адреса
    # закрыты даже при SOCKS-запросе с доменом, резолвящимся в частную сеть.
    printf 'nameserver 10.10.0.5\n' > /etc/resolv.conf
    iptables -N DNSTT_USER 2>/dev/null || true
    iptables -F DNSTT_USER
    iptables -A DNSTT_USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    for proto in tcp udp; do
        iptables -A DNSTT_USER -d 10.10.0.5 -p "$proto" --dport 53 -j RETURN
    done
    for net in 0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10; do
        iptables -A DNSTT_USER -d "$net" -j REJECT
    done
    iptables -C OUTPUT -m owner --uid-owner vpnbot -j DNSTT_USER 2>/dev/null || iptables -I OUTPUT -m owner --uid-owner vpnbot -j DNSTT_USER
    ip6tables -N DNSTT_USER 2>/dev/null || true
    ip6tables -F DNSTT_USER
    ip6tables -A DNSTT_USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    for net in ::/128 ::1/128 fc00::/7 fe80::/10; do
        ip6tables -A DNSTT_USER -d "$net" -j REJECT
    done
    ip6tables -C OUTPUT -m owner --uid-owner vpnbot -j DNSTT_USER 2>/dev/null || ip6tables -I OUTPUT -m owner --uid-owner vpnbot -j DNSTT_USER
    /usr/sbin/sshd -D -e -f /tmp/sshd_dnstt.conf &
else
    # Восстановление бэкапа может вернуть прежнюю SSH identity. SIGHUP
    # перечитывает HostKey в master, сохраняя управляющее SSH-соединение.
    /usr/sbin/sshd -t -f /tmp/sshd_dnstt.conf
    if read -r sshd_pid < /var/run/sshd.pid; then
        case "$sshd_pid" in ''|*[!0-9]*) exit 1;; esac
        kill -HUP "$sshd_pid"
    fi
fi

pkill -x dnstt-server || true
# Отзываем уже открытые SSH-сеансы при смене пароля или отключении.
pkill -u vpnbot || true
if [ -s /dnstt/settings.json ] && jq -e '.domain and .password_hash' /dnstt/settings.json >/dev/null; then
    jq -r '"vpnbot:" + .password_hash' /dnstt/settings.json | chpasswd -e
    if [ ! -s /dnstt/server.key ]; then
        dnstt-server -gen-key -privkey-file /dnstt/server.key -pubkey-file /dnstt/server.pub >/dev/null
    fi
    chmod 400 /dnstt/server.key
    domain=$(jq -r '.domain' /dnstt/settings.json)
    nohup dnstt-server -udp :53 -privkey-file /dnstt/server.key "$domain" 127.0.0.1:22 </dev/null >>/logs/dnstt 2>&1 &
else
    # BusyBox passwd -l возвращает 1, если adduser уже заблокировал пароль.
    # С set -e это роняло совершенно новый контейнер без settings.json.
    printf 'vpnbot:!\n' | chpasswd -e
fi
echo dnstt-ready
[ "${1:-}" = "--reload" ] || exec tail -f /dev/null
