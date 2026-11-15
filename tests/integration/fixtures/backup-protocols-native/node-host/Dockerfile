FROM debian:trixie
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    systemd systemd-sysv docker.io docker-cli sudo openssh-server python3 git nftables iproute2 ca-certificates openssl procps conntrack \
    && rm -rf /var/lib/apt/lists/* && systemctl mask getty@tty1.service >/dev/null
COPY start /usr/local/sbin/node-test-init
RUN chmod 755 /usr/local/sbin/node-test-init
CMD ["/usr/local/sbin/node-test-init"]
