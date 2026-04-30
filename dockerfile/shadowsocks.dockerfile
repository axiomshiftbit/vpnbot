ARG image
FROM $image
RUN apk add openssh git xz jq \
    && mkdir /root/.ssh \
    && wget -O shadowsocks-rust.x86_64-unknown-linux-musl.tar.xz $(wget -q -O - https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest | grep browser_download_url | cut -d\" -f4 | egrep '.x86_64-unknown-linux-musl.tar.xz$') \
    && tar -xf shadowsocks-rust.x86_64-unknown-linux-musl.tar.xz \
    && wget -O v2ray-plugin-linux-amd64.tar.gz $(wget -q -O - https://api.github.com/repos/teddysun/v2ray-plugin/releases/latest | grep browser_download_url | cut -d\" -f4 | egrep 'v2ray-plugin-linux-amd64') \
    && tar -xf v2ray-plugin-linux-amd64.tar.gz \
    && wget -O /usr/bin/ck-server $(wget -q -O - https://api.github.com/repos/cbeuw/Cloak/releases/latest | grep browser_download_url | cut -d\" -f4 | egrep 'ck-server-linux-amd64') \
    && wget -O /usr/bin/ck-client $(wget -q -O - https://api.github.com/repos/cbeuw/Cloak/releases/latest | grep browser_download_url | cut -d\" -f4 | egrep 'ck-client-linux-amd64') \
    && chmod +x /usr/bin/ck-server /usr/bin/ck-client \
    && mv sslocal /usr/bin/ \
    && mv ssserver /usr/bin/ \
    && mv ssmanager /usr/bin/ \
    && mv ssservice /usr/bin/ \
    && mv ssurl /usr/bin/ \
    && mv v2ray-plugin_linux_amd64 /usr/bin/v2ray-plugin \
    && rm v2ray-plugin-linux-amd64.tar.gz \
    && rm shadowsocks-rust.x86_64-unknown-linux-musl.tar.xz
ENV ENV="/root/.ashrc"
