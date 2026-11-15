#!/bin/sh
# Адаптеры сохраняют пути и custom configs; запускаются только supervisor.
set -eu
umask 077
action=${1:-}
name=${2:-}
case "$name" in
    adguard) executable=/opt/adguardhome/AdGuardHome; log=/logs/adguard;;
    ssserver|sslocal|ck-server|simple-tls) executable=/usr/bin/$name; log=/logs/$name.log;;
    naive) executable=/usr/local/bin/caddy; log=/logs/caddy;;
    trusttunnel) executable=/usr/local/libexec/trusttunnel_endpoint; log=/logs/trusttunnel.log;;
    dnstt) executable=/usr/local/bin/dnstt-server; log=/logs/dnstt;;
    *) exit 2;;
esac
[ "$name" != ssserver ] || log=/logs/shadowsocks
[ "$name" != sslocal ] || log=/logs/shadowsocks_proxy
if [ "$action" = executable ]; then printf '%s\n' "$executable"; exit 0; fi

ports() {
    case "$name" in
        ssserver)
            jq -r '(.mode // "tcp_only") as $m | .server_port as $p |
                (if $m != "udp_only" then "tcp:\($p)" else empty end),
                (if $m != "tcp_only" then "udp:\($p)" else empty end)' /config.json;;
        sslocal)
            jq -r '(.mode // "tcp_only") as $default | ([.] + (.locals // []))[] |
                select(.local_port != null) | (.mode // $default) as $m | .local_port as $p |
                (if $m != "udp_only" then "tcp:\($p)" else empty end),
                (if $m != "tcp_only" then "udp:\($p)" else empty end)' /config.json;;
        ck-server)
            jq -r '.BindAddr[] | "tcp:" + (split(":")[-1])' /config/ckserver.json;;
        simple-tls) printf 'tcp:%s\n' "${STLSPORT:-3443}";;
        dnstt) echo udp:53;;
        trusttunnel)
            # Только корневое literal поле listen_address; metrics не участвует.
            awk '/^[[:space:]]*\[/ {section=1}
                !section && /^[[:space:]]*listen_address[[:space:]]*=/ {
                    value=$0; sub(/^[^=]*=[[:space:]]*/,"",value)
                    quote=substr(value,1,1)
                    if (quote != "\"" && quote != "\047") exit 1
                    value=substr(value,2); end=index(value,quote); if (!end) exit 1
                    value=substr(value,1,end-1); sub(/^.*:/,"",value)
                    print "tcp:" value; count++
                } END {if(count!=1) exit 1}' /trusttunnel_endpoint/vpn.toml;;
        naive)
            # Caddy сам разбирает imports/адреса/глобальные options. Из его
            # канонического JSON берём только HTTP listen arrays, не admin.
            "$executable" adapt --config /config/Caddyfile --adapter caddyfile --pretty 2>/dev/null |
                awk '/"listen"[[:space:]]*:[[:space:]]*\[/ {inside=1; next}
                    inside && /\]/ {inside=0; next}
                    inside {value=$0; gsub(/[[:space:]",]/,"",value); sub(/^.*:/,"",value);
                        print "tcp:" value; count++}
                    END {if(!count) exit 1}';;
        adguard)
            # AGH хранит dns.port и tls.port_* в этих корневых секциях.
            # Не печатаем пользователей, passwords, upstreams или другие поля.
            awk '
                /^[^[:space:]#]/ {section=""}
                /^dns:[[:space:]]*(#.*)?$/ {section="dns"; next}
                /^tls:[[:space:]]*(#.*)?$/ {section="tls"; next}
                section=="dns" && /^[[:space:]]+port:/ {v=$0;sub(/^[^:]*:[[:space:]]*/,"",v);sub(/[[:space:]]*#.*/,"",v);gsub(/[[:space:]"\047]/,"",v);dns=v}
                section=="tls" && /^[[:space:]]+enabled:/ {v=$0;sub(/^[^:]*:[[:space:]]*/,"",v);sub(/[[:space:]]*#.*/,"",v);enabled=v}
                section=="tls" && /^[[:space:]]+port_(https|dns_over_tls|dns_over_quic):/ {
                    key=$1;v=$0;sub(/^[^:]*:[[:space:]]*/,"",v);sub(/[[:space:]]*#.*/,"",v);gsub(/[[:space:]"\047]/,"",v)
                    tls[key]=v
                }
                END {
                    if(dns=="") dns=53
                    if(dns!="0") {print "tcp:" dns; print "udp:" dns}
                    if(enabled=="true") for(key in tls) if(tls[key]+0>0)
                        print (key=="port_dns_over_quic:"?"udp:":"tcp:") tls[key]
                }' /config/AdGuardHome.yaml;;
    esac
}
if [ "$action" = ports ]; then ports; exit $?; fi

enabled() {
    case "$name" in
        adguard) [ -s /config/AdGuardHome.yaml ];;
        ssserver|sslocal) [ -s /config.json ];;
        ck-server) [ -s /config/ckserver.json ] && [ "$(jq -r '.Enabled // 0' /config/ckserver.json)" = 1 ];;
        simple-tls) [ -s /config/stlsserver.json ] && [ "$(jq -r '.Enabled // 0' /config/stlsserver.json)" = 1 ];;
        naive)
            [ -s /config/Caddyfile ] && ! grep -qE '^[[:space:]]*basic_auth[[:space:]]+(CHANGEME[[:space:]]+CHANGEME|_[[:space:]]+__)[[:space:]]*$' /config/Caddyfile;;
        trusttunnel)
            for f in vpn.toml hosts.toml credentials.toml rules.toml; do [ -f "/trusttunnel_endpoint/$f" ] || return 1; done
            grep -q '^[[:space:]]*\[\[client\]\]' /trusttunnel_endpoint/credentials.toml && [ -s /certs/cert_public ] && [ -s /certs/cert_private ];;
        dnstt)
            [ -s /dnstt/settings.json ] && jq -e 'if type == "object" then
                (.domain | type == "string") and (.password_hash | type == "string")
                and (.domain != "") and (.password_hash != "") else false end' /dnstt/settings.json >/dev/null;;
    esac
}
if [ "$action" = enabled ]; then enabled; exit $?; fi
if [ "$action" = stopped ]; then
    case "$name" in
        adguard) rm -f /opt/adguardhome/pid;;
        dnstt)
            # Только SSH-сеансы tunnel-user; управляющий root SSH не затронут.
            pkill -u vpnbot || true
            printf 'vpnbot:!\n' | chpasswd -e;;
    esac
    exit 0
fi
[ "$action" = run ] && enabled || exit 1
mkdir -p /logs
exec >>"$log" 2>&1
directory=/run/vpnbot-services/$name
ports > "$directory/ports"
# Проверяем все обязательные порты до exec; пустая/неоднозначная опись — отказ.
awk -F: 'NF!=2 || ($1!="tcp" && $1!="udp") || $2!~/^[0-9]+$/ || $2<1 || $2>65535 {bad=1}
    END {exit bad || NR==0}' "$directory/ports"
if [ "$name" = ssserver ] || [ "$name" = sslocal ]; then
    plugin=$(jq -r '.plugin // empty' /config.json)
    if [ -n "$plugin" ]; then
        plugin=$(command -v "$plugin")
        readlink -f "$plugin" > "$directory/plugin-executable"
    fi
fi
case "$name" in
    adguard)
        exec "$executable" --no-check-update --pidfile /opt/adguardhome/pid -c /config/AdGuardHome.yaml -h 0.0.0.0 -w /opt/adguardhome/work;;
    ssserver|sslocal)
        exec "$executable" -v -c /config.json;;
    ck-server)
        # Производная копия содержит private key и никогда не лежит в /tmp.
        directory=/run/vpnbot-services/ck-server
        temporary=$(mktemp "$directory/config.XXXXXX")
        trap 'rm -f "$temporary"' EXIT HUP INT TERM
        jq 'del(.Enabled) | if (.AdminUID // "") == "" then del(.AdminUID) else . end
            | if (.DatabasePath // "") == "" then del(.DatabasePath) else . end' /config/ckserver.json > "$temporary"
        mv -f "$temporary" "$directory/config.json"
        trap - EXIT HUP INT TERM
        exec "$executable" -c "$directory/config.json";;
    simple-tls)
        if [ -s /certs/cert_public ] && [ -s /certs/cert_private ]; then
            cert=/certs/cert_public; key=/certs/cert_private
        else
            cert=/certs/self_public; key=/certs/self_private
        fi
        exec "$executable" -s -b ":${STLSPORT:-3443}" -d 127.0.0.1:8388 -cert "$cert" -key "$key";;
    naive)
        exec "$executable" run -c /config/Caddyfile;;
    trusttunnel)
        cd /trusttunnel_endpoint
        exec "$executable" vpn.toml hosts.toml;;
    dnstt)
        jq -r '"vpnbot:" + .password_hash' /dnstt/settings.json | chpasswd -e
        if [ ! -s /dnstt/server.key ]; then
            "$executable" -gen-key -privkey-file /dnstt/server.key -pubkey-file /dnstt/server.pub >/dev/null
        fi
        chmod 400 /dnstt/server.key
        domain=$(jq -r '.domain' /dnstt/settings.json)
        exec "$executable" -udp :53 -privkey-file /dnstt/server.key "$domain" 127.0.0.1:22;;
esac
