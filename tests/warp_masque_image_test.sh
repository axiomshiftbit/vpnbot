#!/bin/sh
# Проверка образа wg: режим WARP через MASQUE обязан в нём работать.
# Запускается сборкой (images.yml) внутри только что собранного образа, без
# сети: скрипты репозитория подключены в /scripts. Cloudflare не нужен —
# устройство синтетическое, проверяется всё, что зависит от самого образа:
# программы, ядро прокси и то, что оно принимает собранный конфиг.
set -eu

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export WARP_MASQUE_DIR="$tmp/masque" WARP_PAC="$tmp/pac.json" WARP_RUN_DIR="$tmp/run"
mkdir -p "$WARP_MASQUE_DIR" "$WARP_RUN_DIR"
echo '{}' > "$WARP_PAC"
masque() { sh /scripts/warp_masque.sh "$@"; }
ok() { echo "ok: $1"; }

# Оболочка образа разбирает скрипты режима.
sh -n /scripts/start_wp.sh
sh -n /scripts/warp_masque.sh
sh -n /scripts/warp_probe.sh
ok 'scripts parse'

[ "$(masque supported)" = ok ]
ok "image has every tool and core $(warp-socks version | awk 'NR == 1 { print $2 }')"

# Без устройства режим честно говорит, что его нет.
! masque exists
! masque endpoint >/dev/null 2>&1
! masque config 1080 >/dev/null 2>&1
[ "$(masque status)" = '{}' ]
ok 'no account: nothing is invented'

# Синтетическое устройство тем же способом, что и настоящая регистрация.
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/sec1.pem"
openssl pkcs8 -topk8 -nocrypt -in "$tmp/sec1.pem" -out "$WARP_MASQUE_DIR/key.pem"
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/endpoint.pem"
openssl pkey -in "$tmp/endpoint.pem" -pubout -out "$tmp/endpoint.pub.pem"
jq -n --rawfile public "$tmp/endpoint.pub.pem" '{
    id: "image-test-device", endpoint_v4: "162.159.198.2:0", endpoint_v6: "", endpoint_public_key: $public,
    address_v4: "172.16.0.2", address_v6: "", account_type: "free", warp_plus: false, registered: 0
}' > "$WARP_MASQUE_DIR/device.json"
printf '%s' '' | sha256sum | cut -c1-64 > "$WARP_MASQUE_DIR/license.sha256"
masque exists
masque current
[ "$(masque endpoint)" = 162.159.198.2 ]
ok 'account is read'

# Ядро образа принимает оба транспорта и конфиг пробного подключения.
for alpn in h3 h2; do
    masque config 1080 "$alpn" > "$tmp/$alpn.json"
    warp-socks run -test -config "$tmp/$alpn.json" 2>&1 | grep -q 'Configuration OK'
    [ "$(jq -r '.outbounds | length' "$tmp/$alpn.json")" = 1 ]
    [ "$(jq -r '.outbounds[0].protocol' "$tmp/$alpn.json")" = masque ]
done
[ "$(jq -c '.outbounds[0].streamSettings.tlsSettings.alpn' "$tmp/h2.json")" = '["h2"]' ]
[ "$(jq -c '.outbounds[0].streamSettings.tlsSettings.alpn' "$tmp/h3.json")" = null ]
masque config 1081 h3 51820 127.0.0.1 > "$tmp/check.json"
warp-socks run -test -config "$tmp/check.json" 2>&1 | grep -q 'Configuration OK'
[ "$(jq -r '.outbounds[0].streamSettings.sockopt.mark' "$tmp/check.json")" = 51820 ]
ok 'core accepts HTTP/3, HTTP/2 and the trial-connection config'

# Проверка ядром не пустая: испорченный ключ и чужой метод оно отвергает.
jq '.outbounds[0].streamSettings.masqueSettings.warp.privateKey = "garbage"' "$tmp/h3.json" > "$tmp/badkey.json"
! warp-socks run -test -config "$tmp/badkey.json" >/dev/null 2>&1
jq '.outbounds[0].streamSettings.masqueSettings.warp.publicKey = "garbage"' "$tmp/h3.json" > "$tmp/badpublic.json"
! warp-socks run -test -config "$tmp/badpublic.json" >/dev/null 2>&1
jq 'del(.outbounds[0].streamSettings.security)' "$tmp/h3.json" > "$tmp/notls.json"
! warp-socks run -test -config "$tmp/notls.json" >/dev/null 2>&1
ok 'core rejects a damaged key, a damaged endpoint key and a config without TLS'

# Прокси работает под отдельным пользователем и обязан прочитать конфиг,
# закрытый от остальных (640, root:warp-proxy), — как его кладёт start_wp.sh.
id warp-proxy >/dev/null 2>&1 || adduser -D -H -s /sbin/nologin warp-proxy
chmod 755 "$tmp"
cp "$tmp/h3.json" "$tmp/proxy.json"
chown root:warp-proxy "$tmp/proxy.json"
chmod 640 "$tmp/proxy.json"
su -s /bin/sh -c "exec warp-socks run -test -config $tmp/proxy.json" warp-proxy 2>&1 | grep -q 'Configuration OK'
id nobody >/dev/null 2>&1 && ! su -s /bin/sh -c "cat $tmp/proxy.json" nobody >/dev/null 2>&1
ok 'the proxy user reads the private config, others do not'

echo 'warp masque image test OK'
