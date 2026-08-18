#!/bin/sh
set -eu

# Удаляет OpenVPN-клиента и чинит состояние, которое оставлял старый overlay-
# restore: active cert вернулся из бэкапа, а его идентичные revoked-файлы
# остались от более нового состояния. Bot держит общий PKI-lock; при ручном
# запуске скрипт берёт его сам.

revoke_user="${1:-}"
revoke_pki="${VPNBOT_OVPN_PKI:-/etc/openvpn/pki}"
revoke_log="${VPNBOT_OVPN_LOG:-/logs/openvpn.log}"
revoke_lock="${VPNBOT_OVPN_LOCK:-/logs/.lock.ovpn-pki}"
revoke_ok='no'
revoke_tmp=''

exec 3>>"$revoke_log"

revoke_log_msg()
{
    printf '[revoke_ovpn_client %s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&3
}

revoke_fail()
{
    revoke_log_msg "FAILED user=$revoke_user: $*"
    exit 1
}

revoke_finish()
{
    [ -z "$revoke_tmp" ] || rm -f "$revoke_tmp"
    if [ "$revoke_ok" != yes ]; then
        echo '__VPNBOT_REVOKE_FAILED__'
    fi
}
trap revoke_finish EXIT HUP INT TERM

case "$revoke_user" in
    ''|server|*[!a-zA-Z0-9_.-]*) revoke_fail 'invalid client name' ;;
esac

if [ "${VPNBOT_OVPN_LOCK_HELD:-0}" != 1 ]; then
    exec 8>"$revoke_lock"
    flock -x 8 || revoke_fail 'cannot acquire PKI lock'
fi

revoke_cert="$revoke_pki/issued/$revoke_user.crt"
revoke_key="$revoke_pki/private/$revoke_user.key"
revoke_req="$revoke_pki/reqs/$revoke_user.req"
[ -f "$revoke_cert" ] || revoke_fail 'issued certificate is absent'

revoke_serial="$(openssl x509 -in "$revoke_cert" -noout -serial 2>&3 | sed 's/^serial=//' | tr '[:lower:]' '[:upper:]')"
case "$revoke_serial" in
    ''|*[!0-9A-F]*) revoke_fail 'invalid certificate serial' ;;
esac

revoke_subject="$(openssl x509 -in "$revoke_cert" -noout -subject -nameopt RFC2253 2>&3 | sed 's/^subject= *//')"
[ "$revoke_subject" = "CN=$revoke_user" ] || revoke_fail 'certificate CN does not match client name'
openssl verify -no_check_time -CAfile "$revoke_pki/ca.crt" "$revoke_cert" >&3 2>&1 \
    || revoke_fail 'certificate is not signed by this CA'

revoke_status="$(awk -F '\t' -v wanted="$revoke_serial" '
    toupper($4) == wanted { count++; status=$1 }
    END {
        if (count == 1) print status
        else if (count > 1) print "MULTI"
    }
' "$revoke_pki/index.txt")"
[ "$revoke_status" != 'MULTI' ] || revoke_fail 'duplicate serial entries in index.txt'

if [ -z "$revoke_status" ]; then
    # EasyRSA не может revoke сертификат без строки index.txt. Восстанавливаем
    # только точную V-запись из проверенного сертификата текущего CA.
    revoke_expiry_iso="$(openssl x509 -in "$revoke_cert" -noout -enddate -dateopt iso_8601 2>&3 | sed 's/^notAfter=//')"
    revoke_expiry="$(printf '%s\n' "$revoke_expiry_iso" | sed -n 's/^20\([0-9][0-9]\)-\([0-9][0-9]\)-\([0-9][0-9]\) \([0-9][0-9]\):\([0-9][0-9]\):\([0-9][0-9]\)Z$/\1\2\3\4\5\6Z/p')"
    [ -n "$revoke_expiry" ] || revoke_fail 'cannot convert certificate expiry for index.txt'
    printf 'V\t%s\t\t%s\tunknown\t/CN=%s\n' \
        "$revoke_expiry" "$revoke_serial" "$revoke_user" >> "$revoke_pki/index.txt"
    revoke_status='V'
    revoke_log_msg "reconstructed missing index entry user=$revoke_user serial=$revoke_serial"
fi

revoke_dst_cert="$revoke_pki/revoked/certs_by_serial/$revoke_serial.crt"
revoke_dst_key="$revoke_pki/revoked/private_by_serial/$revoke_serial.key"
revoke_dst_req="$revoke_pki/revoked/reqs_by_serial/$revoke_serial.req"

revoke_require_same()
{
    revoke_src="$1"
    revoke_dst="$2"
    if [ -e "$revoke_dst" ]; then
        [ -e "$revoke_src" ] && cmp -s "$revoke_src" "$revoke_dst" \
            || revoke_fail "conflicting revoked artifact: $revoke_dst"
    fi
}

revoke_require_same "$revoke_cert" "$revoke_dst_cert"
revoke_require_same "$revoke_key" "$revoke_dst_key"
revoke_require_same "$revoke_req" "$revoke_dst_req"

if [ "$revoke_status" = 'R' ]; then
    # Сертификат уже отозван по индексу. Сохраняем его revoked-артефакты,
    # пересобираем CRL и лишь после проверки убираем воскресшие active-копии.
    mkdir -p "$(dirname "$revoke_dst_cert")" "$(dirname "$revoke_dst_key")" "$(dirname "$revoke_dst_req")"
    [ -e "$revoke_dst_cert" ] || cp -p "$revoke_cert" "$revoke_dst_cert"
    [ ! -e "$revoke_key" ] || [ -e "$revoke_dst_key" ] || cp -p "$revoke_key" "$revoke_dst_key"
    [ ! -e "$revoke_req" ] || [ -e "$revoke_dst_req" ] || cp -p "$revoke_req" "$revoke_dst_req"
elif [ "$revoke_status" = 'V' ] || [ "$revoke_status" = 'E' ]; then
    # Удаляем только доказанно идентичные stale-копии. Оригиналы остаются в
    # active-каталогах, и EasyRSA сейчас же перенесёт их обратно в revoked/.
    [ ! -e "$revoke_dst_cert" ] || rm -f "$revoke_dst_cert"
    [ ! -e "$revoke_dst_key" ] || rm -f "$revoke_dst_key"
    [ ! -e "$revoke_dst_req" ] || rm -f "$revoke_dst_req"
    EASYRSA_PKI="$revoke_pki" EASYRSA_BATCH=1 \
        /usr/share/easy-rsa/easyrsa revoke "$revoke_user" >&3 2>&1 \
        || revoke_fail 'easyrsa revoke failed'
else
    revoke_fail "unsupported index status: $revoke_status"
fi

EASYRSA_PKI="$revoke_pki" EASYRSA_BATCH=1 EASYRSA_CRL_DAYS=3650 \
    /usr/share/easy-rsa/easyrsa gen-crl >&3 2>&1 \
    || revoke_fail 'easyrsa gen-crl failed'

revoke_tmp="$(mktemp)"
openssl crl -in "$revoke_pki/crl.pem" -noout -text >"$revoke_tmp" 2>&3 \
    || revoke_fail 'cannot read generated CRL'
grep -Fqi "Serial Number: $revoke_serial" "$revoke_tmp" \
    || revoke_fail 'certificate serial is absent from generated CRL'

if [ "$revoke_status" = 'R' ]; then
    rm -f "$revoke_cert" "$revoke_key" "$revoke_req"
fi
[ ! -e "$revoke_cert" ] || revoke_fail 'issued certificate still exists after revoke'

revoke_log_msg "OK user=$revoke_user serial=$revoke_serial"
revoke_ok='yes'
echo '__VPNBOT_REVOKED__'
exit 0
