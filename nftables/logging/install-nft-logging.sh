#!/bin/bash
# Установщик журналов nftables VPNBot (основной бот и минимальная нода).
# Требует работающих rsyslog и cron. Правила firewall не изменяет.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 027

say() { printf '[NFT logging] %s\n' "$*"; }
die() { printf 'Ошибка: %s\n' "$*" >&2; exit 1; }
if [[ $# == 1 && ( $1 == --help || $1 == -h ) ]]; then
    printf 'Использование: sudo bash %s --profile main\n' "$0"
    printf 'Группирует журналы, сохраняет историю, настраивает ротацию и проверяет запись.\n'
    exit 0
fi
[[ $EUID == 0 ]] || die 'запустите скрипт от root'
[[ $# == 2 && $1 == --profile ]] || die 'ожидается --profile main'
nft_profile=$2
[[ $nft_profile == main ]] || die 'неизвестный профиль'
for nft_cmd in rsyslogd logrotate systemctl logger flock stat getent ps nft python3; do
    command -v "$nft_cmd" >/dev/null || die "не найдена команда $nft_cmd"
done
check_dir() {
    [[ ! -L $1 ]] || die "символьная ссылка: $1"
    if [[ -e $1 ]]; then
        [[ -d $1 && $(stat -c %u "$1") == 0 ]] || die "необычный каталог или владелец: $1"
        local nft_mode
        nft_mode=$(stat -c %a "$1")
        (( (8#$nft_mode & 0022) == 0 )) || die "$1 доступен для посторонней записи"
    fi
}
check_file() {
    [[ ! -L $1 ]] || die "символьная ссылка: $1"
    if [[ -e $1 ]]; then
        [[ -f $1 && $(stat -c %h "$1") == 1 ]] || die "необычный файл или жёсткая ссылка: $1"
    fi
}
for nft_dir in /etc/rsyslog.d /etc/logrotate.d /etc/cron.d /var/log /var/backups /run /var/lib/logrotate; do
    [[ -d $nft_dir ]] || die "нет каталога $nft_dir"
    # Защищаем весь путь, включая родителя root-owned каталога журналов.
    # Разрешение группе syslog переименовать nftables/ небезопасно также
    # после установки: logrotate обращается к тем же путям от root.
    nft_parent=$nft_dir
    while :; do
        check_dir "$nft_parent"
        [[ $nft_parent == / ]] && break
        nft_parent=$(dirname -- "$nft_parent")
    done
done
nft_script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
nft_verdict_helper=$nft_script_dir/nft-log-verdicts.py
check_dir "$nft_script_dir"
check_file "$nft_verdict_helper"
[[ -f $nft_verdict_helper && $(stat -c %u "$nft_verdict_helper") == 0 ]] || die 'нет root-owned nft-log-verdicts.py рядом с установщиком'
nft_helper_mode=$(stat -c %a "$nft_verdict_helper")
(( (8#$nft_helper_mode & 0022) == 0 )) || die 'nft-log-verdicts.py доступен для посторонней записи'
check_file /run/nftables-logging-install.lock
exec 9>/run/nftables-logging-install.lock
flock -n 9 || die 'уже выполняется другой экземпляр установки'
# Тот же lock, что у ежедневного logrotate; debug-проверка его не захватывает.
check_file /var/lib/logrotate/status
exec 8<>/var/lib/logrotate/status
flock -w 30 8 || die 'logrotate занят; повторите установку позднее'
systemctl is-active --quiet rsyslog.service || die 'rsyslog.service должен быть запущен'
if ! systemctl is-active --quiet cron.service && ! systemctl is-active --quiet crond.service; then
    die 'для почасовой проверки ротации нужен запущенный cron/crond'
fi
nft_pid=$(systemctl show --value -p MainPID rsyslog.service)
[[ $nft_pid =~ ^[1-9][0-9]*$ ]] || die 'не удалось определить PID rsyslog'
SYSLOG_USER=$(ps -o euser= -p "$nft_pid" | tr -d ' ')
SYSLOG_GROUP=$(ps -o egroup= -p "$nft_pid" | tr -d ' ')
[[ $SYSLOG_USER =~ ^[a-zA-Z0-9_-]+$ && $SYSLOG_GROUP =~ ^[a-zA-Z0-9_-]+$ ]] || die 'не удалось определить владельца журналов'
if [[ $SYSLOG_USER == root ]] && getent group adm >/dev/null; then SYSLOG_GROUP=adm; fi

LOGS_DIR=/var/log/nftables
for nft_dir in "$LOGS_DIR" "$LOGS_DIR/archive" "$LOGS_DIR/legacy"; do check_dir "$nft_dir"; done
NFT_TARGETS=(/etc/rsyslog.d/10-nftables.conf /etc/logrotate.d/nftables /etc/cron.d/nftables-log-cleanup "$LOGS_DIR/README_RU.txt")
NFT_LOGS=(rkn-blacklist.log host.log vpn.log docker.log network.log security.log other.log service.log)
for nft_file in "${NFT_TARGETS[@]}"; do check_file "$nft_file"; done
shopt -s nullglob
NFT_OLD_FILES=()
for nft_file in "$LOGS_DIR/"*.log "$LOGS_DIR/"*.log.* "$LOGS_DIR/"*.log-*; do
    check_file "$nft_file"
    nft_active=0
    for nft_log in "${NFT_LOGS[@]}"; do
        if [[ $nft_file == "$LOGS_DIR/$nft_log" ]]; then nft_active=1; break; fi
    done
    if (( ! nft_active )); then NFT_OLD_FILES+=("$nft_file"); fi
done
for nft_log in "${NFT_LOGS[@]}"; do check_file "$LOGS_DIR/$nft_log"; done

nft_backup=$(mktemp -d /var/backups/nftables-logging.XXXXXXXX)
chmod 700 "$nft_backup"
for nft_i in "${!NFT_TARGETS[@]}"; do
    if [[ -e ${NFT_TARGETS[nft_i]} ]]; then cp -p "${NFT_TARGETS[nft_i]}" "$nft_backup/before-$nft_i"; fi
done
nft_changed=0
nft_restart_attempted=0
nft_legacy=''
NFT_TMPFILES=()
NFT_MOVED=()
NFT_RECOVER_FDS=()
NFT_RECOVER_PATHS=()
atomic_install() {
    local nft_tmp
    nft_tmp=$(mktemp "$(dirname "$2")/.nftables-install.XXXXXXXX")
    NFT_TMPFILES+=("$nft_tmp")
    install -m 644 -o root -g root "$1" "$nft_tmp"
    mv -fT -- "$nft_tmp" "$2"
}
legacy_dir() {
    if [[ -z $nft_legacy ]]; then
        nft_legacy=$(mktemp -d "$LOGS_DIR/legacy/$(date -u +%Y%m%dT%H%M%SZ).XXXXXXXX")
        chown root:"$SYSLOG_GROUP" "$nft_legacy"
        chmod 750 "$nft_legacy"
    fi
}
recover_tail() {
    local nft_i nft_fd nft_failed=0
    for nft_i in "${!NFT_RECOVER_FDS[@]}"; do
        nft_fd=${NFT_RECOVER_FDS[nft_i]}
        # Смещение FD осталось на конце предварительной копии. Забираем записи,
        # добавленные старым демоном до его штатного завершения.
        cat <&"$nft_fd" >> "${NFT_RECOVER_PATHS[nft_i]}" || nft_failed=1
    done
    return "$nft_failed"
}
cleanup() {
    local nft_rc=$? nft_restore_failed=0 nft_file nft_i nft_tmp
    trap - EXIT HUP INT TERM
    set +e
    if (( nft_rc != 0 && nft_changed )); then
        for nft_file in "${NFT_MOVED[@]}"; do
            if [[ ! -e $LOGS_DIR/$nft_file ]]; then
                mv -T -- "$nft_legacy/$nft_file" "$LOGS_DIR/$nft_file" || nft_restore_failed=1
            else
                nft_restore_failed=1
            fi
        done
        for nft_i in "${!NFT_TARGETS[@]}"; do
            if [[ -f $nft_backup/before-$nft_i ]]; then
                cp -p -- "$nft_backup/before-$nft_i" "${NFT_TARGETS[nft_i]}" || nft_restore_failed=1
            else
                rm -f -- "${NFT_TARGETS[nft_i]}" || nft_restore_failed=1
            fi
        done
        if (( nft_restart_attempted )); then
            systemctl restart rsyslog.service && systemctl is-active --quiet rsyslog.service || nft_restore_failed=1
        fi
        if (( nft_restore_failed )); then
            printf 'Автовосстановление завершилось с ошибкой. Копия: %s\n' "$nft_backup" >&2
        else
            printf 'Прежние настройки восстановлены. Копия: %s\n' "$nft_backup" >&2
        fi
    fi
    if ! recover_tail; then
        printf 'Ошибка сохранения удалённых журналов; проверьте %s/deleted\n' "$nft_legacy" >&2
        nft_rc=1
    fi
    for nft_tmp in "${NFT_TMPFILES[@]}"; do rm -f -- "$nft_tmp"; done
    exit "$nft_rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
say "Профиль: $nft_profile. Проверка каталогов и подготовка ${#NFT_LOGS[@]} журналов."
for nft_dir in "$LOGS_DIR" "$LOGS_DIR/archive" "$LOGS_DIR/legacy"; do
    install -d -m 750 -o root -g "$SYSLOG_GROUP" "$nft_dir"
    [[ $(stat -c %d "$nft_dir") == "$(stat -c %d "$LOGS_DIR")" ]] || die 'archive и legacy должны быть на том же разделе, что журналы'
done
for nft_log in "${NFT_LOGS[@]}"; do
    if [[ ! -e $LOGS_DIR/$nft_log ]]; then
        install -m 640 -o "$SYSLOG_USER" -g "$SYSLOG_GROUP" /dev/null "$LOGS_DIR/$nft_log"
    else
        chown "$SYSLOG_USER:$SYSLOG_GROUP" "$LOGS_DIR/$nft_log"
        chmod 640 "$LOGS_DIR/$nft_log"
    fi
done

# Восстанавливаем удалённые, но ещё открытые rsyslog файлы до перезапуска.
# Собственные FD удерживают inode; содержимое никогда не выводится на экран.
declare -A NFT_RECOVER_INODES=()
for nft_fdpath in /proc/"$nft_pid"/fd/*; do
    nft_link=$(readlink -- "$nft_fdpath") || continue
    [[ $nft_link == "$LOGS_DIR/"*' (deleted)' && -f $nft_fdpath ]] || continue
    nft_name=${nft_link#"$LOGS_DIR/"}
    nft_name=${nft_name%' (deleted)'}
    [[ $nft_name =~ ^[a-zA-Z0-9._-]+$ ]] || die 'необычное имя удалённого журнала'
    nft_inode=$(stat -Lc '%d-%i' "$nft_fdpath")
    [[ -z ${NFT_RECOVER_INODES[$nft_inode]:-} ]] || continue
    exec {nft_hold_fd}< "$nft_fdpath"
    NFT_RECOVER_INODES[$nft_inode]=1
    legacy_dir
    install -d -m 750 -o root -g "$SYSLOG_GROUP" "$nft_legacy/deleted"
    nft_recovered="$nft_legacy/deleted/$nft_name.inode-$nft_inode"
    install -m 640 -o root -g "$SYSLOG_GROUP" /dev/null "$nft_recovered"
    NFT_RECOVER_FDS+=("$nft_hold_fd")
    NFT_RECOVER_PATHS+=("$nft_recovered")
    cat <&"$nft_hold_fd" > "$nft_recovered"
done
say "Старых файлов к переносу: ${#NFT_OLD_FILES[@]}; открытых удалённых журналов сохранено: ${#NFT_RECOVER_FDS[@]}."

# Снимок действий берётся из работающего firewall, а не из имён BL/DENY.
# При изменении правил установщик следует запустить повторно.
python3 "$nft_verdict_helper" > "$nft_backup/verdicts.conf"

# Порядок правил важен: одно сообщение получает первую подходящую категорию.
# Якоря и выделение первого префикса исключают совпадения внутри полей пакета.
{
    printf '%s\n' 'rkn-blacklist.log ^(IPTABLES-RK|INPUT-RKN|RELAY-BL|DOCKER-BL|FWD-(CLOAK|HYSTERIA|IPSEC|SS|STLS|TELEMT)-BL):$'
    # Ранний антиспуфинг и PREROUTE-L2/L2V6/ARP — кадры соседей по сети хостера.
    printf '%s\n' 'security.log ^(BR|PREROUTE)-[A-Z0-9-]+:$'
    cat <<'GROUPS' 
security.log ^((INPUT6?|FORWARD6?|OUTPUT6?|FWD)-(NODE|BOGON|RESERVED|INVALID|FRAG|SPOOF|SYNFLOOD|UDPFLOOD|CONNLIMIT|CTCOUNT|TCPSCAN|PORTSCAN)(-[A-Z0-9-]+)?):$
GROUPS
    cat <<'GROUPS'
vpn.log ^(INPUT6?|FORWARD6?|OUTPUT6?|FWD)-(VLESS|NAIVE|SNOLC|CLOAK|HYSTERIA2?|IPSEC|OVPN|SS|STLS|SHADOWTLS|TELEMT|MTP|MTPROTO|TG|TT|TUIC|MIERU|VPN|WG1?)(-[A-Z0-9-]+)?:$
docker.log ^(DOCKER-[A-Z0-9-]+|(INPUT6?|FORWARD6?|OUTPUT6?|FWD)-(DOCKER0?|BRIDGE|17219|DNAT|EXT-TO-DOCKER0?)(-[A-Z0-9-]+)?):$
host.log ^(INPUT6?|OUTPUT6?)-[A-Z0-9-]+:$
network.log ^((FWD|FORWARD6?)-(DNS|DOH|INET|UPSTREAM|BUILD|NGINX|CERT|CF|ASN|PRIVATE-EGRESS)(-[A-Z0-9-]+)?|FORWARD6?-DROP):$
GROUPS
} > "$nft_backup/groups.txt"
{
    cat <<'RSYSLOG'
# Создано install-nft-logging.sh. Полный текст пакета, одна категория на событие.
template(name="NFT_ActionFileFormat" type="string" string="%TIMESTAMP:::date-rfc3339% %HOSTNAME% %syslogtag% ACTION=%$.nft_action% GROUP=%$.nft_group%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n")
if ($programname == "nftables-setup" and $msg contains "NFTABLES-SETUP: ") then {
RSYSLOG
    nft_action() {
        printf 'set $.nft_group = "%s";\n' "${1%.log}"
        printf 'action(type="omfile" file="%s/%s" template="NFT_ActionFileFormat" fileCreateMode="0640" fileOwner="%s" fileGroup="%s" createDirs="off")\nstop\n' "$LOGS_DIR" "$1" "$SYSLOG_USER" "$SYSLOG_GROUP"
    }
    printf 'set $.nft_action = "INFO";\n'
    nft_action service.log
    cat <<'RSYSLOG'
}
if ($syslogfacility == 0) then {
set $.nft_prefix = re_extract($msg, "(^| )((INPUT6?|FORWARD6?|OUTPUT6?|FWD|DOCKER|RELAY|PREROUTE|BR)-[A-Z0-9-]+:|IPTABLES-RK:) ", 0, 2, "");
if ($.nft_prefix != "") then {
RSYSLOG
    cat "$nft_backup/verdicts.conf"
    while read -r nft_log nft_pattern; do
        printf "if re_match(\$.nft_prefix, '%s') then {\n" "$nft_pattern"
        nft_action "$nft_log"
        printf '}\n'
    done < "$nft_backup/groups.txt"
    nft_action other.log
    printf '}\n}\n'
} > "$nft_backup/rsyslog.conf"
{
    printf '"%s" ' "${NFT_LOGS[@]/#/$LOGS_DIR/}"
    cat <<EOF
{
    su root root
    olddir $LOGS_DIR/archive
    rotate 10
    daily
    maxsize 20M
    maxage 10
    missingok
    notifempty
    compress
    delaycompress
    nodateext
    nocopytruncate
    create 640 ${SYSLOG_USER} ${SYSLOG_GROUP}
    sharedscripts
    postrotate
        if /usr/bin/systemctl is-active --quiet rsyslog.service; then
            /usr/bin/systemctl kill --kill-who=main --signal=HUP rsyslog.service
        fi
    endscript
}
EOF
} > "$nft_backup/logrotate.conf"
cat > "$nft_backup/cron.conf" <<'CRON'
# Проверка размера раз в час; история legacy/ не удаляется и не обнуляется.
SHELL=/bin/sh
PATH=/usr/sbin:/usr/bin:/sbin:/bin
17 * * * * root /usr/bin/flock -n /run/nftables-logging-install.lock /usr/sbin/logrotate /etc/logrotate.d/nftables
CRON
cat > "$nft_backup/README_RU.txt" <<'README'
Журналы NFTables: одно событие — один файл; исходный префикс и поля сохранены.
rkn-blacklist.log — RKN Blacklist: IPTABLES-RK, INPUT-RKN, RELAY-BL, DOCKER-BL, протокольные FWD-*-BL.
host.log       — доступ к хосту, SSH, INPUT/OUTPUT и отказы по умолчанию.
vpn.log        — VPN/прокси, TeleMT, WG; разрешения и отказы.
docker.log     — Docker, мосты, DNAT и ограничения контейнерных сетей.
network.log    — DNS/DoH, выход в Интернет, upstream, NGINX, общие FORWARD-отказы.
security.log   — некорректные пакеты, bogon/reserved, сканирование, flood, лимиты, PREROUTE.
                 PREROUTE-L2/L2V6 — broadcast/multicast и пакеты не на адрес сервера с WAN,
                 PREROUTE-ARP — ARP о внутренних адресах Docker/VPN с WAN (соседи хостера).
other.log      — неизвестные префиксы NFT (чтобы новые правила не теряли журнал).
service.log    — установка и проверка журналирования, не события firewall.
RKN Blacklist имеет приоритет над VPN/Docker; DENY/NOASN/SPOOF остаются в своих группах.
ACTION=DROP — правило блокирует; ACTION=ACCEPT — правило разрешает.
ACTION=REJECT — отказ с ответом; ACTION=UNKNOWN — действие не доказано.
ACTION=INFO — служебная запись. GROUP — категория события.
Действие берётся из активных правил при установке. После изменения правил
повторите установку для обновления соответствий; имя префикса не определяет действие.
ACCEPT означает разрешение этим правилом: последующие цепочки могут запретить пакет.
Исходный rate limit сохранён: журнал не является полным учётом всего трафика.
Журналы не защищены от подделки процессом с правом записи в них или от root.
Facility kern сам по себе не удостоверяет источник: дополнительные сетевые
входы rsyslog должны использовать отдельный ruleset и не попадать в эти правила.
Старая история не переписывается; отметки добавляются только к новым событиям.

archive/ — ротация новых журналов: .1 ещё без сжатия, .2.gz ... .10.gz.
legacy/  — прежние файлы с исходными именами и архивами; автоматически не удаляются.
legacy/<дата>/deleted/ — восстановленные открытые, но ранее удалённые файлы.
Новые архивы: ежедневно или >20 МиБ при проверке; проверка размера раз в час.
До 10 архивов каждого журнала; maxage 10 дней проверяется при его ротации.
20 МиБ — порог при проверке, не жёсткий предел. Самые старые архивы удаляются.

Чтение (от root либо с sudo):
  tail -F /var/log/nftables/vpn.log
  tail -F /var/log/nftables/*.log
  grep -F 'FWD-TELEMT-' /var/log/nftables/vpn.log
  grep -F ' ACTION=DROP ' /var/log/nftables/vpn.log
  grep -F ' ACTION=ACCEPT ' /var/log/nftables/host.log
  tail -F /var/log/nftables/rkn-blacklist.log
  zgrep -F 'FWD-TELEMT-' /var/log/nftables/archive/vpn.log.*.gz
  less /var/log/nftables/host.log
Поля IN/OUT, SRC/DST, PROTO, SPT/DPT и метки остаются в исходном сообщении.
Для общего просмотра используйте tail -F *.log: отдельного nft-all.log больше нет.
Не удаляйте и не обнуляйте активные файлы: их переоткрытием управляет logrotate.
Конфиги и проверки каждой установки: /var/backups/nftables-logging.* (root).
Родительские каталоги, включая /var/log, должны принадлежать root и быть
недоступны для записи группе и другим пользователям. Установщик не меняет
эти системные права автоматически; /var/log с режимом 0775 отклоняется.
README
nft_changed=1
say "Установка конфигурации; резерв: $nft_backup."
atomic_install "$nft_backup/rsyslog.conf" "${NFT_TARGETS[0]}"
atomic_install "$nft_backup/logrotate.conf" "${NFT_TARGETS[1]}"
if ! rsyslogd -N1 > "$nft_backup/rsyslog-validation.log" 2>&1; then
    say "Подробности проверки сохранены в $nft_backup/rsyslog-validation.log"
    die 'конфигурация rsyslog не прошла проверку'
fi
if ! logrotate --debug /etc/logrotate.d/nftables > "$nft_backup/logrotate-validation.log" 2>&1 ||
   ! logrotate --debug /etc/logrotate.conf >> "$nft_backup/logrotate-validation.log" 2>&1; then
    say "Подробности проверки сохранены в $nft_backup/logrotate-validation.log"
    die 'конфигурация logrotate не прошла проверку'
fi
atomic_install "$nft_backup/cron.conf" "${NFT_TARGETS[2]}"
atomic_install "$nft_backup/README_RU.txt" "${NFT_TARGETS[3]}"
say 'Проверки rsyslog и logrotate успешны. Перезапуск rsyslog и проверка свежей записи.'
nft_restart_attempted=1
systemctl restart rsyslog.service
systemctl is-active --quiet rsyslog.service || die 'rsyslog не запустился'
recover_tail || die 'не удалось сохранить последние записи удалённых журналов'
nft_test_id="NFTABLES-SETUP: $(date -u +%Y%m%dT%H%M%S%N)-$$"
logger --socket-errors=on -p user.notice -t nftables-setup -- "$nft_test_id"
nft_test_ok=0
for ((nft_i=0; nft_i<40; nft_i++)); do
    if grep -Fq -- "$nft_test_id" "$LOGS_DIR/service.log"; then nft_test_ok=1; break; fi
    sleep 0.25
done
(( nft_test_ok )) || die 'свежее тестовое сообщение не записано в service.log'
if (( ${#NFT_OLD_FILES[@]} )); then
    legacy_dir
    say "Перенос ${#NFT_OLD_FILES[@]} прежних файлов в $nft_legacy."
    for nft_file in "${NFT_OLD_FILES[@]}"; do
        check_file "$nft_file"
        [[ -f $nft_file ]] || die "старый журнал исчез во время установки: $nft_file"
        mv -T -- "$nft_file" "$nft_legacy/${nft_file##*/}"
        NFT_MOVED+=("${nft_file##*/}")
    done
fi
say "Готово: ${#NFT_LOGS[@]} активных журналов в $LOGS_DIR, владелец $SYSLOG_USER:$SYSLOG_GROUP."
say 'Ротация: archive/, ежедневно или >20 МиБ при почасовой проверке, до 10 архивов на журнал.'
if [[ -n $nft_legacy ]]; then say "Прежняя история сохранена: $nft_legacy (без автоматического удаления)."; fi
say "Описание категорий и команды чтения: $LOGS_DIR/README_RU.txt. Резерв настроек: $nft_backup."
