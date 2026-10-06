#!/bin/sh
# Блокировка torrent-трафика на FORWARD/OUTPUT. Зовётся из start_wg.sh при
# pac.blocktorrent=1 и из бота.
#
# Что изменилось после аудита 2026-08-18:
#  - модуль ipp2p (xtables-addons) живёт на ХОСТЕ, и при обновлении ядра
#    dkms-сборка может не пройти. Раньше правила просто не вставали, вывод
#    уходил в никуда, а меню бота показывало «торренты заблокированы»;
#  - правила `--string "torrent"` и `--string "announce"` дропали ЛЮБОЙ
#    форвардимый пакет с этой подстрокой: ломался обычный HTTP (ссылка на
#    torrent-трекер в теле страницы, слово announce в API) и любой plaintext.
#    Плюс поиск по каждому пакету на FORWARD заметно грузит CPU при высоком
#    PPS. Оставлены только сигнатуры самого протокола.
LOG=/logs/block_torrent

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"
}

# -C перед -I: при повторном запуске (рестарт контейнера, повторное нажатие в
# боте) правила не копятся.
add() {
    chain="$1"
    shift
    iptables -C "$chain" "$@" -j DROP 2>/dev/null && return 0
    # У xt_ipp2p 3.27 с iptables-nft проверка -C может не узнать своё же
    # правило (служебные поля match меняются в ядре). Сверяем только точное
    # правило --bit, иначе повторный запуск накапливает дубликаты.
    if [ "$#" -eq 5 ] && [ "$3" = -m ] && [ "$4" = ipp2p ] && [ "$5" = --bit ]; then
        if iptables -S "$chain" 2>/dev/null | awk -v chain="$chain" -v proto="$2" '
            NF == 9 && $1 == "-A" && $2 == chain && $3 == "-p" && $4 == proto &&
            $5 == "-m" && $6 == "ipp2p" && $7 == "--bit" && $8 == "-j" && $9 == "DROP" { found=1 }
            END { exit !found }'; then return 0; fi
    fi
    if ! iptables -I "$chain" "$@" -j DROP 2>>"$LOG"; then
        log "FAILED: iptables -I $chain $* -j DROP"
        return 1
    fi
    return 0
}

fails=0

# Сигнатуры протокола BitTorrent: ipp2p (если модуль есть) плюс точные строки
# handshake и запросов трекеру.
add FORWARD -p tcp -m ipp2p --bit || fails=$((fails + 1))
add FORWARD -p udp -m ipp2p --bit || fails=$((fails + 1))
add OUTPUT  -p tcp -m ipp2p --bit || fails=$((fails + 1))
add OUTPUT  -p udp -m ipp2p --bit || fails=$((fails + 1))
if [ "$fails" -gt 0 ]; then
    log "ipp2p rules not applied ($fails): модуль xtables-addons на хосте недоступен?"
fi

add FORWARD -m string --algo bm --string "BitTorrent protocol" || log "string rule failed: BitTorrent protocol"
add FORWARD -m string --algo bm --string "peer_id=" || log "string rule failed: peer_id="
add FORWARD -m string --algo bm --string "info_hash" || log "string rule failed: info_hash"
add FORWARD -m string --algo bm --string ".torrent" || log "string rule failed: .torrent"
add FORWARD -m string --algo bm --string "announce.php?passkey=" || log "string rule failed: announce.php"
