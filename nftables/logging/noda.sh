#!/bin/bash
# Журналирование nftables минимальной ноды (nftables/noda.conf). Правила nftables не изменяются.
set -euo pipefail
if (( $# != 0 )); then printf 'Скрипт запускается без аргументов.\n' >&2; exit 1; fi
nft_script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec /bin/bash "$nft_script_dir/install-nft-logging.sh" --profile main
