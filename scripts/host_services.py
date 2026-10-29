#!/usr/bin/env python3
"""Хостовые службы до/после запуска Compose; без серверных адресов в исходниках."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def run(args, timeout=180):
    return subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=timeout)


def same(a, b):
    return a.is_file() and b.is_file() and hashlib.sha256(a.read_bytes()).digest() == hashlib.sha256(b.read_bytes()).digest()


def supported():
    # Explicit root-process opt-out for disposable CI stands, which intentionally
    # attach test peers and must not install persistent services on their runner.
    value = os.environ.get('VPNBOT_HOST_SERVICES', 'on')
    if value not in ('on', 'off'):
        raise RuntimeError('VPNBOT_HOST_SERVICES допускает только on или off')
    return value == 'on' and os.geteuid() == 0 and Path('/run/systemd/system').is_dir()


def prepare(root):
    if not supported():
        print('[INFO] Автоустановка хостовых служб отключена или недоступна (требуются root и systemd)')
        return
    if not all(shutil.which(x) for x in ('nft', 'ip', 'nsenter', 'systemctl')):
        raise RuntimeError('Для защиты контейнеров нужны nftables, iproute2, util-linux и systemd')
    guard = root / 'scripts/container_origin_guard.py'
    config = Path('/etc/vpnbot-origin/config.json')
    if not config.exists() or not same(guard, Path('/usr/local/sbin/vpnbot-origin')):
        result = run([sys.executable, guard, 'install', '--bot-dir', root])
        if result.returncode:
            raise RuntimeError('Установка защиты контейнеров не завершена; запустите scripts/container_origin_guard.py install для диагностики')
    elif run(['systemctl', 'is-active', '--quiet', 'vpnbot-origin.service']).returncode:
        if run(['systemctl', 'start', 'vpnbot-origin.service']).returncode:
            raise RuntimeError('Не запущена защита контейнеров')
    if run([sys.executable, '/usr/local/sbin/vpnbot-origin', 'check', '--bot-dir', root], timeout=60).returncode:
        raise RuntimeError('Не подтверждена защита этой установки VPN-бота')


def finalize(root):
    if not supported():
        return
    # Network addresses must have converged after the final Compose operation.
    for attempt in range(15):
        result = run([sys.executable, '/usr/local/sbin/vpnbot-origin', 'sync'], timeout=60)
        if result.returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError('Не подтверждены интерфейсы контейнеров; доступ неизвестным портам остаётся закрыт')
    exists = run(['nft', 'list', 'set', 'ip', 'filter', 'acme_http_fwd'])
    if exists.returncode:
        if Path('/etc/acme-window/config.json').exists():
            raise RuntimeError('Установлен ACME, но в firewall пропал набор окна')
        print('[WARNING] Окно ACME не установлено: основной firewall не содержит acme_http_fwd')
        return
    # This performs strict live/disk/DNAT checks and preserves existing targets,
    # auto=false, certificate history and operator settings.
    result = run([sys.executable, root / 'scripts/setup_acme.py', 'ensure', '--bot-dir', root,
                  '--wait-lock', '30'], timeout=240)
    if result.returncode:
        raise RuntimeError('Автоустановка окна ACME не завершена; выполните python3 scripts/setup_acme.py check для диагностики')
    print('[OK] Защита контейнеров и окно ACME установлены и проверены')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'finalize'))
    parser.add_argument('--bot-dir', type=Path, default=Path.cwd())
    args = parser.parse_args()
    globals()[args.action](args.bot_dir.resolve())


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as e:
        print('[ОТКАЗ] ' + (str(e) if isinstance(e, RuntimeError) else 'Ошибка установки хостовых служб'), file=sys.stderr)
        sys.exit(1)
