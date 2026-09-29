#!/usr/bin/env python3
"""Run an exported VPNBot snolc profile with the pinned native Linux client."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import subprocess
import sys
import time

from snolc_config import install, install_patches, write_config, write_private


def prepare(profile, root, packages=None, socks_port=1080):
    if profile.get("schema") != "vpnbot.snolc.v1" or profile.get("version") != "0.0.4":
        raise ValueError("Неподдерживаемая версия профиля.")
    server = profile["server"]
    if not 1024 <= server["port"] <= 65535 or not 1024 <= socks_port <= 65535:
        raise ValueError("Неверный порт.")
    if not re.fullmatch(r"[a-f0-9]{64}", profile["credential"]):
        raise ValueError("Неверный личный ключ.")
    if not re.fullmatch(r"[a-f0-9]{64}", server["noise_public_key"]):
        raise ValueError("Неверный ключ Noise.")
    if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]{68}", server["ssh_public_key"]):
        raise ValueError("Неверный ключ SSH.")
    root = Path(root).resolve()
    addresses = socket.getaddrinfo(server["host"], server["port"], type=socket.SOCK_STREAM)
    addresses.sort(key=lambda item: item[0] != socket.AF_INET)
    host = str(ipaddress.ip_address(addresses[0][4][0]))
    endpoint = f"[{host}]:{server['port']}" if ":" in host else f"{host}:{server['port']}"
    state = root / "state"
    write_private(state / "ssh-public", server["ssh_public_key"] + "\n")
    write_private(state / "noise-key.hex", server["noise_public_key"] + "\n")
    return write_config(root / "config", packages or root / "packages", state, endpoint, server,
                        credential=profile["credential"], socks_port=socks_port)


def run_client(binary, path, reconnect_timeout=20):
    """Bound a stuck SSH reconnect in upstream 0.0.4; never relax server pins."""
    while True:
        process = subprocess.Popen([str(binary), "run", str(path)], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + reconnect_timeout
            buffered = b""
            with selectors.DefaultSelector() as events:
                events.register(process.stdout, selectors.EVENT_READ)
                while process.poll() is None:
                    for key, _ in events.select(timeout=0.5):
                        data = os.read(key.fd, 4096)
                        if not data:
                            events.unregister(key.fd)
                            continue
                        buffered += data
                        while b"\n" in buffered:
                            line, buffered = buffered.split(b"\n", 1)
                            if line.startswith(b"Tunnel {") and b'state: "established"' in line:
                                deadline = None
                            elif line.startswith(b"ModuleError {") and deadline is None:
                                deadline = time.monotonic() + reconnect_timeout
                        buffered = buffered[-8192:]
                    if deadline is not None and time.monotonic() >= deadline:
                        break
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            process.stdout.close()
        print("Соединение недоступно; повторное подключение с прежними ключами.", flush=True)
        time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description="VPNBot snolc: SSH + Noise, локальный SOCKS5")
    parser.add_argument("--install", action="store_true", help="Скачать ядро и модули с проверкой SHA256")
    parser.add_argument("--prepare", action="store_true", help="Только создать конфигурацию")
    parser.add_argument("--profile", default=str(Path(__file__).with_name("profile.json")))
    parser.add_argument("--directory", default=str(Path(__file__).with_name("runtime")))
    parser.add_argument("--socks-port", default=1080, type=int)
    args = parser.parse_args()
    os.umask(0o077)
    def terminate(_signum, _frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, terminate)
    root = Path(args.directory).resolve()
    try:
        if args.install:
            bundle = Path(__file__).with_name("client-patches.zip")
            if not bundle.is_file():
                raise RuntimeError("Скачайте полный ZIP после запуска сервиса snolc.")
            install(root)
            install_patches(root, bundle)
        profile = json.loads(Path(args.profile).read_text())
        path = prepare(profile, root, socks_port=args.socks_port)
        binary = root / "bin/snolc"
        if not binary.is_file():
            raise RuntimeError("Сначала выполните python3 client.py --install --prepare")
        version = subprocess.run([str(binary), "--version"], capture_output=True, timeout=5, check=True)
        if version.stdout.strip() != b"snolc 0.0.4+vpnbot.2 wire 1":
            raise RuntimeError("Установите исправленный клиент из нового ZIP.")
        checked = subprocess.run([str(binary), "validate", str(path)], capture_output=True, timeout=15)
        if checked.returncode:
            raise RuntimeError("Ядро отклонило конфигурацию. Проверьте версию клиента и права файлов.")
        if args.prepare:
            print("Конфигурация проверена.")
            return
        print(f"SOCKS5: 127.0.0.1:{args.socks_port}; TCP и UDP. Для остановки нажмите Ctrl+C.", flush=True)
        run_client(binary, path)
    except KeyboardInterrupt:
        return
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError):
        # Native parser errors can contain authentication material.
        print("Не удалось запустить snolc. Проверьте профиль, Linux x86_64/glibc, Python 3.11+ и установку ядра.", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
