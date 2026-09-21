#!/usr/bin/env python3
"""Update public build pins from official stable GitHub releases; never print .env."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import urllib.request

REPOS = {"singbox": "SagerNet/sing-box", "mihomo": "MetaCubeX/mihomo", "mieru": "enfein/mieru"}
MAX_ARCHIVE = 128 * 1024 * 1024


def version(value):
    if value == "latest":
        return value
    if not re.fullmatch(r"v?[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", value):
        raise ValueError("Нужна стабильная версия vX.Y.Z либо latest")
    return "v" + value.removeprefix("v")


def request(url):
    # Only constant official endpoints and validated version strings reach this function.
    return urllib.request.urlopen(urllib.request.Request(url, headers={
        "User-Agent": "VPNBot-version-pins", "Accept": "application/vnd.github+json",
    }), timeout=60)


def digest(url):
    checksum = hashlib.sha256()
    size = 0
    with request(url) as response:
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_ARCHIVE:
                raise ValueError("Архив превышает допустимый размер")
            checksum.update(chunk)
    if not size:
        raise ValueError("Пустой архив")
    return checksum.hexdigest()


def release_pins(core, wanted):
    wanted = version(wanted)
    repo = REPOS[core]
    endpoint = "latest" if wanted == "latest" else "tags/" + wanted
    with request(f"https://api.github.com/repos/{repo}/releases/{endpoint}") as response:
        release = json.loads(response.read(2 * 1024 * 1024))
    tag = version(release["tag_name"])
    if tag == "latest" or release.get("prerelease") or release.get("draft") or (wanted != "latest" and tag != wanted):
        raise ValueError("Релиз не является запрошенной стабильной версией")
    prefix = core.upper()
    pins = {prefix + "_VERSION": tag}
    if core in ("singbox", "mieru"):
        pins[prefix + "_SOURCE_SHA256"] = digest(f"https://codeload.github.com/{repo}/tar.gz/refs/tags/{tag}")
    if core != "mieru":
        filename = (f"sing-box-{tag[1:]}-linux-amd64-musl.tar.gz" if core == "singbox"
                    else f"mihomo-linux-amd64-{tag}.gz")
        assets = [a for a in release.get("assets", []) if a["name"] == filename]
        if len(assets) != 1:
            raise ValueError("Нет нужного Linux amd64 ассета в официальном релизе")
        expected = assets[0].get("digest", "")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", expected):
            raise ValueError("GitHub не предоставил SHA-256 ассета; требуется ручная проверка")
        actual = digest(f"https://github.com/{repo}/releases/download/{tag}/{filename}")
        if "sha256:" + actual != expected:
            raise ValueError("SHA-256 скачанного ассета не совпадает")
        pins[prefix + "_SHA256"] = actual
    return pins


def updated_text(original, pins):
    lines = original.splitlines(keepends=True)
    for key, value in pins.items():
        found = [n for n, line in enumerate(lines) if re.match(r"^\s*(?:export\s+)?" + re.escape(key) + r"\s*=", line)]
        if len(found) > 1:
            raise ValueError("Повторное определение переменной версии: " + key)
        if found:
            index = found[0]
            ending = "\r\n" if lines[index].endswith("\r\n") else "\n"
            lines[index] = f"{key}={value}{ending}"
        else:
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.append(f"{key}={value}\n")
    return "".join(lines)


def update_file(path, pins, dry_run=False):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("Нужен обычный небольшой файл окружения")
    original = path.read_bytes()
    output = updated_text(original.decode(), pins).encode()
    if dry_run or output == original:
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    fd, temporary = tempfile.mkstemp(prefix=".version-pins-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(output)
            stream.flush()
            os.fsync(stream.fileno())
        if path.is_symlink() or path.read_bytes() != original:
            raise ValueError("Файл изменился во время проверки; повторите команду")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for core in REPOS:
        parser.add_argument("--" + core, metavar="vX.Y.Z|latest")
    parser.add_argument("--env", type=Path, default=Path(__file__).resolve().parents[1] / ".env")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if not any(getattr(args, core) for core in REPOS):
        parser.error("Укажите --singbox, --mihomo или --mieru")
    pins = {}
    try:
        for core in REPOS:
            if value := getattr(args, core):
                pins.update(release_pins(core, value))
        update_file(args.env, pins, args.dry_run)
    except Exception as error:
        # Network exceptions can contain URLs; no environment content is included.
        parser.exit(1, f"Не удалось обновить пины ({type(error).__name__}). Файл сохранён без изменений.\n")
    for key, value in pins.items():
        print(f"{key}={value}")
    print("Проверено; файл не менялся." if args.dry_run else "Пины записаны. Пересоберите образы и проверьте совместимость патчей и клиентов.")


if __name__ == "__main__":
    main()
