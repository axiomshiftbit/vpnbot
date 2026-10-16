"""Pinned snolc 0.0.4 configuration shared by the server and exported client."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import tarfile
import tomllib
import uuid
import zipfile

VERSION = "0.0.4"
TARGET = "x86_64-unknown-linux-gnu"
CLIENT_PACKAGES = ("snolc", "adapter-socks5", "carrier-ssh", "protection-noise", "policy-local")
# Файлы клиента, собранные из закреплённых исходников (client-patches.zip):
# ядро и все модули. Из архивов выпуска берутся только лицензии и lock-файлы.
PATCHED = ("snolc",) + tuple("libsnolc_" + name.replace("-", "_") + ".so" for name in CLIENT_PACKAGES[1:])
PRIVATE_NETS = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
                "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
                "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128",
                "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
                "2001::/32", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8"]


def archive_name(name):
    return f"{name}-{VERSION}-{TARGET}.tar.gz"


def toml_value(value):
    if isinstance(value, dict):
        return "{" + ", ".join(json.dumps(k) + " = " + toml_value(v) for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(map(toml_value, value)) + "]"
    if isinstance(value, (str, bool, int)):
        return json.dumps(value, ensure_ascii=False)
    raise ValueError("invalid_toml_value")


def toml(value):
    return "".join(json.dumps(k) + " = " + toml_value(v) + "\n" for k, v in value.items())


def write_private(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with open(temporary, "xb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data.encode() if isinstance(data, str) else data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def install(root, server=False, archives=None, built=None):
    """Extract only expected regular files, after verifying pinned archive hashes.

    built: каталог с ядром и модулями, собранными из закреплённых исходников
    (серверный образ на musl). Архивы выпуска тогда дают только лицензии.
    """
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        raise RuntimeError("Автоустановка поддерживает Linux x86_64 (glibc).")
    root = Path(root).resolve()
    manifest = json.loads(Path(__file__).with_name("releases.json").read_text())
    names = ["snolc", "adapter-direct" if server else "adapter-socks5",
             "carrier-ssh", "protection-noise", "policy-local"]
    archives = Path(archives) if archives else Path(__file__).with_name("archives")
    packages = []
    for name in names:
        entry = manifest[name]
        filename = archive_name(name)
        if archives.is_dir():
            data = (archives / filename).read_bytes()
        else:
            with zipfile.ZipFile(archives) as bundle:
                member = bundle.getinfo("archives/" + filename)
                if member.file_size > 64 * 1024 * 1024:
                    raise RuntimeError("oversized_release_archive")
                data = bundle.read(member)
        if len(data) > 64 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise RuntimeError("Не совпала SHA256 загруженного snolc.")
        relative = "bin/snolc" if name == "snolc" else f"lib/libsnolc_{name.replace('-', '_')}.so"
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            member = archive.getmember(relative)
            if not member.isfile() or member.size > 64 * 1024 * 1024:
                raise RuntimeError("invalid_package_member")
            body = archive.extractfile(member).read() if built is None else (Path(built) / Path(relative).name).read_bytes()
            notices = {}
            for notice in ("LICENSE", "THIRD_PARTY_NOTICES.txt"):
                member = archive.getmember(notice)
                if not member.isfile() or member.size > 4 * 1024 * 1024:
                    raise RuntimeError("invalid_package_notice")
                notices[notice] = archive.extractfile(member).read()
        packages.append((name, relative, body, notices))
    # Validate every pinned archive before replacing any installed component.
    for name, relative, body, notices in packages:
        for notice, data in notices.items():
            write_private(root / "licenses" / name / notice, data)
        if name == "snolc":
            write_private(root / "bin/snolc", body, 0o500)
            continue
        library = Path(relative).name
        write_private(root / "packages/store" / name / library, body, 0o400)
        lock = {"wire_version": 1, "package": f"owenewans/{name}@{VERSION}",
                "target": TARGET if built is None else "x86_64-unknown-linux-musl",
                "content_sha256": hashlib.sha256(body).hexdigest(),
                "library": f"../../../store/{name}/{library}", "store": f"../../../store/{name}",
                "dependencies": []}
        write_private(root / "packages/locks/owenewans" / name / f"{VERSION}.toml", toml(lock))


def install_patches(root, bundle, install_base=False):
    """Use the tested client binaries delivered by the bot's server image."""
    root = Path(root)
    names = set(PATCHED)
    release_names = {"archives/" + archive_name(name) for name in CLIENT_PACKAGES}
    expected = names | release_names | {"manifest.json"}
    with zipfile.ZipFile(bundle) as archive:
        if set(archive.namelist()) != expected or len(archive.namelist()) != len(expected):
            raise ValueError("invalid_patch_bundle")
        if any(info.file_size > 8 * 1024 * 1024 for info in archive.infolist()):
            raise ValueError("oversized_patch_bundle")
        manifest = json.loads(archive.read("manifest.json"))
        if manifest["version"] != "0.0.4+vpnbot.3" or set(manifest["sha256"]) != names | release_names:
            raise ValueError("invalid_patch_version")
        files = {name: archive.read(name) for name in names | release_names}
    if any(hashlib.sha256(data).hexdigest() != manifest["sha256"][name] for name, data in files.items()):
        raise ValueError("invalid_patch_digest")
    if install_base:
        install(root, archives=bundle)
    write_private(root / "bin/snolc", files["snolc"], 0o500)
    for module in CLIENT_PACKAGES[1:]:
        name = "libsnolc_" + module.replace("-", "_") + ".so"
        write_private(root / "packages/store" / module / name, files[name], 0o400)
        path = root / "packages/locks/owenewans" / module / "0.0.4.toml"
        lock = tomllib.loads(path.read_text())
        lock["content_sha256"] = manifest["sha256"][name]
        write_private(path, toml(lock))


def main_config(directory, packages, state, server):
    directory, state = Path(directory), Path(state)
    return {"wire_version": 1, "paths": {"packages": str(packages), "state": str(state)},
            "engine": {"max_sessions": 16 if server else 2, "max_flows": 256 if server else 32,
                       "max_pending_sessions": 16 if server else 2, "max_pending_opens": 32 if server else 8,
                       "max_managed_bytes": 134217728 if server else 33554432, "max_commands": 256,
                       "max_events": 1024, "max_io_chunk": 16384, "max_ingress_packets_per_tick": 32,
                       "connect_timeout_ms": 15000, "handshake_timeout_ms": 15000, "shutdown_timeout_ms": 3000},
            # This is an internal loopback stack, not an IP tunnel device.
            # Avoid its four-slot fragment reassembly limit for concurrent UDP.
            "stack": {"ipv4": True, "ipv6": True, "mtu": 65535, "tcp_socket_rx_bytes": 16384,
                      "tcp_socket_tx_bytes": 16384, "udp_socket_rx_bytes": 131072, "udp_socket_tx_bytes": 131072,
                      "udp_metadata_slots": 8, "packet_queue_bytes": 262144, "max_udp_payload_bytes": 65507,
                      "reassembly_slots": 4, "reassembly_timeout_ms": 15000},
            "yamux": {"max_streams_per_session": 17, "receive_window_bytes": 4456448,
                      "split_send_size": 16384, "read_after_close": True},
            "logging": {"mode": "file", "source": "toml", "levels": ["warning", "error"],
                        "file": str(state / "snolc.log"), "limit": "1mb", "queue_bytes": 65536,
                        "max_record_bytes": 2048, "flush_interval_ms": 1000, "on_io_error": "event"},
            "control": {"mode": "unix", "path": str(state / "control.sock"), "max_request_bytes": 65536,
                        "max_connections": 4} if server else {"mode": "off"},
            # In 0.0.4 each tunnel accepts ONE session. Share the listener/policy
            # across slots; max_sessions alone does not create acceptors.
            "tunnels": [{"name": f"main-{slot}", "role": "server" if server else "client",
                         "adapters": [str(directory / "adapter.toml")],
                         **{k: str(directory / (k + ".toml")) for k in ("protection", "carrier", "policy")}}
                        for slot in range(16 if server else 1)]}


def policy_options(server_id, database, credential=None, blocked_ips=()):
    entries = []
    if credential is None:
        entries = [{"action": "deny", "direction": "both", "protocol": "any", "unavailable": "deny",
                    "cidr": cidr} for cidr in PRIVATE_NETS + list(blocked_ips)]
    options = {"server_id": server_id, "credential_transport": "protected", "max_cached_users": 256,
               "max_admin_clients": 4, "max_control_frame_bytes": 16384, "status_interval_ms": 1000,
               "control_grace_ms": 5000, "sniff_bytes": 16384, "sniff_timeout_ms": 2000,
               "on_unknown_protocol": "allow", "checkpoint_interval_ms": 1000,
               "storage": {"path": str(database), "cache_bytes": 4194304, "max_database_bytes": 134217728,
                           "queue_capacity": 64, "accounting_block_bytes": 65536, "batch_max_delay_ms": 5},
               "global_rate": {"mode": "unlimited"}, "rules": {"terminal": "allow", "entries": entries}}
    if credential is not None:
        options["client"] = {"credential": {"source": "toml", "value": credential}}
    return options


def module(name, instance, options, server):
    return {"wire_version": 1, "instance": instance, "package": f"owenewans/{name}@{VERSION}",
            "role": "server" if server else "client", "options": options}


def write_config(directory, packages, state, endpoint, identity, server=False, credential=None,
                 socks_port=1080, blocked_ips=(), database=None):
    directory, state = Path(directory).resolve(), Path(state).resolve()
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    carrier = {"mode": "listen" if server else "connect", "endpoint_ip": endpoint, "username": "snolc",
               "max_connections": 64 if server else 2, "queue_chunks": 8, "chunk_bytes": 16384,
               "inactivity_timeout_ms": 60000, "auth": {"mode": "password", "password": identity["ssh_password"]}}
    carrier["host_key" if server else "server_host_key"] = str(state / ("ssh-private" if server else "ssh-public"))
    adapter = {"dns_mode": "system", "max_pending_opens": 32, "max_resolved_addresses": 16,
               "resolve_timeout_ms": 15000, "connect_timeout_ms": 15000}
    # Adapter/noise option names are pinned to the signed module release.
    templates = json.loads(Path(__file__).with_name("module-options.json").read_text())
    noise = dict(templates["noise-server" if server else "noise-client"])
    noise["private_key_file" if server else "server_public_key_file"] = str(state / "noise-key.hex")
    if not server:
        adapter = dict(templates["socks5-client"])
        adapter["listen"] = f"127.0.0.1:{socks_port}"
    options = policy_options(identity["server_id"], database or state / "policy.redb", credential, blocked_ips)
    modules = {"carrier": module("carrier-ssh", "ssh-main", carrier, server),
               "protection": module("protection-noise", "noise-main", noise, server),
               "policy": module("policy-local", "policy-main", options, server),
               "adapter": module("adapter-direct" if server else "adapter-socks5", "adapter-main", adapter, server)}
    for name, value in modules.items():
        write_private(directory / (name + ".toml"), toml(value))
    path = directory / "snolc.toml"
    write_private(path, toml(main_config(directory, Path(packages).resolve(), state, server)))
    return path
