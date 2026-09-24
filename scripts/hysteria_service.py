#!/usr/bin/env python3
"""Supervise native Hysteria; authorize users and durably enforce their quotas."""
import copy
import fcntl
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import threading
import time
from urllib.request import ProxyHandler, Request, build_opener

import yaml


def read_json(path):
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("invalid_state")
    return value


def atomic_json(path, value):
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    try:
        with temporary.open("x") as stream:
            json.dump(value, stream, ensure_ascii=False)
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


def validate_usage(value):
    if not isinstance(value.get("users"), dict):
        raise ValueError("invalid_usage")
    for uid, row in value["users"].items():
        if not re.fullmatch(r"[a-f0-9]{16}", uid) or not isinstance(row, dict):
            raise ValueError("invalid_usage")
        if not isinstance(row.get("reset"), str) or not re.fullmatch(r"[a-f0-9]{16}", row["reset"]):
            raise ValueError("invalid_usage")
        if any(type(row.get(key)) is not int or row[key] < 0 for key in ("upload", "download")):
            raise ValueError("invalid_usage")


def read_users(path):
    state = read_json(path) if path.exists() else {"schema": 1, "protocol": "hysteria2", "revision": 0, "users": {}}
    if (state.get("schema") != 1 or state.get("protocol") != "hysteria2"
            or type(state.get("revision")) is not int or state["revision"] < 0
            or not isinstance(state.get("users"), dict) or len(state["users"]) > 1000):
        raise ValueError("invalid_state")
    names = set()
    for uid, user in state["users"].items():
        if (not re.fullmatch(r"[a-f0-9]{16}", uid) or not isinstance(user, dict)
                or not isinstance(user.get("name"), str) or not user["name"].strip()
                or len(user["name"]) > 60 or re.search(r"[\x00-\x1f\x7f]", user["name"])
                or user["name"] in names or type(user.get("enabled")) is not bool):
            raise ValueError("invalid_user")
        names.add(user["name"])
        for key, pattern in (("password", r"[A-Za-z0-9_-]{43}"), ("reset", r"[a-f0-9]{16}")):
            if not isinstance(user.get(key), str) or not re.fullmatch(pattern, user[key]):
                raise ValueError("invalid_user")
        if any(key not in user or (user[key] is not None and (type(user[key]) is not int or user[key] < 1))
               for key in ("expires", "quota")):
            raise ValueError("invalid_limits")
    restore = state.get("restore_usage")
    if restore is not None:
        if not isinstance(restore, dict) or not isinstance(restore.get("id"), str) or not re.fullmatch(r"[a-f0-9]{32}", restore["id"]):
            raise ValueError("invalid_restore")
        validate_usage(restore)
    return state


class Supervisor:
    def __init__(self, config=Path("/config/hysteria.yaml"), users=Path("/config/hysteria/users.json"),
                 root=Path("/var/lib/hysteria"), binary="hysteria"):
        self.config_path, self.users_path, self.root, self.binary = map(Path, (config, users, root, binary))
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.state = read_users(self.users_path)
        path = self.root / "usage.json"
        if path.exists():
            self.usage = read_json(path)
        elif self.state["users"] and not self.state.get("restore_usage"):
            raise ValueError("missing_usage")
        else:
            self.usage = {"users": {}}
        validate_usage(self.usage)
        self.process = None
        self.log = None
        self.config = None
        self.fingerprint = None
        self.authorized = {}
        self.ready = False
        self.stats_time = 0
        self.error = ""
        self.stopping = False
        self.api_secret = secrets.token_urlsafe(32)
        self.auth_path = "/" + secrets.token_hex(24)
        self.auth_server = None
        self.auth_port, self.stats_port = 18081, 18080

    def alive(self):
        return self.process is not None and self.process.poll() is None

    def eligible(self, uid, state=None):
        user = (state or self.state)["users"].get(uid)
        if not user or not user["enabled"] or (user["expires"] is not None and user["expires"] <= time.time()):
            return False
        if user["quota"] is None:
            return True
        row = self.usage["users"].get(uid)
        return bool(row and row["reset"] == user["reset"] and time.monotonic() - self.stats_time < 10
                    and row["upload"] + row["download"] < user["quota"])

    def authenticate(self, credential):
        with self.lock:
            if not self.ready or not self.alive() or not isinstance(credential, str):
                return {"ok": False}
            # Read current desired state for every new connection, including revocation
            # committed between supervisor ticks. An invalid file closes admission.
            try:
                state = read_users(self.users_path)
            except (OSError, ValueError, TypeError):
                return {"ok": False}
            uid, _, password = credential.partition(":")
            user = state["users"].get(uid)
            if user and self.eligible(uid, state) and hmac.compare_digest(password.encode(), user["password"].encode()):
                self.authorized.setdefault(uid, set()).add(user["password"])
                return {"ok": True, "id": uid}
            legacy = str((self.config or {}).get("auth", {}).get("password") or "")
            if legacy and hmac.compare_digest(credential.encode(), legacy.encode()):
                self.authorized.setdefault("legacy", set()).add(legacy)
                return {"ok": True, "id": "legacy"}
            return {"ok": False}

    def serve_auth(self):
        supervisor = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.connection.settimeout(3)
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if self.path != supervisor.auth_path or length < 1 or length > 8192:
                        raise ValueError("invalid_request")
                    value = json.loads(self.rfile.read(length))
                    result = supervisor.authenticate(value.get("auth"))
                except (OSError, ValueError, AttributeError):
                    result = {"ok": False}
                body = json.dumps(result).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

        self.auth_server = HTTPServer(("127.0.0.1", self.auth_port), Handler)
        threading.Thread(target=self.auth_server.serve_forever, daemon=True).start()

    def counters(self):
        request = Request(f"http://127.0.0.1:{self.stats_port}/traffic", headers={"Authorization": self.api_secret})
        with build_opener(ProxyHandler({})).open(request, timeout=2) as response:
            value = json.loads(response.read(2 * 1024 * 1024))
        if not isinstance(value, dict):
            raise ValueError("invalid_counters")
        for row in value.values():
            if not isinstance(row, dict) or any(type(row.get(key)) is not int or row[key] < 0 for key in ("tx", "rx")):
                raise ValueError("invalid_counters")
        return value

    def collect(self):
        counters = self.counters()
        updated = copy.deepcopy(self.usage)
        for uid, user in self.state["users"].items():
            row = updated["users"].setdefault(uid, {"reset": user["reset"], "upload": 0, "download": 0})
            if row["reset"] != user["reset"]:
                row.update(reset=user["reset"], upload=0, download=0)
                row["last"] = counters.get(uid, {"tx": 0, "rx": 0})
            for source, target in (("tx", "download"), ("rx", "upload")):
                value = counters.get(uid, {}).get(source, 0)
                before = row.get("last", {}).get(source, 0)
                row[target] += value - before if value >= before else value
            row["last"] = counters.get(uid, {"tx": 0, "rx": 0})
        updated["time"] = int(time.time())
        atomic_json(self.root / "usage.json", updated)
        self.usage = updated
        self.stats_time = time.monotonic()

    def stop(self):
        self.ready = False
        if self.alive():
            try:
                self.collect()
            except (OSError, ValueError):
                self.error = "stats_unavailable"
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.process = None
        if self.log:
            self.log.close()
            self.log = None
        self.authorized = {}

    def native_config(self, config):
        candidate = copy.deepcopy(config)
        candidate["auth"] = {"type": "http", "http": {"url": f"http://127.0.0.1:{self.auth_port}{self.auth_path}"}}
        candidate["trafficStats"] = {"listen": f"127.0.0.1:{self.stats_port}", "secret": self.api_secret}
        return candidate

    def validate_config(self, config):
        # Hysteria has no `check` command. Let the real binary initialize the
        # candidate on an ephemeral loopback socket before touching the live core.
        candidate = self.native_config(config)
        candidate["listen"] = "127.0.0.1:0"
        candidate["trafficStats"]["listen"] = "127.0.0.1:0"
        path = self.root / "check.json"
        atomic_json(path, candidate)
        log_path = self.root / "check.log"
        with log_path.open("w+b") as log:
            process = subprocess.Popen([str(self.binary), "server", "-c", str(path)], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 5
                while process.poll() is None and time.monotonic() < deadline:
                    log.seek(0)
                    if b"server up and running" in log.read(65536):
                        return
                    time.sleep(0.05)
                raise ValueError("invalid_config")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
                path.unlink(missing_ok=True)
                log_path.unlink(missing_ok=True)

    def start(self, config):
        self.stop()
        for row in self.usage["users"].values():
            row["last"] = {}
        # Persist the new generation before starting; counters cannot inherit
        # the previous process's raw baseline after an unclean worker shutdown.
        atomic_json(self.root / "usage.json", self.usage)
        atomic_json(self.root / "server.json", self.native_config(config))
        self.log = (self.root / "core.log").open("ab", buffering=0)
        self.process = subprocess.Popen([str(self.binary), "server", "-c", str(self.root / "server.json")],
                                        stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 5
        while self.alive() and time.monotonic() < deadline:
            try:
                self.collect()
                self.ready = True
                return
            except (OSError, ValueError):
                time.sleep(0.1)
        self.stop()
        raise RuntimeError("start_failed")

    def tick(self):
        with self.lock:
            state = read_users(self.users_path)
            restore = state.get("restore_usage")
            if restore and self.usage.get("restored") != restore["id"]:
                self.stop()
                self.usage = {"users": copy.deepcopy(restore["users"]), "restored": restore["id"]}
                atomic_json(self.root / "usage.json", self.usage)
            self.state = state
            if self.alive():
                self.collect()
            try:
                config = yaml.safe_load(self.config_path.read_text())
                if not isinstance(config, dict) or not isinstance(config.get("auth"), dict):
                    raise ValueError("invalid_config")
                # Native API auth can preserve password-mode installations only.
                # Never silently replace a manually configured external auth backend.
                if config["auth"].get("type") != "password":
                    raise ValueError("unsupported_auth")
                material = [json.dumps(config, sort_keys=True).encode()]
                for key in ("cert", "key"):
                    material.append(Path(config["tls"][key]).read_bytes())
                fingerprint = hashlib.sha256(b"".join(material)).hexdigest()
                if fingerprint != self.fingerprint:
                    self.validate_config(config)
            except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError):
                # Keep the last valid server configuration, but still enforce
                # the current credential state while an unrelated edit is invalid.
                config, fingerprint = self.config, self.fingerprint
                self.error = "configuration_rejected"
            else:
                self.error = ""
            if config is None:
                raise ValueError("invalid_config")
            revoked = any((uid == "legacy" and password != config["auth"].get("password"))
                          or (uid != "legacy" and (not self.eligible(uid) or password != state["users"].get(uid, {}).get("password")))
                          for uid, passwords in self.authorized.items() for password in passwords)
            if fingerprint != self.fingerprint or revoked or not self.alive():
                previous = self.config
                self.config = config
                try:
                    self.start(config)
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                    if previous is None or previous == config:
                        raise
                    self.config = previous
                    self.start(previous)
                    self.error = "configuration_rejected"
                else:
                    self.fingerprint = fingerprint
            log = self.root / "core.log"
            if log.exists() and log.stat().st_size > 1024 * 1024:
                with log.open("r+b") as stream:
                    stream.seek(-65536, os.SEEK_END)
                    tail = stream.read()
                    stream.seek(0)
                    stream.write(tail)
                    stream.truncate()
            atomic_json(self.root / "status.json", {"schema": 1, "time": int(time.time()), "running": self.alive(),
                        "revision": state["revision"], "error": self.error, "users": len(state["users"])})

    def run(self):
        self.serve_auth()
        try:
            while not self.stopping:
                started = time.monotonic()
                try:
                    self.tick()
                except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
                    with self.lock:
                        self.stop()
                    # No exception strings: parsers may include credentials.
                    try:
                        atomic_json(self.root / "status.json", {"schema": 1, "time": int(time.time()), "running": False, "error": "state_or_io_error"})
                    except OSError:
                        pass
                while not self.stopping and time.monotonic() - started < 1:
                    time.sleep(0.05)
        finally:
            with self.lock:
                self.stop()
            self.auth_server.shutdown()
            self.auth_server.server_close()


def main():
    os.umask(0o077)
    root = Path("/var/lib/hysteria")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (root / "supervisor.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        supervisor = Supervisor(root=root)
        def stop(*_):
            supervisor.stopping = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        supervisor.run()


if __name__ == "__main__":
    main()
