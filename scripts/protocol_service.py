#!/usr/bin/env python3
"""One supervisor per protocol; desired state is owned by PHP, usage by this process."""
import copy
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import uuid


def read_json(path):
    with open(path, encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError("invalid_state")
    return data


def atomic_json(path, data):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with open(temporary, "x", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, sort_keys=True)
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


class Supervisor:
    protocol = "anytls"
    def __init__(self, root, binary="/usr/local/bin/sing-box", stats="/usr/local/bin/protocol-stats", protocol=None):
        if protocol is not None:
            if protocol not in ("anytls", "tuic", "shadowtls"): raise ValueError("invalid_protocol")
            self.protocol = protocol
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.desired = Path(os.environ.get('PROTOCOL_DESIRED', str(self.root / 'desired.json')))
        self.binary, self.stats = binary, stats
        self.process = None
        self.log = None
        self.current = None
        self.fingerprint = ""
        self.applied_revision = None
        self.active = []
        self.stats_time = 0
        self.error = ""
        self.last_poll = 0
        self.last_write = 0
        self.binary_identity = None
        self.binary_hash = b""
        self.version_identity = None
        self.core_version = ""
        self.stopping = False
        self.last_valid_state = None
        path = self.root / "usage.json"
        # A corrupt counter file must never silently grant a fresh quota.
        self.usage = read_json(path) if path.exists() else {"users": {}}
        if not isinstance(self.usage.get("users"), dict):
            raise ValueError("invalid_usage")
        for user in self.usage["users"].values():
            if any(not isinstance(user.get(k), int) or user[k] < 0 for k in ("upload", "download")):
                raise ValueError("invalid_usage")

    def alive(self):
        return self.process is not None and self.process.poll() is None

    def counters(self):
        result = subprocess.run([self.stats], capture_output=True, timeout=4, check=True)
        data = json.loads(result.stdout)
        counters = {}
        for item in data.get("stat") or []:
            parts = item["name"].split(">>>")
            if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic" and parts[3] in ("uplink", "downlink"):
                value = int(item.get("value", 0))
                if value < 0:
                    raise ValueError("invalid_counter")
                counters.setdefault(parts[1], {})["upload" if parts[3] == "uplink" else "download"] = value
        return counters

    def collect(self):
        if not self.alive():
            return
        counters = self.counters()
        for uid in self.active:
            record = self.usage["users"][uid]
            for direction in ("upload", "download"):
                value = counters.get(uid, {}).get(direction, 0)
                before = record.get("last", {}).get(direction, 0)
                record[direction] += value - before if value >= before else value
                record.setdefault("last", {})[direction] = value
        collected = int(time.time())
        self.usage["time"] = collected
        atomic_json(self.root / "usage.json", self.usage)
        self.stats_time = collected

    def stop(self):
        if self.alive():
            try:
                self.collect()
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
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
        self.active = []

    def start(self, directory, users):
        if not os.access(self.stats, os.X_OK):
            raise RuntimeError("stats_unavailable")
        path = self.root / "core.log"
        if path.exists() and path.stat().st_size > 1024 * 1024:
            os.replace(path, self.root / "core.previous.log")
        self.log = open(path, "ab", buffering=0)
        # Verify the API on a core with no public inbound. Otherwise persistent
        # API failure could reopen revoked/quota-bound access on every retry.
        probe = read_json(directory / "config.json")
        probe["inbounds"] = []
        atomic_json(directory / "api-check.json", probe)
        self.process = subprocess.Popen([self.binary, "run", "-c", str(directory / "api-check.json")],
                                        stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log)
        self.active = []
        deadline = time.monotonic() + 5
        ready = False
        while time.monotonic() < deadline and self.alive():
            try:
                self.counters()
                ready = True
                break
            except (OSError, ValueError, subprocess.SubprocessError): time.sleep(0.1)
        if not ready:
            raise RuntimeError("stats_unavailable")
        self.process.terminate()
        try: self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill(); self.process.wait(timeout=3)
        self.process = None
        self.process = subprocess.Popen([self.binary, "run", "-c", str(directory / "config.json")],
                                        stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log)
        self.active = list(users)
        for uid in self.active:
            self.usage["users"][uid]["last"] = {}
        # The API must actually answer; a live PID is not readiness.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and self.alive():
            try:
                self.collect()
                return
            except (OSError, ValueError, subprocess.SubprocessError):
                time.sleep(0.1)
        raise RuntimeError("start_failed")

    def prepare(self, state):
        if state.get("schema") != 1 or state.get("protocol") != self.protocol or not isinstance(state.get("enabled"), bool):
            raise ValueError("invalid_state")
        if not isinstance(state.get("revision"), int) or not isinstance(state.get("users"), dict):
            raise ValueError("invalid_state")
        config = copy.deepcopy(state["config"])
        if self.protocol != "mieru" and (len(config["inbounds"]) != (2 if self.protocol == "shadowtls" else 1) or config["inbounds"][0]["type"] != self.protocol):
            raise ValueError("invalid_config")
        if self.protocol == "shadowtls" and (config["inbounds"][1]["type"] != "shadowsocks"
                or config["inbounds"][1]["listen"] != "127.0.0.1" or config["inbounds"][1]["network"] != "tcp"):
            raise ValueError("invalid_internal_listener")
        now = time.time()
        active = {}
        for uid, user in state["users"].items():
            if len(uid) != 16 or any(c not in "0123456789abcdef" for c in uid):
                raise ValueError("invalid_user")
            if type(user.get("enabled")) is not bool or not re.fullmatch(r"[A-Za-z0-9_-]{43}", user.get("password", "")) or not re.fullmatch(r"[a-f0-9]{16}", user.get("reset", "")):
                raise ValueError("invalid_user")
            if self.protocol == "tuic" and not re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", user.get("uuid", "")):
                raise ValueError("invalid_user")
            if self.protocol == "shadowtls" and (not isinstance(user.get("ss_key"), str)
                    or len(base64.b64decode(user["ss_key"], validate=True)) != 16):
                raise ValueError("invalid_user")
            for field in ("expires", "quota"):
                if user[field] is not None and (type(user[field]) is not int or user[field] <= 0):
                    raise ValueError("invalid_user")
            previous = self.usage["users"].setdefault(uid, {"upload": 0, "download": 0, "reset": user["reset"]})
            if previous.get("reset") != user["reset"]:
                # Preserve the raw baseline when resetting totals during a live session.
                previous.update(upload=0, download=0, reset=user["reset"])
            exhausted = user["quota"] is not None and previous["upload"] + previous["download"] >= user["quota"]
            expired = user["expires"] is not None and user["expires"] <= now
            if user["enabled"] and not exhausted and not expired:
                active[uid] = user
        if self.protocol == "mieru":
            config["users"] = [{"name": uid, "password": u["password"], "allowPrivateIP": False, "allowLoopbackIP": False,
                                "quotas": [u["rolling_quota"]] if u.get("rolling_quota") else []} for uid, u in active.items()]
        else:
            config["inbounds"][0]["users"] = [{"name": uid, "password": u["password"]} for uid, u in active.items()]
            if self.protocol == "tuic":
                for user in config["inbounds"][0]["users"]: user["uuid"] = active[user["name"]]["uuid"]
            if self.protocol == "shadowtls":
                config["inbounds"][1]["users"] = [{"name": uid, "password": u["ss_key"]} for uid, u in active.items()]
            config["experimental"]["v2ray_api"]["stats"] = {"enabled": True, "users": list(active)}
        return config, active

    def authentication(self, config):
        if self.protocol == "shadowtls":
            keys = {u["name"]: u["password"] for u in config["inbounds"][1]["users"]}
            return [dict(u, ss_key=keys[u["name"]]) for u in config["inbounds"][0]["users"]]
        return config["users"] if self.protocol == "mieru" else config["inbounds"][0]["users"]

    def credentials_allowed(self, credentials, users):
        return all(u["name"] in users and all(users[u["name"]].get(k) == u[k] for k in ("password", "uuid", "ss_key") if k in u) for u in credentials)

    def candidate(self, config, state):
        # File contents, not just JSON, participate in revision detection.
        tls = config["inbounds"][0].get("tls")
        material = (Path(tls["certificate_path"]).read_bytes(), Path(tls["key_path"]).read_bytes()) if tls else ()
        info = Path(self.binary).stat()
        identity = (info.st_ino, info.st_mtime_ns, info.st_size)
        if identity != self.binary_identity:
            self.binary_hash = hashlib.sha256(Path(self.binary).read_bytes()).digest()
            self.binary_identity = identity
        fingerprint = hashlib.sha256(json.dumps(config, sort_keys=True).encode()
                                     + state["settings"]["sni"].encode() + b"".join(material) + self.binary_hash).hexdigest()
        if fingerprint == self.fingerprint and self.alive():
            return None, fingerprint
        directory = self.root / ("generation-" + uuid.uuid4().hex)
        directory.mkdir(mode=0o700)
        try:
            if tls:
                for filename, data in zip(("certificate.pem", "private.pem"), material):
                    (directory / filename).write_bytes(data)
                certificate = directory / "certificate.pem"
                hostname = state["settings"]["sni"]
                try:
                    ipaddress.ip_address(hostname)
                    identity_option = "-verify_ip"
                except ValueError:
                    identity_option = "-verify_hostname"
                # x509 -checkhost exits 0 even on mismatch; verify checks dates too.
                subprocess.run(["openssl", "verify", "-trusted", str(certificate), "-partial_chain",
                                "-purpose", "sslserver", identity_option, hostname, str(certificate)],
                               capture_output=True, check=True, timeout=5)
                tls["certificate_path"] = str(certificate)
                tls["key_path"] = str(directory / "private.pem")
            atomic_json(directory / "config.json", config)
            subprocess.run([self.binary, "check", "-c", str(directory / "config.json")],
                           capture_output=True, check=True, timeout=10)
            return directory, fingerprint
        except Exception:
            shutil.rmtree(directory)
            raise

    def tick(self):
        # Keep the child's append-only descriptor valid while bounding disk
        # usage even during a sustained stream of failed authentication.
        log_path = self.root / 'core.log'
        if log_path.exists() and log_path.stat().st_size > 1024 * 1024:
            with open(log_path, 'r+b') as stream:
                stream.seek(-65536, os.SEEK_END)
                tail = stream.read()
                stream.seek(0); stream.write(tail); stream.truncate()
        desired = self.desired
        if not desired.exists():
            self.stop()
            self.write_status(None, "disabled")
            return
        state = read_json(desired)
        restore = state.get("restore_usage")
        if restore and self.usage.get("restored") != restore["id"]:
            records = restore["users"]
            if not isinstance(records, dict) or any(not isinstance(v, dict) or any(type(v.get(k)) is not int or v[k] < 0 for k in ("upload", "download")) for v in records.values()):
                raise ValueError("invalid_usage_restore")
            self.stop()
            self.usage = {"users": copy.deepcopy(records), "restored": restore["id"]}
            if self.protocol == "mieru": self.usage["native_metrics"] = restore.get("native_metrics", "")
            for record in self.usage["users"].values(): record.pop("last", None)
            atomic_json(self.root / "usage.json", self.usage)
            self.fingerprint = ""
        # Keep usage current before checking expiry/quota or rotating a core.
        if self.alive() and time.monotonic() - self.last_poll >= 5:
            self.last_poll = time.monotonic()
            try:
                self.collect()
            except (OSError, ValueError, subprocess.SubprocessError):
                self.error = "stats_unavailable"
                if any(u.get("quota") or u.get("rolling_quota") for u in state.get("users", {}).values()) and time.time() - self.stats_time > 15:
                    self.stop()
                    raise RuntimeError("quota_stats_unavailable")
        config, users = self.prepare(state)
        self.last_valid_state = state
        cover_only = self.protocol == "anytls" and bool(config["inbounds"][0].get("fallback_server_name"))
        if not state["enabled"] or (not users and not cover_only):
            self.stop()
            self.applied_revision = state["revision"]
            self.fingerprint = ""
            self.error = ""
            atomic_json(self.root / "usage.json", self.usage)
            self.write_status(state, "disabled" if not state["enabled"] else "idle")
            return
        # Revocation wins over an unrelated invalid new TLS/configuration change.
        # Keeping the old process in that case would keep revoked sessions alive.
        if self.alive() and self.current:
            old_auth = self.authentication(read_json(self.current / "config.json"))
            if not self.credentials_allowed(old_auth, users):
                self.stop()
        directory, fingerprint = self.candidate(config, state)
        if directory:
            # A concurrent edit during validation must not be overwritten.
            if read_json(desired) != state:
                shutil.rmtree(directory)
                return
            old_directory, old_users = self.current, list(self.active)
            old_config = read_json(old_directory / "config.json") if old_directory else None
            self.stop()
            try:
                self.start(directory, users)
            except Exception:
                self.stop()
                # A failed update must not resurrect a removed or rotated credential.
                old_auth = self.authentication(old_config) if old_config else []
                allowed = self.credentials_allowed(old_auth, users)
                if old_directory and allowed:
                    self.start(old_directory, old_users)
                shutil.rmtree(directory)
                raise
            self.current, self.fingerprint = directory, fingerprint
            for previous in self.root.glob("generation-*"):
                if previous not in (directory, old_directory):
                    shutil.rmtree(previous)
        self.applied_revision = state["revision"]
        self.error = ""
        self.write_status(state, "cover_only" if not users else "running")

    def binary_version(self):
        try:
            info = Path(self.binary).stat()
            identity = (info.st_ino, info.st_mtime_ns, info.st_size)
            if identity != self.version_identity:
                self.version_identity = identity
                self.core_version = ""
                result = subprocess.run([self.binary, "version"], capture_output=True, text=True, timeout=3, check=True)
                match = re.search(r"(?<![\w.])v?(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)(?![\w.])", result.stdout[:512])
                if match: self.core_version = match.group(1)
        except (OSError, UnicodeError, subprocess.SubprocessError):
            self.core_version = ""
        return self.core_version

    def write_status(self, state, phase):
        atomic_json(self.root / "status.json", {"time": int(time.time()), "phase": phase,
                    "running": self.alive(), "pid": self.process.pid if self.alive() else None,
                    "revision": self.applied_revision, "desired_revision": state.get("revision") if state else None,
                    "stats_time": self.stats_time, "active": self.active, "error": self.error,
                    "core_version": self.binary_version()})

    def run(self):
        lock = open(self.root / "service.lock", "a")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        def terminate(_signum, _frame):
            self.stopping = True
        signal.signal(signal.SIGTERM, terminate)
        signal.signal(signal.SIGINT, terminate)
        try:
            while not self.stopping:
                try:
                    self.tick()
                except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as exc:
                    # Core validation errors can contain credentials: publish a category only.
                    self.error = str(exc) if isinstance(exc, RuntimeError) else "configuration_or_io_error"
                    # A damaged desired file must not suspend previously accepted
                    # expiry/quota enforcement on a still-running generation.
                    if self.alive() and self.last_valid_state:
                        try:
                            self.collect()
                            _, allowed = self.prepare(self.last_valid_state)
                            if any(uid not in allowed for uid in self.active): self.stop()
                        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                            self.stop()
                    try:
                        self.write_status(None, "error")
                    except OSError:
                        pass
                time.sleep(1)
        finally:
            self.stop()
            self.write_status(None, "stopped")
            lock.close()


if __name__ == "__main__":
    os.umask(0o077)
    try:
        Supervisor(sys.argv[1] if len(sys.argv) > 1 else "/state",
                   os.environ.get("PROTOCOL_BINARY", "/usr/local/bin/sing-box"),
                   os.environ.get("PROTOCOL_STATS", "/usr/local/bin/protocol-stats"),
                   os.environ.get("PROTOCOL_KIND", "anytls")).run()
    except Exception:
        print("protocol supervisor: startup failed; check private state and dependencies", file=sys.stderr)
        sys.exit(1)
