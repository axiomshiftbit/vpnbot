#!/usr/bin/env python3
"""snolc SSH/Noise supervisor with durable, replayable policy-local mutations."""
import base64
import copy
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app/snolc"))
sys.path.insert(0, "/snolc")
from snolc_config import toml, write_config, write_private
from protocol_service import Supervisor, atomic_json, read_json


class SnolcSupervisor(Supervisor):
    protocol = "snolc"

    def __init__(self, root, binary="/opt/snolc/runtime/bin/snolc", packages="/opt/snolc/runtime/packages"):
        super().__init__(root, binary)
        self.packages = Path(packages)
        path = self.root / "admin.json"
        self.admin = read_json(path) if path.exists() else {"seq": 0, "users": {}}
        if type(self.admin.get("seq")) is not int or not isinstance(self.admin.get("users"), dict):
            raise ValueError("invalid_admin_state")
        # Never silently replace a lost policy DB: it owns crash-safe quota reservations.
        if self.admin["seq"] and not self.database().is_file():
            raise ValueError("missing_policy_database")
        if not path.exists() and any(self.root.glob("policy*.redb")):
            raise ValueError("missing_admin_state")
        if not path.exists():
            atomic_json(path, self.admin)
        bundle = Path("/opt/snolc/client-patches.zip")
        if bundle.is_file():
            data = bundle.read_bytes()
            exported = self.root / "client-patches.zip"
            if not exported.is_file() or exported.read_bytes() != data:
                write_private(exported, data)

    def database(self):
        name = self.admin.get("database", "policy.redb")
        if not isinstance(name, str) or not re.fullmatch(r"policy(?:-[a-f0-9]{32})?\.redb", name):
            raise ValueError("invalid_database_path")
        return self.root / name

    def prepare_restore(self, state):
        restore_id = state.get("restore_usage", {}).get("id", "")
        if not restore_id or self.admin.get("restored", "") == restore_id:
            return
        # Revoked digests in policy-local cannot be reused, even after deleting
        # their user (the native credential cache is lazy). An explicit restore
        # selects a NEW ledger, populated exclusively from the validated backup.
        # The atomic admin switch happens before the core can create that ledger.
        previous = self.database().name
        outdated = self.admin.get("previous_database")
        updated = {"seq": 0, "users": {}, "restored": restore_id,
                   "database": "policy-" + restore_id + ".redb", "previous_database": previous}
        atomic_json(self.root / "admin.previous.json", self.admin)
        atomic_json(self.root / "admin.json", updated)
        self.admin = updated
        if outdated and outdated not in (previous, updated["database"]) and re.fullmatch(r"policy(?:-[a-f0-9]{32})?\.redb", outdated):
            (self.root / outdated).unlink(missing_ok=True)

    def control(self, request):
        path = self.root / "request.toml"
        write_private(path, toml(request))
        try:
            result = subprocess.run([self.binary, "control", str(self.root / "control.sock"), "policy-main", str(path)],
                                    capture_output=True, timeout=8, check=True)
            response = tomllib.loads(result.stdout.decode())
            if response.get("status") != "ok":
                raise ValueError("control_rejected")
            return response
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise RuntimeError("stats_unavailable") from exc
        finally:
            path.unlink(missing_ok=True)

    def finish_pending(self):
        pending = self.admin.get("pending")
        if pending is None:
            return
        response = self.control(pending["request"])
        effect = pending["effect"]
        if "put" in effect:
            record = copy.deepcopy(effect["record"])
            if effect.get("created"):
                record["native"] = response["user_id"]
            self.admin["users"][effect["put"]] = record
        if "delete" in effect:
            self.admin["users"].pop(effect["delete"], None)
        self.admin["seq"] = pending["request"]["seq"]
        del self.admin["pending"]
        atomic_json(self.root / "admin.json", self.admin)

    def mutate(self, request, effect=None):
        self.finish_pending()
        request = dict(request, client_id="vpnbot", seq=self.admin["seq"] + 1)
        self.admin["pending"] = {"request": request, "effect": effect or {}}
        atomic_json(self.root / "admin.json", self.admin)
        self.finish_pending()

    def native_usage(self, record):
        response = self.control({"method": "usage.get", "user_id": record["native"]})
        for key in ("upload_bytes", "download_bytes", "used_bytes", "revision"):
            if type(response.get(key)) is not int or response[key] < 0:
                raise ValueError("invalid_usage")
        return response

    def collect(self):
        if not self.alive():
            return
        records = {}
        for uid, record in self.admin["users"].items():
            usage = self.native_usage(record)
            records[uid] = {"upload": record["base_upload"] + usage["upload_bytes"],
                            "download": record["base_download"] + usage["download_bytes"] + record.get("burned", 0),
                            "reset": record["reset"],
                            "charged": record["base_upload"] + record["base_download"] + usage["used_bytes"]}
        self.stats_time = int(time.time())
        self.usage = {"users": records, "time": self.stats_time, "restored": self.admin.get("restored", "")}
        atomic_json(self.root / "usage.json", self.usage)

    def stop(self):
        if self.alive():
            try:
                self.collect()
            except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
                self.error = "stats_unavailable"
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.process = None
        if self.log:
            self.log.close()
            self.log = None
        self.active = []
        self.fingerprint = None

    @staticmethod
    def validate(state):
        if state.get("schema") != 1 or state.get("protocol") != "snolc" or type(state.get("enabled")) is not bool:
            raise ValueError("invalid_state")
        if type(state.get("revision")) is not int or state["revision"] < 0 or not isinstance(state.get("users"), dict):
            raise ValueError("invalid_state")
        settings = state["settings"]
        if settings.get("listen_port") != 24448 or settings.get("egress") != "direct" or settings.get("options") not in ({}, []):
            raise ValueError("invalid_settings")
        if not re.fullmatch("[a-f0-9]{64}", settings.get("server_seed", "")):
            raise ValueError("invalid_identity")
        for address in settings["blocked_ips"]:
            ipaddress.ip_address(address)
        for uid, user in state["users"].items():
            if not re.fullmatch("[a-f0-9]{16}", uid) or type(user.get("enabled")) is not bool:
                raise ValueError("invalid_user")
            if not re.fullmatch("[A-Za-z0-9_-]{43}", user.get("password", "")) or not re.fullmatch("[a-f0-9]{16}", user.get("reset", "")):
                raise ValueError("invalid_user")
            for key in ("expires", "quota"):
                if user[key] is not None and (type(user[key]) is not int or user[key] <= 0):
                    raise ValueError("invalid_user")
        restore = state.get("restore_usage")
        if restore:
            if not re.fullmatch("[a-f0-9]{32}", restore["id"]) or not isinstance(restore["users"], dict):
                raise ValueError("invalid_restore")
            for record in restore["users"].values():
                for key in ("upload", "download", "charged"):
                    if key == "charged" and key not in record:
                        continue
                    if type(record.get(key)) is not int or record[key] < 0:
                        raise ValueError("invalid_restore")

    def identity(self, settings):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
        seed = bytes.fromhex(settings["server_seed"])
        def derive(name):
            return hmac.new(seed, f"vpnbot/snolc/{name}/v1".encode(), hashlib.sha256).digest()
        ssh = Ed25519PrivateKey.from_private_bytes(derive("ssh"))
        public = ssh.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        write_private(self.root / "ssh-private", ssh.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
        write_private(self.root / "noise-key.hex", derive("noise").hex())
        return {"server_id": "vpnbot-" + hashlib.sha256(public).hexdigest()[:24], "ssh_password": derive("carrier").hex()}

    def start_core(self, state, public=False):
        identity = self.identity(state["settings"])
        blocked = [str(ipaddress.ip_network(address)) for address in state["settings"]["blocked_ips"]]
        endpoint = ("0.0.0.0" if public else "127.0.0.1") + ":24448"
        path = write_config(self.root / "config", self.packages, self.root, endpoint, identity,
                            server=True, blocked_ips=blocked, database=self.database())
        checked = subprocess.run([self.binary, "validate", str(path)], capture_output=True, timeout=15)
        if checked.returncode:
            raise RuntimeError("configuration_rejected")
        self.last_validation = int(time.time())
        self.log = open(self.root / "core.log", "ab", buffering=0)
        self.process = subprocess.Popen([self.binary, "run", str(path)], stdin=subprocess.DEVNULL,
                                        stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 8
        while self.alive() and time.monotonic() < deadline:
            try:
                self.control({"method": "sessions.list"})
                return
            except RuntimeError:
                time.sleep(0.1)
        raise RuntimeError("start_failed")

    @staticmethod
    def user_spec(user, record):
        remaining = None if user["quota"] is None else user["quota"] - record["base_upload"] - record["base_download"]
        return {"status": "enabled" if user["enabled"] and (remaining is None or remaining > 0) else "disabled",
                "expiration": {"mode": "unlimited"} if user["expires"] is None else {"mode": "at-utc", "unix_seconds": user["expires"]},
                "quota": {"mode": "unlimited"} if remaining is None else {"mode": "limited", "bytes": max(1, remaining)},
                "upload_rate": {"mode": "unlimited"}, "download_rate": {"mode": "unlimited"},
                "combined_rate": {"mode": "unlimited"}, "burst_bytes": 1048576,
                "max_sessions": {"mode": "limited", "count": 4}, "max_flows": {"mode": "limited", "count": 32},
                "weekly_access": {"mode": "unlimited"}, "weight": 1, "group": "vpnbot", "rule_profile": "default"}

    def sync_users(self, state):
        self.finish_pending()
        restore = state.get("restore_usage", {})
        restore_id = restore.get("id", "")
        for uid in set(self.admin["users"]) - set(state["users"]):
            record = self.admin["users"][uid]
            revision = self.native_usage(record)["revision"]
            self.mutate({"method": "user.delete", "user_id": record["native"], "expected_revision": revision}, {"delete": uid})
        for uid, user in state["users"].items():
            record = self.admin["users"].get(uid)
            reset = record is not None and (record["reset"] != user["reset"] or record.get("restore", "") != restore_id)
            if record is None or reset:
                before = restore.get("users", {}).get(uid, {}) if restore_id else {}
                if before.get("reset") != user["reset"]:
                    before = {}
                base = {"reset": user["reset"], "restore": restore_id, "base_upload": before.get("upload", 0),
                        "base_download": before.get("download", 0), "burned": 0, "digest": "", "spec": ""}
                # A backup carries reserved bytes too; never turn an uncheckpointed
                # reservation into new quota after moving to another server.
                base["base_download"] += max(0, before.get("charged", 0) - base["base_upload"] - base["base_download"])
                if record is None:
                    spec = self.user_spec(user, base)
                    spec["status"] = "disabled"
                    self.mutate({"method": "user.create", "user": spec}, {"put": uid, "record": base, "created": True})
                else:
                    base.update(native=record["native"], digest=record["digest"])
                    self.mutate({"method": "quota.new_period", "user_id": record["native"],
                                 "quota": self.user_spec(user, base)["quota"]}, {"put": uid, "record": base})
                record = self.admin["users"][uid]
            digest = hashlib.sha256(base64.urlsafe_b64decode(user["password"] + "=")).hexdigest()
            if record["digest"] != digest:
                if record["digest"]:
                    self.mutate({"method": "credential.revoke", "credential_sha256": record["digest"]})
                updated = dict(record, digest=digest)
                self.mutate({"method": "credential.add", "user_id": record["native"], "credential_sha256": digest},
                            {"put": uid, "record": updated})
                record = self.admin["users"][uid]
            spec = self.user_spec(user, record)
            fingerprint = hashlib.sha256(toml(spec).encode()).hexdigest()
            usage = self.native_usage(record)
            if record["spec"] != fingerprint:
                updated = dict(record, spec=fingerprint)
                self.mutate({"method": "user.update", "user_id": record["native"],
                             "expected_revision": usage["revision"], "user": spec}, {"put": uid, "record": updated})
                record = self.admin["users"][uid]
            # At this point only loopback is listening and there are no user flows.
            # Persist reservations lost by an unclean shutdown as charged traffic.
            record["burned"] = max(0, usage["used_bytes"] - usage["upload_bytes"] - usage["download_bytes"])
        self.admin["restored"] = restore_id
        atomic_json(self.root / "admin.json", self.admin)
        self.collect()

    def tick(self):
        if not self.desired.exists():
            self.stop()
            self.write_status(None, "disabled")
            return
        state = read_json(self.desired)
        self.validate(state)
        self.last_valid_state = state
        if not state["enabled"]:
            self.stop()
            self.applied_revision = state["revision"]
            self.error = ""
            self.write_status(state, "disabled")
            return
        fingerprint = hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()
        if not self.alive() and fingerprint == self.fingerprint and not self.active:
            self.write_status(state, "idle")
            return
        if not self.alive() or fingerprint != self.fingerprint:
            self.stop()
            self.prepare_restore(state)
            # Reconcile on loopback BEFORE exposing a listener with a persisted DB.
            # Expired/revoked accounts must not briefly revive during container boot.
            self.start_core(state)
            self.sync_users(state)
            self.stop()
            if read_json(self.desired) != state:
                return
            active = [uid for uid, user in state["users"].items() if user["enabled"]
                      and (user["expires"] is None or user["expires"] > time.time())]
            if active:
                self.start_core(state, public=True)
                self.active = active
                self.collect()
            self.fingerprint = fingerprint
            self.last_success = int(time.time())
        if self.alive() and time.monotonic() - self.last_poll >= 5:
            self.collect()
            self.last_poll = time.monotonic()
        log = self.root / "core.log"
        if log.exists() and log.stat().st_size > 1048576:
            with open(log, "r+b") as stream:
                stream.truncate(0)
        self.applied_revision = state["revision"]
        self.error = ""
        self.write_status(state, "running" if self.alive() else "idle")

    def run(self):
        with open(self.root / "service.lock", "a") as lock:
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
                        self.stop()
                        self.error = str(exc) if isinstance(exc, RuntimeError) and str(exc) in {
                            "stats_unavailable", "configuration_rejected", "start_failed"} else "configuration_or_io_error"
                        try:
                            self.write_status(None, "error")
                        except OSError:
                            pass
                    time.sleep(1)
            finally:
                self.stop()
                self.write_status(None, "stopped")


if __name__ == "__main__":
    os.umask(0o077)
    try:
        SnolcSupervisor(sys.argv[1] if len(sys.argv) > 1 else "/state").run()
    except Exception:
        print("snolc: startup failed; inspect private state and dependencies", file=sys.stderr)
        sys.exit(1)
