#!/usr/bin/env python3
"""Xray MASQUE adapter for the managed-protocol lifecycle and usage ledger."""
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import uuid

from protocol_service import Supervisor, atomic_json, read_json


class MasqueSupervisor(Supervisor):
    protocol = "masque"

    def __init__(self, root, binary="/usr/local/bin/xray"):
        super().__init__(root, binary, binary)

    def prepare(self, state):
        if (state.get("schema") != 1 or state.get("protocol") != self.protocol
                or type(state.get("revision")) is not int or type(state.get("enabled")) is not bool
                or not isinstance(state.get("users"), dict)):
            raise ValueError("invalid_state")
        config = copy.deepcopy(state["config"])
        inbounds = config["inbounds"]
        if (len(inbounds) != 2 or inbounds[0]["protocol"] != "masque" or inbounds[0]["port"] != 24449
                or inbounds[0]["listen"] != "0.0.0.0" or inbounds[1] != {
                    "tag": "api", "listen": "127.0.0.1", "port": 10085, "protocol": "dokodemo-door",
                    "settings": {"address": "127.0.0.1"}}):
            raise ValueError("invalid_config")
        active = self.active_users(state)
        inbounds[0]["settings"]["users"] = [{"email": uid, "pass": u["password"], "level": 0} for uid, u in active.items()]
        return config, active

    def authentication(self, config):
        return [{"name": u["email"], "password": u["pass"]} for u in config["inbounds"][0]["settings"]["users"]]

    def counters(self):
        result = subprocess.run([self.binary, "api", "statsquery", "--server=127.0.0.1:10085"],
                                capture_output=True, timeout=4, check=True)
        data = json.loads(result.stdout)
        counters = {}
        for item in data.get("stat") or []:
            parts = item["name"].split(">>>")
            if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic" and parts[3] in ("uplink", "downlink"):
                value = int(item.get("value", 0))
                if value < 0: raise ValueError("invalid_counter")
                counters.setdefault(parts[1], {})["upload" if parts[3] == "uplink" else "download"] = value
        return counters

    def check_ports(self, config):
        if self.alive(): return  # This adapter has fixed internal ports and its own network namespace.
        for host, port, kind in [("0.0.0.0", 24449, socket.SOCK_DGRAM), ("0.0.0.0", 24449, socket.SOCK_STREAM),
                                 ("127.0.0.1", 10085, socket.SOCK_STREAM)]:
            with socket.socket(socket.AF_INET, kind) as probe:
                if kind == socket.SOCK_STREAM: probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try: probe.bind((host, port))
                except OSError as exc: raise RuntimeError("port_in_use") from exc

    def candidate(self, config, state):
        if not os.access(self.binary, os.X_OK): raise RuntimeError("core_unavailable")
        cert = config["inbounds"][0]["streamSettings"]["tlsSettings"]["certificates"][0]
        try: material = [Path(cert[key]).read_bytes() for key in ("certificateFile", "keyFile")]
        except OSError as exc: raise RuntimeError("tls_unavailable") from exc
        info = Path(self.binary).stat()
        identity = (info.st_ino, info.st_mtime_ns, info.st_size)
        if identity != self.binary_identity:
            self.binary_hash = hashlib.sha256(Path(self.binary).read_bytes()).digest()
            self.binary_identity = identity
        fingerprint = hashlib.sha256(json.dumps(config, sort_keys=True).encode()
                                     + state["settings"]["sni"].encode() + b"".join(material) + self.binary_hash).hexdigest()
        if fingerprint == self.fingerprint and self.alive(): return None, fingerprint
        self.check_ports(config)
        directory = self.root / ("generation-" + uuid.uuid4().hex)
        directory.mkdir(mode=0o700)
        try:
            for filename, data in zip(("certificate.pem", "private.pem"), material):
                (directory / filename).write_bytes(data)
            certificate = directory / "certificate.pem"
            hostname = state["settings"]["sni"]
            try:
                ipaddress.ip_address(hostname)
                identity_option = "-verify_ip"
            except ValueError: identity_option = "-verify_hostname"
            try:
                subprocess.run(["openssl", "verify", "-trusted", str(certificate), "-partial_chain",
                                "-purpose", "sslserver", identity_option, hostname, str(certificate)],
                               capture_output=True, check=True, timeout=5)
            except subprocess.CalledProcessError as exc:
                category = "tls_invalid"
                for marker, code in ((b"certificate has expired", "tls_expired"),
                                     (b"not yet valid", "tls_not_yet_valid"), (b"mismatch", "tls_name_mismatch")):
                    if marker in (exc.stderr or b""): category = code; break
                raise RuntimeError(category) from exc
            try:
                public = subprocess.run(["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"],
                                        capture_output=True, check=True, timeout=5).stdout
                private = subprocess.run(["openssl", "pkey", "-in", str(directory / "private.pem"), "-pubout",
                                          "-passin", "pass:"], capture_output=True, check=True, timeout=5).stdout
            except subprocess.CalledProcessError as exc: raise RuntimeError("tls_invalid") from exc
            # Xray's config test/API can succeed with an unusable TLS key pair.
            if public != private: raise RuntimeError("tls_key_mismatch")
            cert.update(certificateFile=str(certificate), keyFile=str(directory / "private.pem"))
            atomic_json(directory / "config.json", config)
            try:
                subprocess.run([self.binary, "run", "-test", "-config", str(directory / "config.json")],
                               capture_output=True, check=True, timeout=10)
            except subprocess.CalledProcessError as exc: raise RuntimeError("configuration_rejected") from exc
            self.last_validation = int(time.time())
            return directory, fingerprint
        except Exception:
            shutil.rmtree(directory)
            raise

    def start(self, directory, users):
        path = self.root / "core.log"
        if path.exists() and path.stat().st_size > 1024 * 1024: os.replace(path, self.root / "core.previous.log")
        self.log = open(path, "ab", buffering=0)
        # Preflight the private stats API with no MASQUE listener. A broken API
        # must not repeatedly reopen quota-bound credentials during retries.
        probe = read_json(directory / "config.json")
        probe["inbounds"] = [i for i in probe["inbounds"] if i["tag"] == "api"]
        atomic_json(directory / "api-check.json", probe)
        self.process = self.launch(directory / "api-check.json")
        self.active = []
        self.wait_api("stats_unavailable")
        self.process.terminate()
        try: self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill(); self.process.wait(timeout=3)
        self.process = self.launch(directory / "config.json")
        self.active = list(users)
        for uid in self.active: self.usage["users"][uid]["last"] = {}
        self.wait_api("start_failed")
        self.collect()

    def launch(self, path):
        return subprocess.Popen([self.binary, "run", "-config", str(path)], stdin=subprocess.DEVNULL,
                                stdout=self.log, stderr=self.log)

    def wait_api(self, error):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and self.alive():
            try:
                self.counters()
                return
            except (OSError, ValueError, subprocess.SubprocessError): time.sleep(0.1)
        raise RuntimeError(error)


if __name__ == "__main__":
    os.umask(0o077)
    try:
        MasqueSupervisor(sys.argv[1] if len(sys.argv) > 1 else "/state").run()
    except Exception:
        print("MASQUE supervisor: startup failed; check private state and dependencies", file=sys.stderr)
        sys.exit(1)
