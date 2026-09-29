#!/usr/bin/env python3
"""Mita adapter: authoritative configs, private RPC and atomic native quota history."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

from protocol_service import Supervisor, atomic_json, read_json


class MieruSupervisor(Supervisor):
    protocol = "mieru"

    def __init__(self, root, binary="/usr/local/bin/mita", stats="/usr/local/bin/mieru-control"):
        super().__init__(root, binary, stats)
        self.environment = os.environ.copy()
        self.environment["MITA_UDS_PATH"] = str(self.root / "control.sock")
        self.metrics_path = Path("/var/lib/mita/metrics.pb")

    def control(self, operation, data=None):
        return subprocess.run([self.stats, operation], input=data, capture_output=True,
                              env=self.environment, check=True, timeout=5).stdout

    def counters(self):
        snapshot = json.loads(self.control("stats", self.usage.get("native_metrics", "").encode()))
        # GetUsers returns the same per-user counters and histories used by native
        # rolling quotas. The totals and protobuf checkpoint commit in one JSON.
        self.usage["native_metrics"] = snapshot["native_metrics"]
        for uid, record in snapshot["users"].items():
            if uid in self.usage["users"]:
                self.usage["users"][uid]["rolling"] = record["rolling"]
        return snapshot["users"]

    def candidate(self, config, state):
        if not os.access(self.binary, os.X_OK): raise RuntimeError("core_unavailable")
        info = Path(self.binary).stat()
        identity = (info.st_ino, info.st_mtime_ns, info.st_size)
        if identity != self.binary_identity:
            self.binary_hash = hashlib.sha256(Path(self.binary).read_bytes()).digest()
            self.binary_identity = identity
        encoded = json.dumps(config, sort_keys=True).encode()
        fingerprint = hashlib.sha256(encoded + self.binary_hash).hexdigest()
        if fingerprint == self.fingerprint and self.alive(): return None, fingerprint
        self.check_ports(config)
        try:
            self.control("check", encoded)
        except subprocess.CalledProcessError as exc:
            raise RuntimeError("configuration_rejected") from exc
        self.last_validation = int(time.time())
        directory = self.root / ("generation-" + uuid.uuid4().hex)
        directory.mkdir(mode=0o700)
        atomic_json(directory / "config.json", config)
        return directory, fingerprint

    def start(self, directory, users):
        if not os.access(self.stats, os.X_OK): raise RuntimeError("stats_unavailable")
        checkpoint = self.usage.get("native_metrics", "").encode()
        baseline = json.loads(self.control("baseline", checkpoint))
        self.metrics_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Never reload the core's independently timed dump over a newer usage.json.
        # Both totals and native rolling history are restored from our atomic checkpoint.
        temporary = self.metrics_path.with_suffix(".tmp")
        with open(temporary, "wb") as stream:
            stream.write(base64.b64decode(checkpoint, validate=True)); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, self.metrics_path)
        path = self.root / "core.log"
        if path.exists() and path.stat().st_size > 1024 * 1024: os.replace(path, self.root / "core.previous.log")
        self.log = open(path, "ab", buffering=0)
        # Mita accepts an empty config as IDLE: test the actual private RPC before
        # letting any public listener start, including after persistent API failure.
        atomic_json(directory / "api-check.json", {"loggingLevel": "WARN"})
        self.environment["MITA_CONFIG_JSON_FILE"] = str(directory / "api-check.json")
        self.process = subprocess.Popen([self.binary, "run"], stdin=subprocess.DEVNULL,
                                        stdout=self.log, stderr=self.log, env=self.environment)
        self.active = []
        deadline, ready = time.monotonic() + 5, False
        while time.monotonic() < deadline and self.alive():
            try:
                self.control("idle"); ready = True; break
            except (OSError, ValueError, subprocess.SubprocessError): time.sleep(0.1)
        if not ready: raise RuntimeError("stats_unavailable")
        self.process.terminate()
        try: self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill(); self.process.wait(timeout=3)
        self.environment["MITA_CONFIG_JSON_FILE"] = str(directory / "config.json")
        self.process = subprocess.Popen([self.binary, "run"], stdin=subprocess.DEVNULL,
                                        stdout=self.log, stderr=self.log, env=self.environment)
        self.active = list(users)
        for uid in self.active:
            self.usage["users"][uid]["last"] = baseline.get(uid, {})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and self.alive():
            try:
                self.collect(); return
            except (OSError, ValueError, subprocess.SubprocessError): time.sleep(0.1)
        raise RuntimeError("start_failed")


if __name__ == "__main__":
    os.umask(0o077)
    try:
        MieruSupervisor(sys.argv[1] if len(sys.argv) > 1 else "/state").run()
    except Exception:
        print("Mieru supervisor: startup failed; check private state and dependencies", file=sys.stderr)
        sys.exit(1)
