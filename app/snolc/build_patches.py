"""Build the public native-client patch bundle inside the snolc image."""
import hashlib
import json
from pathlib import Path
import sys
import zipfile


def build(core, adapter, policy, destination):
    files = {"snolc": Path(core).read_bytes(), "libsnolc_adapter_socks5.so": Path(adapter).read_bytes(),
             "libsnolc_policy_local.so": Path(policy).read_bytes()}
    manifest = {"version": "0.0.4+vpnbot.1",
                "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for name, data in files.items():
            archive.writestr(name, data)


if __name__ == "__main__":
    build(*sys.argv[1:])
