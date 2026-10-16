"""Build the public native-client patch bundle inside the snolc image."""
import hashlib
import json
from pathlib import Path
import sys
import zipfile
from snolc_config import CLIENT_PACKAGES, archive_name


def build(core, adapter, policy, destination):
    files = {"snolc": Path(core).read_bytes(), "libsnolc_adapter_socks5.so": Path(adapter).read_bytes(),
             "libsnolc_policy_local.so": Path(policy).read_bytes()}
    releases = json.loads(Path(__file__).with_name("releases.json").read_text())
    for name in CLIENT_PACKAGES:
        filename = archive_name(name)
        data = (Path(__file__).with_name("archives") / filename).read_bytes()
        if hashlib.sha256(data).hexdigest() != releases[name]["sha256"]:
            raise ValueError("invalid_release_digest")
        files["archives/" + filename] = data
    manifest = {"version": "0.0.4+vpnbot.3",
                "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for name, data in files.items():
            archive.writestr(name, data)


if __name__ == "__main__":
    build(*sys.argv[1:])
