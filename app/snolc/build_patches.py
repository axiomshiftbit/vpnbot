"""Build the public native-client patch bundle inside the snolc image."""
import hashlib
import json
from pathlib import Path
import sys
import zipfile
from snolc_config import CLIENT_PACKAGES, PATCHED, archive_name


def build(built, destination):
    """built: каталог с ядром и модулями клиента, собранными из исходников."""
    files = {name: (Path(built) / name).read_bytes() for name in PATCHED}
    releases = json.loads(Path(__file__).with_name("releases.json").read_text())
    for name in CLIENT_PACKAGES:
        filename = archive_name(name)
        data = (Path(__file__).with_name("archives") / filename).read_bytes()
        if hashlib.sha256(data).hexdigest() != releases[name]["sha256"]:
            raise ValueError("invalid_release_digest")
        files["archives/" + filename] = data
    manifest = {"version": "0.0.4+vpnbot.4",
                "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for name, data in files.items():
            archive.writestr(name, data)


if __name__ == "__main__":
    build(*sys.argv[1:])
