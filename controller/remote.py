"""The one way controller code runs on a target.

The host/ package plus pinned data files are packed into a single executable
archive. playbooks/remote.yml uploads it, runs one entry, and removes it, so
host code can share modules (distro, packages, ...) without any install step.
"""
import atexit
import json
from pathlib import Path
import shutil
import stat
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
DATA = {"vendor/lse.sh": "host/data/lse.sh", "vendor/LSE-LICENSE": "host/data/LSE-LICENSE"}
MAIN = "from host.launcher import main\nraise SystemExit(main())\n"
TASK = "Run host script"
_bundle = None


def build_bundle(destination, root=ROOT):
    """Write the archive deterministically so identical code yields identical bytes."""
    def add(archive, name, data):
        info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
        info.external_attr = 0o644 << 16
        archive.writestr(info, data, zipfile.ZIP_DEFLATED)

    with open(destination, "wb") as out:
        out.write(b"#!/usr/bin/env python3\n")
        with zipfile.ZipFile(out, "w") as archive:
            add(archive, "__main__.py", MAIN)
            for path in sorted((root / "host").glob("*.py")):
                add(archive, "host/" + path.name, path.read_bytes())
            for source, name in sorted(DATA.items()):
                add(archive, name, (root / source).read_bytes())
    Path(destination).chmod(stat.S_IRWXU)


def bundle_path():
    """Built once per controller process in a private directory, removed at exit."""
    global _bundle
    if _bundle is None or not _bundle.exists():
        directory = Path(tempfile.mkdtemp(prefix="ccdc-bundle-"))
        atexit.register(shutil.rmtree, directory, True)
        _bundle = directory / "bundle.pyz"
        build_bundle(_bundle)
    return _bundle


def request(entry, args=(), become=True, connection=False, payload=None):
    """Extra-vars for playbooks/remote.yml.

    connection: hand the script the SSH_CONNECTION of this very login (sudo drops it).
    payload: controller file delivered to the script as stdin.
    """
    return json.dumps({"ccdc_remote": {
        "bundle": str(bundle_path()), "entry": entry, "args": [str(a) for a in args],
        "become": become, "connection": connection, "payload": str(payload) if payload else ""}})
