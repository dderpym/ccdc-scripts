"""Packs the steps of a BundleScript into ONE archive: only their files, nothing else."""
import json
from pathlib import Path
import stat
import zipfile

DRIVER = Path(__file__).resolve().parent / "driver.py"
STAMP = (2020, 1, 1, 0, 0, 0)  # fixed, so identical content gives identical bytes


def build(steps, destination, keep_going=True):
    """steps: [{name, source: Path, support: [Path], args, stdin, timeout}] in run order."""
    def add(archive, name, data, mode=0o644):
        info = zipfile.ZipInfo(name, STAMP)
        info.external_attr = mode << 16
        archive.writestr(info, data, zipfile.ZIP_DEFLATED)

    library = {}
    for step in steps:
        for path in step["support"]:
            data = Path(path).read_bytes()
            if library.setdefault(Path(path).name, data) != data:
                raise ValueError("two different support files are both named " + Path(path).name)
    manifest = {"keep_going": keep_going, "steps": [
        {"name": step["name"], "file": "steps/%s/%s" % (step["name"], Path(step["source"]).name),
         "args": list(step["args"]), "stdin": bool(step["stdin"]), "timeout": step["timeout"]} for step in steps]}
    with open(destination, "wb") as out:
        out.write(b"#!/usr/bin/env python3\n")
        with zipfile.ZipFile(out, "w") as archive:
            add(archive, "__main__.py", DRIVER.read_bytes())
            add(archive, "manifest.json", json.dumps(manifest, sort_keys=True))
            for step, entry in zip(steps, manifest["steps"]):
                add(archive, entry["file"], Path(step["source"]).read_bytes(), 0o755)
            for name in sorted(library):
                add(archive, "lib/" + name, library[name])
    Path(destination).chmod(stat.S_IRWXU)
