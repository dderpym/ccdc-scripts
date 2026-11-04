#!/usr/bin/env python3
"""fix_sudoers FILE TEXT: delete lines equal to TEXT from a sudoers file, validated with visudo.

Order: visudo -c must pass; the original goes to /root/ir/sudoers-<ts>/ (0700);
the edit is checked with visudo -cf before and visudo -c after replacing; any
failure restores the original bytes. Matching on text, not line number, so a
file that changed since the scan is never edited blindly.
"""
import json
import os
import shutil
import subprocess
import sys
import time

EVIDENCE = "/root/ir"


def find_visudo():
    return shutil.which("visudo") or next(
        (p for p in ("/usr/sbin/visudo", "/sbin/visudo") if os.access(p, os.X_OK)), None)


def allowed(path):
    real = os.path.realpath(path)
    return (not os.path.islink(path)
            and (real == "/etc/sudoers" or os.path.dirname(real) == "/etc/sudoers.d"))


def valid(visudo, *extra, run=subprocess.run):
    return run([visudo, "-c", *extra], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def write_like(path, data, info):
    with open(path, "wb") as handle:
        handle.write(data)
    os.chmod(path, info.st_mode & 0o7777)
    os.chown(path, info.st_uid, info.st_gid)


def fix(path, text, evidence=EVIDENCE, run=subprocess.run, visudo=None):
    visudo = visudo or find_visudo()
    if not visudo:
        raise RuntimeError("visudo not found")
    if not allowed(path):
        raise ValueError("not a sudoers file: " + path)
    if not valid(visudo, run=run):
        raise RuntimeError("sudoers is already invalid; refusing to edit")
    with open(path, "rb") as handle:
        original = handle.read()
    info = os.stat(path)
    lines = original.decode("utf-8", "replace").splitlines(keepends=True)
    kept = [line for line in lines if line.strip() != text.strip()]
    removed = len(lines) - len(kept)
    if not removed:
        return {"path": path, "removed": 0}
    directory = os.path.join(evidence, "sudoers-%d" % time.time())
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    with open(os.path.join(directory, os.path.basename(path)), "wb") as handle:
        handle.write(original)
    temporary = path + ".ccdc-new"
    try:
        write_like(temporary, "".join(kept).encode(), info)
        if not valid(visudo, "-f", temporary, run=run):
            raise RuntimeError("edited file failed visudo; original untouched")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    if not valid(visudo, run=run):
        try:
            write_like(temporary, original, info)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        raise RuntimeError("sudoers invalid after edit; original restored")
    return {"path": path, "removed": removed, "evidence": directory}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print("usage: fix_sudoers FILE TEXT", file=sys.stderr)
        return 2
    try:
        print(json.dumps(fix(*argv)))
    except (OSError, ValueError, RuntimeError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
