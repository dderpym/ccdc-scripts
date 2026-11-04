#!/usr/bin/env python3
"""Processes running fileless (exe -> /memfd:...) or from a deleted file outside system dirs."""
import json
import sys

from host import procfs

# A deleted exe under these is almost always a package upgrade awaiting restart.
SYSTEM_DIRS = ("/usr/", "/bin/", "/sbin/", "/lib", "/opt/")
DELETED = " (deleted)"


def classify(exe):
    if exe.startswith("/memfd:"):
        return "memfd"
    if exe.endswith(DELETED) and not exe.startswith(SYSTEM_DIRS):
        return "deleted"
    return None


def scan(root="/proc"):
    findings = [dict(proc, kind=kind) for proc in procfs.processes(root) if (kind := classify(proc["exe"]))]
    return {"findings": findings, "errors": []}


def main():
    print(json.dumps(scan()))


if __name__ == "__main__":
    sys.exit(main())
