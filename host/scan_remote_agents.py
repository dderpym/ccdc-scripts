#!/usr/bin/env python3
"""Report (never remove) remote-access agents: running processes, systemd units, known paths."""
import json
import os
import sys

from host import ioc_agents, procfs

UNIT_DIRS = ("/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system")


def scan(root="/proc", unit_dirs=UNIT_DIRS, paths=None):
    names = set(ioc_agents.NAMES)
    findings = []
    for proc in procfs.processes(root):
        exe = os.path.basename(proc["exe"].removesuffix(" (deleted)"))
        for candidate in (proc["comm"], exe):
            if candidate in names:
                findings.append({"kind": "process", "name": candidate, "location": proc["exe"], "pid": proc["pid"]})
                break
    for directory in unit_dirs:
        try:
            entries = sorted(os.listdir(directory))
        except OSError:
            continue
        for entry in entries:
            stem = entry.rsplit(".", 1)[0]
            if stem in names:
                findings.append({"kind": "unit", "name": stem, "location": os.path.join(directory, entry), "pid": 0})
    for path in ioc_agents.PATHS if paths is None else paths:
        if os.path.lexists(path):
            findings.append({"kind": "path", "name": os.path.basename(path), "location": path, "pid": 0})
    return {"findings": findings, "errors": []}


def main():
    print(json.dumps(scan()))


if __name__ == "__main__":
    sys.exit(main())
