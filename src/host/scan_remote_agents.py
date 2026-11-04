#!/usr/bin/env python3
"""Report (never remove) remote-access agents: running processes, units as systemd has loaded them
(name or resolved ExecStart binary), known paths."""
import json
import os
import re
import subprocess
import sys

from host import ioc_agents, procfs



def systemctl(*args, run=subprocess.run):
    result = run(["systemctl", "--no-pager", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                 universal_newlines=True, timeout=60)
    if result.returncode:
        raise OSError("systemctl %s: %s" % (" ".join(args[:2]), result.stderr.strip() or result.returncode))
    return result.stdout


def live_units(run=subprocess.run, chunk=100):
    """[(unit, fragment path, [ExecStart binaries])] for every service systemd knows about."""
    names = set()
    for args in (("list-unit-files", "--type=service", "--no-legend"),
                 ("list-units", "--all", "--type=service", "--no-legend", "--plain")):
        names.update(f[0] for f in (l.split() for l in systemctl(*args, run=run).splitlines())
                     if f and f[0].endswith(".service"))
    names = sorted(names)
    units = []
    for i in range(0, len(names), chunk):
        out = systemctl("show", "-p", "Id,FragmentPath,ExecStart", *names[i:i + chunk], run=run)
        for block in out.strip("\n").split("\n\n"):
            props = dict(line.partition("=")[::2] for line in block.splitlines() if "=" in line)
            if props.get("Id"):
                units.append((props["Id"], props.get("FragmentPath", ""),
                              re.findall(r"\{ path=(\S+) ;", props.get("ExecStart", ""))))
    return units


def scan(root="/proc", units=None, paths=None):
    names = set(ioc_agents.NAMES)
    findings, errors = [], []
    for proc in procfs.processes(root):
        exe = os.path.basename(proc["exe"].removesuffix(" (deleted)"))
        for candidate in (proc["comm"], exe):
            if candidate in names:
                findings.append({"kind": "process", "name": candidate, "location": proc["exe"], "pid": proc["pid"]})
                break
    try:
        for unit, fragment, binaries in (live_units() if units is None else units):
            hit = unit.rsplit(".", 1)[0] if unit.rsplit(".", 1)[0] in names else next(
                (os.path.basename(b) for b in binaries if os.path.basename(b) in names), None)
            if hit:
                findings.append({"kind": "unit", "name": hit, "location": fragment or unit, "pid": 0})
    except OSError as exc:
        errors.append("systemd units not inspected: %s" % exc)
    for path in ioc_agents.PATHS if paths is None else paths:
        if os.path.lexists(path):
            findings.append({"kind": "path", "name": os.path.basename(path), "location": path, "pid": 0})
    return {"findings": findings, "errors": errors}


def main():
    print(json.dumps(scan()))


if __name__ == "__main__":
    sys.exit(main())
