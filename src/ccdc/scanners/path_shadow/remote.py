#!/usr/bin/env python3
"""Same command name in two PATH directories where at least one copy is not package-owned.

The directories come from live state: the PATH a fresh login shell gets, the systemd manager's PATH and
the PATH of every running process (/proc/*/environ), not just this scanner's own environment."""
import json
import os
import subprocess
import sys

import pkgowner

STANDARD = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")


def live_paths(proc="/proc", run=subprocess.run):
    """PATH directories in effect: login shells, systemd manager, running processes."""
    values = []
    for command in (["sh", "-lc", "echo $PATH"], ["bash", "-lc", "echo $PATH"], ["systemctl", "show-environment"]):
        try:
            out = run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True,
                      timeout=30, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "TERM": "dumb"}).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        values += [line[5:] for line in out.splitlines() if line.startswith("PATH=")] if command[0] == "systemctl" \
            else out.strip().splitlines()[:1]
    try:
        pids = [p for p in os.listdir(proc) if p.isdigit()]
    except OSError:
        pids = []
    for pid in pids:
        try:
            with open(f"{proc}/{pid}/environ", "rb") as handle:
                for item in handle.read().split(b"\0"):
                    if item.startswith(b"PATH="):
                        values.append(os.fsdecode(item[5:]))
        except OSError:
            continue
    return [d for value in values for d in value.split(os.pathsep)]


def scan(path_dirs=None, owned=None):
    owned = owned or pkgowner.checker()
    directories = list(dict.fromkeys(path_dirs or (*STANDARD, *os.environ.get("PATH", "").split(os.pathsep),
                                                  *live_paths())))
    copies = {}
    for directory in directories:
        if not directory or not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            full = os.path.join(directory, name)
            if os.path.isfile(full) and os.access(full, os.X_OK):
                copies.setdefault(name, {}).setdefault(os.path.realpath(full), full)  # usrmerge: one copy per realpath
    findings, errors = [], []
    for name, found in sorted(copies.items()):
        if len(found) < 2:
            continue
        states = {path: owned(path) for path in found.values()}
        if None in states.values():
            errors.append("no package manager available; PATH shadowing not assessed")
            break
        unowned = [path for path, state in states.items() if not state]
        if unowned:
            findings.append({"name": name, "paths": list(found.values()), "unowned": unowned})
    return {"findings": findings, "errors": errors}


def main():
    print(json.dumps(scan()))


if __name__ == "__main__":
    sys.exit(main())
