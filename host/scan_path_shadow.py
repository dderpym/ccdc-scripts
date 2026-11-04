#!/usr/bin/env python3
"""Same command name in two PATH directories where at least one copy is not package-owned."""
import json
import os
import sys

from host import pkgowner

STANDARD = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")


def scan(path_dirs=None, owned=None):
    owned = owned or pkgowner.checker()
    directories = list(dict.fromkeys(path_dirs or (*STANDARD, *os.environ.get("PATH", "").split(os.pathsep))))
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
