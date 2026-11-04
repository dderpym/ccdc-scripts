#!/usr/bin/env python3
"""fix_services disable UNIT...: `systemctl disable --now` each unit that exists.

Prints {"disabled": [...], "absent": [...], "failed": {unit: reason}}. Units not
installed are skipped, so the same list works on every host.
"""
import json
import re
import subprocess
import sys

UNIT = re.compile(r"[A-Za-z0-9:_.@\\-]+")


def exists(unit, run=subprocess.run):
    result = run(["systemctl", "list-unit-files", unit, "--no-legend"], stdout=subprocess.PIPE,
                 stderr=subprocess.DEVNULL, text=True)
    return result.returncode == 0 and unit in result.stdout


def disable(units, run=subprocess.run):
    out = {"disabled": [], "absent": [], "failed": {}}
    for unit in units:
        if not UNIT.fullmatch(unit) or unit.startswith("-"):
            out["failed"][unit] = "invalid unit name"
        elif not exists(unit, run):
            out["absent"].append(unit)
        else:
            result = run(["systemctl", "disable", "--now", unit], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True)
            if result.returncode:
                out["failed"][unit] = result.stderr.strip()
            else:
                out["disabled"].append(unit)
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2 or argv[0] != "disable":
        print("usage: fix_services disable UNIT...", file=sys.stderr)
        return 2
    print(json.dumps(disable(argv[1:])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
